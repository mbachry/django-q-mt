import concurrent.futures
import contextlib
import ctypes
import dataclasses
import logging
import multiprocessing
import pydoc
import signal
import threading
import time
import traceback
from collections.abc import Callable
from typing import cast

from django.core.management.base import BaseCommand
from django.utils import timezone
from django_q.brokers import get_broker
from django_q.conf import Conf
from django_q.monitor import save_cached, save_task
from django_q.scheduler import scheduler
from django_q.signing import SignedPackage
from django_q.utils import get_func_repr
from ptrace.debugger import PtraceDebugger
from ptrace.syscall import SYSCALL_NAMES

NR_sched_yield = next(k for k, v in SYSCALL_NAMES.items() if v == 'sched_yield')

ctypes.pythonapi.PyThreadState_SetAsyncExc.argtypes = [ctypes.c_long, ctypes.py_object]
ctypes.pythonapi.PyThreadState_SetAsyncExc.restype = ctypes.c_int

logger = logging.getLogger('django-q')


def process_task(task: dict) -> tuple[str, bool]:
    info_name = get_func_repr(task["func"])
    task_desc = f"Processing '{info_name}' {task['name']}"
    if "group" in task:
        task_desc += f" [{task['group']}]"
    logger.info(task_desc)

    f = task["func"]
    # if it's not an instance try to get it from the string
    if not callable(f):
        # locate() returns None if f cannot be loaded
        func = cast('Callable | None', pydoc.locate(f))
        if func is None:
            # raise a meaningfull error if task["func"] is not a valid function
            return f"Function {task['func']} is not defined", False
        f = func
    try:
        res = f(*task["args"], **task["kwargs"])
        return res, True
    except Exception as e:
        return f"{e} : {traceback.format_exc()}", False


def finalize_task(broker, ack_id, task):
    if task.get("cached", False):
        save_cached(task, broker)
    else:
        save_task(task, broker)

    # acknowledge result
    if task["success"] or task.get("ack_failure", False):
        broker.acknowledge(ack_id)

    info_name = get_func_repr(task["func"])
    if task["success"]:
        logger.info(f"Processed '{info_name}' {task['name']})")
    else:
        logger.error(f"Failed '{info_name}' {task['name']} - {task['result']}")


def run_scheduler(broker, sched_event):
    while True:
        try:
            scheduler(broker)
        except Exception:
            logger.exception('scheduler failed')
        if sched_event.wait(30):
            logger.info('scheduler exiting')
            break


def raise_in_thread(tid: int, exc_type: type[Exception]):
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, exc_type)
    if res == 0:
        logger.warning(f'invalid thread id: {tid}')
    if res != 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        logger.error('PyThreadState_SetAsyncExc failed')


@dataclasses.dataclass
class FutureInfo:
    started_at: float
    thread_id: int
    native_thread_id: int
    ack_id: int
    task: dict
    timeout_attempts: int = 0


@dataclasses.dataclass
class Futures:
    data: dict[concurrent.futures.Future, FutureInfo]
    lock: threading.Lock


def threaded_worker(supervisor_queue: multiprocessing.SimpleQueue):
    broker = get_broker()

    sched_event = threading.Event()
    sched_thread = threading.Thread(target=run_scheduler, args=(broker, sched_event))
    sched_thread.daemon = True
    sched_thread.start()

    timeout = Conf.TIMEOUT

    futures = Futures(data={}, lock=threading.Lock())

    def worker_done_cb(future: concurrent.futures.Future):
        with futures.lock:
            info = futures.data[future]
        try:
            result, success = future.result()
            info.task["result"] = result
            info.task["success"] = success
            info.task["stopped"] = timezone.now()
            finalize_task(broker, info.ack_id, info.task)
        except TimeoutError:
            info.task["result"] = 'Task timed out'
            info.task["success"] = False
            info.task["stopped"] = timezone.now()
            finalize_task(broker, info.ack_id, info.task)
        except Exception:
            logger.exception('worker_done_cb failed')
        finally:
            with futures.lock:
                del futures.data[future]

    def cancel_timed_out_futures():
        assert timeout is not None
        assert timeout > 0
        while not cancel_event.wait(30):
            with futures.lock:
                futures_copy = futures.data.copy()
            now = time.monotonic()
            for info in futures_copy.values():
                if now - info.started_at > timeout:
                    match info.timeout_attempts:
                        case 0:
                            raise_in_thread(info.thread_id, TimeoutError)
                        case 1:
                            logger.info('using ptrace as a last resort')
                            raise_in_thread(info.thread_id, TimeoutError)
                            supervisor_queue.put(('unblock_thread', info.native_thread_id))
                        case _:
                            logger.error('unable to unblock a timed out thread, restarting all workers')
                            supervisor_queue.put('exit')
                    info.timeout_attempts += 1
        logger.info('cancel thread exiting')

    if timeout is not None and timeout > 0:
        cancel_event = threading.Event()
        cancel_thread = threading.Thread(target=cancel_timed_out_futures)
        cancel_thread.daemon = True
        cancel_thread.start()

    def worker_wrapper(tid_container, event, task):
        tid = threading.get_ident()
        native = threading.get_native_id()
        tid_container.append(tid)
        tid_container.append(native)
        event.set()
        return process_task(task)

    with concurrent.futures.ThreadPoolExecutor(max_workers=Conf.WORKERS) as executor:
        logger.info(f'[{Conf.CLUSTER_NAME}] Started threaded worker, max threads: {Conf.WORKERS}')
        while True:
            try:
                task_batch = broker.dequeue()
            except Exception:
                logging.exception('failed to dequeue from broker')
                time.sleep(0.5)
                continue
            if not task_batch:
                continue

            for ack_id, packed_task in task_batch:
                try:
                    task = SignedPackage.loads(packed_task)
                except Exception:
                    logger.exception('SignedPackage.loads failed')
                    broker.fail(ack_id)
                    continue

                event = threading.Event()
                tid_container: list[int] = []
                future = executor.submit(worker_wrapper, tid_container, event, task)
                if not event.wait(5):
                    logging.error('worker_wrapper timed out')
                    supervisor_queue.put('exit')
                    break
                info = FutureInfo(
                    started_at=time.monotonic(),
                    thread_id=tid_container[0],
                    native_thread_id=tid_container[1],
                    ack_id=ack_id,
                    task=task,
                )
                with futures.lock:
                    futures.data[future] = info
                future.add_done_callback(worker_done_cb)

    # sched_event.set()
    # cancel_event.set()


def unblock_thread(pid, tid):
    logger.info(f'unblocking timed out thread {tid=}')
    debugger = PtraceDebugger()
    debugger.addProcess(pid, False)
    thread = debugger.addProcess(tid, False, is_thread=True)

    thread.singleStep()
    thread.kill(signal.SIGINT)

    thread.waitSignals(signal.SIGTRAP, signal.SIGSTOP, signal.SIGINT)

    thread.syscall()
    debugger.waitSyscall()

    # replace the blocked syscall with a benign sched_yield. orig_rax
    # shouldn't do any damage if the thread isn't blocked on a syscall
    thread.setreg('orig_rax', NR_sched_yield)

    debugger.quit()
    logger.info(f'thread {tid=} unblocked')


def supervisor_process():
    supervisor_queue = multiprocessing.SimpleQueue()

    process = multiprocessing.Process(target=threaded_worker, args=(supervisor_queue,), daemon=True)
    process.start()

    while True:
        task = supervisor_queue.get()
        try:
            match task:
                case 'unblock_thread', tid:
                    unblock_thread(process.pid, tid)
                case 'exit':
                    break
                case _:
                    raise AssertionError(f'invalid supervisor task: {task}')
        except Exception:
            logger.exception('supervisor task failed')

    logger.info('workers restarting')
    process.terminate()
    process.join()


class Command(BaseCommand):
    help = 'Starts a Django Q multithreaded Cluster.'

    def handle(self, *args, **options):
        # don't block on shutdown
        threading._shutdown = lambda: None  # type: ignore[attr-defined]

        with contextlib.suppress(KeyboardInterrupt):
            while True:
                supervisor_process()
