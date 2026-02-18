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
from django.dispatch import Signal
from django.utils import timezone
from django_q.brokers import get_broker
from django_q.conf import Conf
from django_q.monitor import save_cached, save_task
from django_q.scheduler import scheduler
from django_q.signals import pre_execute
from django_q.signing import SignedPackage
from django_q.utils import get_func_repr
from ptrace.debugger import ProcessSignal, PtraceDebugger
from ptrace.syscall import SYSCALL_NAMES

NR_sched_yield = next(k for k, v in SYSCALL_NAMES.items() if v == 'sched_yield')

ctypes.pythonapi.PyThreadState_SetAsyncExc.argtypes = [ctypes.c_long, ctypes.py_object]
ctypes.pythonapi.PyThreadState_SetAsyncExc.restype = ctypes.c_int

logger = logging.getLogger('django-q')

# compatibility signal for django-q2<=1.9.0
post_execute_in_worker = Signal()


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

    pre_execute.send(sender="django_q", func=f, task=task)

    try:
        res = f(*task["args"], **task["kwargs"])
        result = (res, True)
    except Exception as e:
        result = (f"{e} : {traceback.format_exc()}", False)

    post_execute_in_worker.send(sender="django_q", func=f, task=task)

    return result


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
    future: concurrent.futures.Future
    ack_id: int
    task: dict
    started_at: float | None = None
    thread_id: int | None = None
    native_thread_id: int | None = None
    timeout_attempts: int = 0


@dataclasses.dataclass
class Futures:
    data: dict[concurrent.futures.Future, FutureInfo]
    booting: dict[threading.Event, FutureInfo]
    lock: threading.Lock


def threaded_worker(supervisor_queue: multiprocessing.SimpleQueue):
    broker = get_broker()

    sched_event = threading.Event()
    sched_thread = threading.Thread(target=run_scheduler, args=(broker, sched_event))
    sched_thread.daemon = True
    sched_thread.start()

    timeout = Conf.TIMEOUT

    futures = Futures(data={}, booting={}, lock=threading.Lock())

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

    def worker_wrapper(event, task):
        event.wait()
        tid = threading.get_ident()
        native = threading.get_native_id()
        with futures.lock:
            info = futures.booting.pop(event)
            info.started_at = time.monotonic()
            info.thread_id = tid
            info.native_thread_id = native
            futures.data[info.future] = info
            info.future.add_done_callback(worker_done_cb)
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

                task['ack_id'] = ack_id

                event = threading.Event()
                future = executor.submit(worker_wrapper, event, task)
                info = FutureInfo(future=future, ack_id=ack_id, task=task)
                with futures.lock:
                    futures.booting[event] = info
                event.set()

    # sched_event.set()
    # cancel_event.set()


def unblock_thread(pid, tid):
    logger.info(f'unblocking timed out thread {tid=}')
    debugger = PtraceDebugger()
    try:
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
        logger.info(f'thread {tid=} unblocked')
    except ProcessSignal as e:
        logger.info(f'ProcessSignal during syscall wait: {e}')
    finally:
        debugger.quit()


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
