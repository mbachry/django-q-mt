# django-q-mt

Multi-threaded django-q2 worker.

## Install

`pip install django-q-mt`

## Usage

Add `django_q_mt` to `INSTALLED_APPS`.

`./manage.py django_q_mt`

Supports standard `django-q2` configuration like `Q_CLUSTER`,
`workers`, `timeout`.

## Limitations

`recycle` isn't supported at the moment. If memory leaks are a
concern, you can use `MemoryMax=` in systemd or an equivalent.


## Timeouts

Timeout handling is more finicky and unreliable in multi-threaded
setups. `django-q-mt` forces timeouts in the following stages:

* A `TimeoutError` is injected with `PyThreadState_SetAsyncExc`. The
  thread must run the Python interpreter in order for this to work.

* If the thread is still alive after 30 seconds, `django-q-mt` uses
  `ptrace` to force-stop a blocking syscall, eg. an infinite `read`
  from a socket.

* If it fails, after 30 second the entire process with all threads is
  recycled. It should be a rare case, as at this point the timing out
  thread is either running a tight C loop or is deadlocked.
