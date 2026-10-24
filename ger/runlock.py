"""The run lock: apply, restore and recover run one at a time.

Each of them holds an exclusive flock(2) for its whole run (from before the gates until after its final audit record) on
  <audit log directory>/ger-run.lock    always (every run of these commands appends to that audit log)
  <quarantine store>/.ger-run.lock      when the quarantine store exists (journals and quarantined objects live there)
The lock is taken without waiting: a second run is rejected (G-8, nothing changed) instead of queueing behind the first.
So the G-8 check for an open journal, the journal creation, every change and the final record of one run cannot interleave
with another run on the same audit log or store (two plans that both passed G-8 can no longer edit the same file at the
same time). The kernel drops the lock when the process ends, including SIGKILL: a lock file left behind holds no lock.
"""
from __future__ import annotations

import errno
import fcntl
import os

from . import audit, fsutil, store

LOG_LOCK = "ger-run.lock"
STORE_LOCK = ".ger-run.lock"


class Busy(Exception):
    """Another apply / restore / recover holds the lock."""


class RunLock:
    def __init__(self):
        self.fds: list[int] = []

    def _take(self, dir_path: str, name: str, what: str) -> None:
        dfd = fsutil.open_dir(dir_path)
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | fsutil.O_NOFOLLOW | fsutil.O_CLOEXEC | fsutil.O_NONBLOCK, 0o600,
                         dir_fd=dfd)
        finally:
            os.close(dfd)
        self.fds.append(fd)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                raise Busy(f"another ger apply / restore / recover is running on this {what} "
                           f"({os.path.join(dir_path, name)})") from None
            raise

    def acquire(self) -> None:
        """Takes both locks (the log directory first). Busy if another run holds one; OSError if a lock file cannot be
        opened or locked. On any failure the locks already taken are released."""
        try:
            self._take(str(audit.log_dir()), LOG_LOCK, "audit log")
            sd = store.store_dir()
            if os.path.isdir(sd):
                self._take(sd, STORE_LOCK, "quarantine store")
        except BaseException:
            self.release()
            raise

    def release(self) -> None:
        for fd in reversed(self.fds):
            try:
                os.close(fd)  # Closing the only descriptor of the open file releases its flock
            except OSError:
                pass
        self.fds.clear()
