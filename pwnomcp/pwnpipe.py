import threading
import subprocess
import queue
import json
import os
from typing import Optional


class PwnPipe:
    """
    Simple subprocess I/O pipeline with queued output buffer.

    - Accumulates stdout/stderr into an internal queue
    - release() returns accumulated output and clears the queue
    - send(data) writes raw data to stdin (no newline automatically)
    - Detects attach marker lines: 'PWNCLI_ATTACH_RESULT:<json>'
    """

    def __init__(self, command: str, cwd: Optional[str] = None, env: Optional[dict] = None):
        self.command = command
        self.cwd = cwd
        self.env = env or {}
        env_full = os.environ.copy()
        env_full.update(self.env)

        self.proc = subprocess.Popen(
            command,
            cwd=self.cwd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
            env=env_full,
        )
        self._q: "queue.Queue[str]" = queue.Queue()
        self._alive = True
        self._lock = threading.Lock()
        self._attach_result = None

        self._t_out = threading.Thread(target=self._reader, args=(self.proc.stdout,))
        self._t_err = threading.Thread(target=self._reader, args=(self.proc.stderr,))
        self._t_out.daemon = True
        self._t_err.daemon = True
        self._t_out.start()
        self._t_err.start()

        self._t_wait = threading.Thread(target=self._waiter)
        self._t_wait.daemon = True
        self._t_wait.start()

    def _reader(self, pipe):
        for line in iter(pipe.readline, ''):
            if line.startswith("PWNCLI_ATTACH_RESULT:"):
                payload = line.split(":", 1)[1].strip()
                try:
                    with self._lock:
                        self._attach_result = json.loads(payload)
                except Exception:
                    pass
                continue
            self._q.put(line)
        pipe.close()

    def _waiter(self):
        self.proc.wait()
        with self._lock:
            self._alive = False

    def is_alive(self) -> bool:
        with self._lock:
            return self._alive and (self.proc.poll() is None)

    def send(self, data: str) -> bool:
        if not self.is_alive():
            return False
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
            return True
        except Exception:
            return False

    def release(self) -> str:
        chunks = []
        try:
            while True:
                chunks.append(self._q.get_nowait())
        except queue.Empty:
            pass
        return ''.join(chunks)

    def get_attach_result(self):
        with self._lock:
            return self._attach_result

    def kill(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.kill()
        finally:
            with self._lock:
                self._alive = False


