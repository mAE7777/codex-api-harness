"""Bounded, cancellation-aware API phases; no retries and no provider fallback."""
import queue
import socket
import threading
import time

from guard import Denied, REQUEST_DEADLINE_SECONDS


class RequestControl:
    def __init__(self, cancelled, paused, *, total=REQUEST_DEADLINE_SECONDS, phase_timeout=120):
        self.cancelled, self.paused = cancelled, paused
        self.total_deadline = time.monotonic()+total
        self.phase = 'admission'
        self.phase_timeout = phase_timeout
        self.phase_deadline = self.total_deadline
        self.lock = threading.RLock()
        self.connections = []
        self.error = None
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.done.set()
        self.thread.join(timeout=.3)
        with self.lock:
            connections = list(self.connections)
        for connection in connections: self._close(connection)

    @staticmethod
    def _close(connection):
        sock = getattr(connection, '_api_socket', None) or getattr(connection, 'sock', None)
        if sock is not None:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        try: connection.close()
        except (OSError, ValueError): pass

    def track(self, connection):
        with self.lock:
            if self.error is not None or self.done.is_set():
                self._close(connection)
                self.check()
                raise Denied('The API operation has already finished', code='client_cancelled')
            if not any(item is connection for item in self.connections): self.connections.append(connection)

    def abort(self, error):
        with self.lock:
            if self.error is not None: return
            self.error = error
            connections = list(self.connections)
        for connection in connections: self._close(connection)

    def check(self):
        with self.lock:
            error, phase = self.error, self.phase
        if error is not None: raise error
        if self.cancelled() or self.paused():
            error = Denied('The request was cancelled. Unsent model requests are not charged; unconfirmed dispatched usage retains its reservation.', code='client_cancelled', details={'phase':phase})
            self.abort(error); raise error
        now = time.monotonic()
        if now >= min(self.total_deadline, self.phase_deadline):
            code = 'api_response_deadline' if now >= self.total_deadline else 'api_timeout'
            error = Denied('The '+phase+' phase timed out. No automatic retry was made; possibly dispatched usage retains its reservation.', code=code, status=504, details={'phase':phase})
            self.abort(error); raise error

    def _watch(self):
        while not self.done.wait(.03):
            try: self.check()
            except Denied: return

    def begin(self, phase, timeout):
        self.check()
        with self.lock:
            self.phase = phase
            self.phase_timeout = timeout
            self.phase_deadline = min(self.total_deadline, time.monotonic()+timeout)

    def touch(self):
        self.check()
        with self.lock: self.phase_deadline = min(self.total_deadline, time.monotonic()+self.phase_timeout)

    def call(self, function, phase, timeout, *, returns_connection=False):
        """Return promptly on cancellation even during DNS or a silent header wait.

        Real transports also check this control before sending bytes. A late result
        is closed by its worker and is never reused or dispatched again.
        """
        self.begin(phase, timeout)
        output = queue.Queue(maxsize=1)
        def work():
            result = None
            try:
                self.check()
                result = function()
                if returns_connection: self.track(result[0])
                self.check()
                if self.done.is_set():
                    if returns_connection: self._close(result[0])
                    return
                output.put((True,result))
            except BaseException as error:
                if returns_connection and result is not None: self._close(result[0])
                output.put((False,error))
        threading.Thread(target=work, daemon=True).start()
        while True:
            self.check()
            try: ok, value = output.get(timeout=.03)
            except queue.Empty: continue
            self.check()
            if ok: return value
            raise value
