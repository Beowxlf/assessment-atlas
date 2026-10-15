"""Track owned listener workers independently of their daemon exit policy."""
import threading


class TrackedRequests:
    """A listener can stop promptly, then its owner explicitly drains writers.

    Register before thread startup: adding workers inside the handler leaves a
    race where the listener has stopped but an accepted worker has not run yet.
    """
    def __init__(self, *args, **kwargs):
        self._requests_condition = threading.Condition()
        self._requests_workers = set()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if hasattr(request, 'settimeout'):
            request.settimeout(15)
        worker = threading.Thread(target=self.process_request_thread,
                                  args=(request, client_address), daemon=self.daemon_threads)
        with self._requests_condition:
            self._requests_workers.add(worker)
            try:
                worker.start()
            except BaseException:
                self._requests_workers.discard(worker)
                self._requests_condition.notify_all()
                self.shutdown_request(request)
                raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._requests_condition:
                self._requests_workers.discard(threading.current_thread())
                self._requests_condition.notify_all()

    def wait_requests(self):
        current = threading.current_thread()
        with self._requests_condition:
            self._requests_condition.wait_for(lambda: not self._requests_workers.difference({current}))
