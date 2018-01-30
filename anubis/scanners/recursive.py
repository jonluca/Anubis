"""The target command."""
import queue
import signal
import sys
import threading
from io import StringIO

from anubis.utils.search_worker import SearchWorker
from anubis.utils.signal_handler import SignalHandler


def recursive_search(self):
  print("Starting recursive search - warning, might take a long time")
  domains = self.clean_domains(self.domains)
  domains_unique = set(domains)
  num_workers = 10

  if self.options["--queue-workers"]:
    num_workers = int(self.options["--queue-workers"])

  stopper = threading.Event()
  url_queue = queue.Queue()
  for domain in domains_unique:
    url_queue.put(domain)

  # we need to keep track of the workers but not start them yet
  workers = [SearchWorker(url_queue, self.domains, stopper, self) for _ in
             range(num_workers)]

  # create our signal handler and connect it
  handler = SignalHandler(stopper, workers)
  signal.signal(signal.SIGINT, handler)

  if not self.options["--verbose"]:
    # catch stdout and replace it with our own
    self.stdout, sys.stdout = sys.stdout, StringIO()

  # start the threads!
  for worker in workers:
    worker.start()

  # wait for the queue to empty
  url_queue.join()

  sys.stdout = self.stdout
