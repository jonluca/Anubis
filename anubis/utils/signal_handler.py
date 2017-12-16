import sys


class SignalHandler:
  """
  The object that will handle signals and stop the worker threads.
  """

  #: The stop event that's shared by this handler and threads.
  stopper = None

  #: The pool of worker threads
  workers = None

  def __init__(self, stopper, workers):
    self.stopper = stopper
    self.workers = workers

  def __call__(self, signum, frame):
    """
    This will be called by the python signal module

    https://docs.python.org/3/library/signal.html#signal.signal
    """
    self.stopper.set()

    for worker in self.workers:
      worker.join()

    sys.__stdout__.write("Quitting...")
    sys.__stdout__.flush()
    sys.exit(0)
