"""Search worker """

import queue
import sys
import threading
from threading import Thread

from anubis.scanners.crt import search_crtsh
from anubis.scanners.dnsdumpster import search_dnsdumpster
from anubis.scanners.hackertarget import subdomain_hackertarget
from anubis.scanners.netcraft import search_netcraft
from anubis.scanners.pkey import search_pkey
from anubis.scanners.zonetransfer import dns_zonetransfer


class SearchWorker(threading.Thread):
  """
  The thread that will check HTTP statuses.
  """

  #: The queue of urls
  domain_queue = None

  #: An event that tells the thread to stop
  stopper = None

  domains = list()
  master_domains = None
  parent = None

  def __init__(self, domain_queue, domains, stopper, parent):
    super().__init__()
    self.domain_queue = domain_queue
    self.stopper = stopper
    self.master_domains = domains
    self.parent = parent

  def run(self):
    while not self.stopper.is_set():
      try:
        target = self.domain_queue.get_nowait()
      except queue.Empty:
        break
      else:
        sys.__stdout__.write("Starting recursive search on " + target + "\n")
        self.parent.stdout.flush()
        # Default scans that run every time
        threads = [Thread(target=dns_zonetransfer(self.parent, target)),
                   Thread(target=subdomain_hackertarget(self.parent, target)),
                   Thread(target=search_pkey(self.parent, target)),
                   Thread(target=search_netcraft(self.parent, target)),
                   Thread(target=search_crtsh(self.parent, target)),
                   Thread(target=search_dnsdumpster(self.parent, target))]

        # Start all threads
        for x in threads:
          x.start()

        # Wait for all of them to finish
        for x in threads:
          x.join()

        self.domains = self.parent.clean_domains(self.domains)
        for domain in self.domains:
          if domain not in self.master_domains:
            sys.__stdout__.write("Found new domain: " + domain)
            self.master_domains.append(domain)
            self.domain_queue.put(domain)

        self.domain_queue.task_done()
