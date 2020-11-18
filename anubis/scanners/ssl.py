from collections import defaultdict
import socket
import ssl
from socket import gaierror


def search_subject_alt_name(self, target):
  print("Searching for Subject Alt Names")
  try:
    context = ssl.create_default_context()

    # Do connectivity testing to ensure SSLyze is able to connect
    try:
      with socket.create_connection((target, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
          # https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.getpeercert
          cert = ssock.getpeercert()

      subjectAltName = defaultdict(set)
      for type_, san in cert['subjectAltName']:
        subjectAltName[type_].add(san)

      dns_domains = list(subjectAltName['DNS'])
      for domain in dns_domains:
        if domain:
          self.domains.append(domain.strip())
    except gaierror as e:
      # Could not connect to the server; abort
      print(f"Error connecting to {target}: {e}")
      return

  except Exception as e:
    self.handle_exception(e)
