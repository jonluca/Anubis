from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.http_headers_plugin import HttpHeadersScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, Tlsv12ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.synchronous_scanner import SynchronousScanner


def search_subject_alt_name(self, target):
  print("Searching for Subject Alt Names")
  try:
    server_info = ServerConnectivityInfo(hostname=target)
    server_info.test_connectivity_to_server()
    synchronous_scanner = SynchronousScanner()

    # Certificate information
    command = CertificateInfoScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    # Direct object reference is pretty bad, but then again so is the crypto.x509 object implementation, so...
    extensions = scan_result.certificate_chain[0].extensions[6]
    for entry in extensions.value:
      if entry.value.strip() not in self.domains:
        self.domains.append(entry.value.strip())

  except Exception as e:
    self.handle_exception(e)


def ssl_scan(self, target):
  print("Running SSL Scan")
  try:
    server_info = ServerConnectivityInfo(hostname=target)
    server_info.test_connectivity_to_server()
    synchronous_scanner = SynchronousScanner()

    # TLS 1.0
    command = Tlsv10ScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    print("Available TLSv1.0 Ciphers:")
    for cipher in scan_result.accepted_cipher_list:
      print('    {}'.format(cipher.name))

    # TLSv1.2
    command = Tlsv12ScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    print("Available TLSv1.2 Ciphers:")
    for cipher in scan_result.accepted_cipher_list:
      print('    {}'.format(cipher.name))

    # Certificate information
    command = CertificateInfoScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    for entry in scan_result.as_text():
      print(entry)

    # Heartbleed vulnerability info
    command = HeartbleedScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    for entry in scan_result.as_text():
      print(entry)

    # HTTP Headers info
    command = HttpHeadersScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    for entry in scan_result.as_text():
      print(entry)

  except Exception as e:
    self.handle_exception(e, "Error running SSL scan")
    pass
