from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from sslyze import ScanCommand, Scanner, ServerConnectivityTester, ServerNetworkLocationViaDirectConnection, ServerScanRequest
from sslyze.errors import ConnectionToServerFailed


def search_subject_alt_name(self, target):
  print("Searching for Subject Alt Names")
  try:
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
      target, 443)

    # Do connectivity testing to ensure SSLyze is able to connect
    try:
      server_info = ServerConnectivityTester().perform(server_location)
    except ConnectionToServerFailed as e:
      # Could not connect to the server; abort
      print(f"Error connecting to {server_location}: {e.error_message}")
      return

    # Then queue some scan commands for the server
    scanner = Scanner()
    server_scan_req = ServerScanRequest(server_info=server_info, scan_commands={
      ScanCommand.CERTIFICATE_INFO}, )
    scanner.queue_scan(server_scan_req)
    # Then retrieve the results
    for server_scan_result in scanner.get_results():
      # Certificate info results
      certinfo_result = server_scan_result.scan_commands_results[
        ScanCommand.CERTIFICATE_INFO]

      # Direct object reference is pretty bad, but then again so is the crypto.x509 object implementation, so...
      cert_deployment = certinfo_result.certificate_deployments[0]
      chain = cert_deployment.received_certificate_chain[0]
      ext = chain.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
      for entry in ext.value.get_values_for_type(x509.DNSName):
        if entry.strip() not in self.domains:
          self.domains.append(entry.strip())

  except Exception as e:
    self.handle_exception(e)


def ssl_scan(self, target):
  print("Running SSL Scan")
  # Define the server that you want to scan
  server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
    target, 443)

  try:
    # Do connectivity testing to ensure SSLyze is able to connect
    try:
      server_info = ServerConnectivityTester().perform(server_location)
    except ConnectionToServerFailed as e:
      # Could not connect to the server; abort
      print(f"Error connecting to {server_location}: {e.error_message}")
      return

    # Then queue some scan commands for the server
    scanner = Scanner()
    server_scan_req = ServerScanRequest(server_info=server_info, scan_commands={
      ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,
      ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
      ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES,
      ScanCommand.HEARTBLEED, ScanCommand.HTTP_HEADERS}, )
    scanner.queue_scan(server_scan_req)

    # Then retrieve the results
    for server_scan_result in scanner.get_results():
      print(
        f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

      heartbleed_vuln = server_scan_result.scan_commands_results[
        ScanCommand.HEARTBLEED].is_vulnerable_to_heartbleed
      print(f"\nIs vulnerable to heartbleed? {heartbleed_vuln}")

      print("\nAccepted cipher suites for TLS 1.0:")
      for accepted_cipher_suite in server_scan_result.scan_commands_results[
        ScanCommand.TLS_1_0_CIPHER_SUITES].accepted_cipher_suites:
        print(f"* {accepted_cipher_suite.cipher_suite.name}")

      print("\nAccepted cipher suites for TLS 1.1:")
      for accepted_cipher_suite in server_scan_result.scan_commands_results[
        ScanCommand.TLS_1_1_CIPHER_SUITES].accepted_cipher_suites:
        print(f"* {accepted_cipher_suite.cipher_suite.name}")

      print("\nAccepted cipher suites for TLS 1.2:")
      for accepted_cipher_suite in server_scan_result.scan_commands_results[
        ScanCommand.TLS_1_2_CIPHER_SUITES].accepted_cipher_suites:
        print(f"* {accepted_cipher_suite.cipher_suite.name}")

      print("\nAccepted cipher suites for TLS 1.3:")
      for accepted_cipher_suite in server_scan_result.scan_commands_results[
        ScanCommand.TLS_1_3_CIPHER_SUITES].accepted_cipher_suites:
        print(f"* {accepted_cipher_suite.cipher_suite.name}")

      # SSL 2.0 results
      ssl2_result = server_scan_result.scan_commands_results[
        ScanCommand.SSL_2_0_CIPHER_SUITES]
      print("\nAccepted cipher suites for SSL 2.0:")
      for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
        print(f"* {accepted_cipher_suite.cipher_suite.name}")

      # Certificate info results
      certinfo_result = server_scan_result.scan_commands_results[
        ScanCommand.CERTIFICATE_INFO]
      print("\nCertificate info:")
      for cert_deployment in certinfo_result.certificate_deployments:
        print(
          f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")

  except Exception as e:
    self.handle_exception(e, "Error running SSL scan")
    pass
