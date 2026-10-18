"""Synthetic crt.sh fixtures and mocked requests; no network is used."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from anubis.scanners import crt


ROOT = "example.com"
MULTI_NAME_CELL = (
  "<TD>dev.example.com<BR>example.com<BR>products.example.com"
  "<BR>support.example.com<BR>www.example.com</TD>"
)
MULTI_NAME_DOMAINS = {
  ROOT, "dev.example.com", "products.example.com", "support.example.com",
  "www.example.com",
}


@pytest.fixture(autouse=True)
def forbid_http_requests(monkeypatch):
  def unexpected_request(*args, **kwargs):
    pytest.fail("Offline crt.sh tests must mock HTTP requests")

  monkeypatch.setattr(crt.requests.sessions.Session, "request", unexpected_request)


@pytest.mark.parametrize("html, expected", [
  pytest.param("<TD>www.example.com</TD>", {ROOT, "www.example.com"},
               id="single-name-control"),
  pytest.param(MULTI_NAME_CELL, MULTI_NAME_DOMAINS, id="multi-name-br-cell"),
  pytest.param('<TD style="text-align:left">www.example.com</TD>',
               {ROOT, "www.example.com"}, id="styled-td-cell"),
])
def test_regression_fixtures(html, expected):
  assert set(crt.extract_domains(html, ROOT)) == expected


@pytest.mark.parametrize("tag", ["TD", "td", "Td"])
@pytest.mark.parametrize("br", ["<BR>", "<br>", "<br/>", "<Br />", "</br>",
                                '<br class="names">'])
def test_tag_case_and_break_variants(tag, br):
  html = f"<{tag}>a.example.com{br}b.example.com</{tag}>"
  assert set(crt.extract_domains(html, ROOT)) == {
    ROOT, "a.example.com", "b.example.com",
  }


def test_entities_whitespace_case_and_duplicates():
  html = (
    "<td>\n WWW&#46;EXAMPLE.COM &nbsp;<br>example.com<br>www.example.com</td>"
    "<td>www.example.com</td><td>&#97;pi.example.com</td>"
  )
  domains = crt.extract_domains(html, "  ExAmPlE.CoM  ")
  assert set(domains) == {ROOT, "www.example.com", "api.example.com"}
  assert len(domains) == 3


def test_only_exact_target_and_dot_delimited_subdomains():
  html = (
    "<td>example.com<br>a.b.example.com<br>notexample.com"
    "<br>www.notexample.com<br>example.com.evil.test<br>elsewhere.test</td>"
  )
  assert set(crt.extract_domains(html, ROOT)) == {ROOT, "a.b.example.com"}


@pytest.mark.parametrize("name", [
  "-bad.example.com", "bad-.example.com", "bad_name.example.com",
  "bad..example.com", ".example.com", "bad name.example.com",
  "https://www.example.com", "user@example.com", "www.example.com:443",
  "bad/part.example.com", "\x00bad.example.com", "café.example.com", "K.example.com",
  "a" * 64 + ".example.com", ".".join(["a" * 63] * 4) + ".example.com",
  "www.example.com.", "evil&lt;br&gt;www.example.com",
])
def test_invalid_hostnames_are_rejected(name):
  assert crt.extract_domains(f"<td>{name}</td>", ROOT) == [ROOT]


def test_valid_label_and_hostname_length_boundaries():
  label = "a" * 63
  longest = ".".join([label, label, label, "a" * 49, ROOT])
  assert len(longest) == 253
  html = f"<td>{label}.example.com<br>{longest}<br>xn--caf-dma.example.com</td>"
  assert set(crt.extract_domains(html, ROOT)) == {
    ROOT, label + ".example.com", longest, "xn--caf-dma.example.com",
  }


def test_wildcards_do_not_invent_concrete_hostnames():
  html = "<td>*.example.com<br>*.hidden.example.com<br>foo*.example.com</td>"
  assert crt.extract_domains(html, ROOT) == [ROOT]


@pytest.mark.parametrize("html", [
  "", "not HTML", "<html><body>error</body></html>", "<td></td>",
  "<td> &nbsp; <br> </td>", "<td", "<td><", "<!-- <td>bad.example.com</td> -->",
])
def test_empty_or_malformed_html_preserves_root(html):
  assert crt.extract_domains(html, ROOT) == [ROOT]


@pytest.mark.parametrize("html", [
  "<td>a.example.com", "<td>a.example.com<td>b.example.com</td>",
  "<table><tr><td>a.example.com</tr></table><td>b.example.com</td>",
])
def test_missing_cell_closures_do_not_join_hostnames(html):
  expected = {ROOT, "a.example.com"}
  if "b.example.com" in html:
    expected.add("b.example.com")
  assert set(crt.extract_domains(html, ROOT)) == expected


def test_only_cell_text_is_considered():
  html = (
    '<p>outside.example.com</p><td title="attribute.example.com">123</td>'
    '<script>script.example.com</script><td>a.example.com</td>'
  )
  assert set(crt.extract_domains(html, ROOT)) == {ROOT, "a.example.com"}


@pytest.mark.parametrize("boundary", ["th", "tr", "thead", "tbody", "tfoot", "table"])
def test_opening_table_boundaries_finish_the_previous_cell(boundary):
  html = f"<td>a.example.com<{boundary}>b.example.com</{boundary}><td>c.example.com"
  assert set(crt.extract_domains(html, ROOT)) == {
    ROOT, "a.example.com", "c.example.com",
  }


@pytest.mark.parametrize("tag", ["script", "style", "a", "span", "div"])
def test_nested_markup_is_not_interpreted_as_names(tag):
  html = (
    f"<td><{tag}><br>hidden.example.com<br></{tag}>"
    "<br>skipped.example.com</td><td>real.example.com</td>"
    f"<td>made<{tag}>up</{tag}>.example.com</td>"
  )
  assert set(crt.extract_domains(html, ROOT)) == {ROOT, "real.example.com"}


@pytest.mark.parametrize("target", ["café.com", "example.com.", "xn--caf-dma.com"])
def test_caller_target_suffix_is_preserved_without_idna_conversion(target):
  html = f"<TD>www.{target}</TD><td>unrelated.com</td>"
  assert set(crt.extract_domains(html, target)) == {target, "www." + target}


def test_unicode_does_not_become_an_ascii_target_suffix():
  assert crt.extract_domains("<TD>www.K.example.com</TD>", "k.example.com") == [
    "k.example.com",
  ]


def test_nested_target_boundary():
  html = "<td>example.com<br>dev.example.com<br>a.dev.example.com<br>notdev.example.com</td>"
  assert set(crt.extract_domains(html, "dev.example.com")) == {
    "dev.example.com", "a.dev.example.com",
  }


def test_search_crtsh_with_mocked_response(monkeypatch):
  get = Mock(return_value=SimpleNamespace(text=MULTI_NAME_CELL))
  monkeypatch.setattr(crt.requests, "get", get)
  scanner = SimpleNamespace(domains=["www.example.com"],
                            options={"--verbose": True}, handle_exception=Mock())

  crt.search_crtsh(scanner, "https://example.com/path")

  get.assert_called_once()
  assert get.call_args.args == ("https://crt.sh/",)
  assert get.call_args.kwargs["params"] == (("q", "%.example.com"),)
  assert "headers" in get.call_args.kwargs
  assert set(scanner.domains) == MULTI_NAME_DOMAINS
  assert len(scanner.domains) == len(MULTI_NAME_DOMAINS)
  scanner.handle_exception.assert_not_called()


def test_search_crtsh_handles_request_error(monkeypatch):
  error = crt.requests.RequestException("synthetic failure")
  monkeypatch.setattr(crt.requests, "get", Mock(side_effect=error))
  scanner = SimpleNamespace(domains=[], options={"--verbose": False},
                            handle_exception=Mock())

  crt.search_crtsh(scanner, ROOT)

  assert scanner.domains == []
  scanner.handle_exception.assert_called_once_with(error, "Error searching crt.sh")
