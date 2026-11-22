"""Tests for the SECURITY.md rendering check. No network: the HTTP opener and the sleep are replaced."""
import contextlib
import http.client
import http.server
import inspect
import io
import json
import os
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import check_security_txt as cst

CONTACT = cst.CONTACT
# Built with chr() so this file stays plain ASCII.
ZERO_WIDTH_SPACE = chr(0x200B)
NO_BREAK_SPACE = chr(0xA0)
E_GRAVE = chr(0xE8)


def page(anchor):
    return f"<p>Report it: {anchor}.</p>\n"


def link(text, href=CONTACT):
    return f'<a href="{href}">{text}</a>'


class CheckRendered(unittest.TestCase):
    def assertLinked(self, html):
        self.assertEqual(cst.check_rendered(html, "gfm"), [])

    def assertNotLinked(self, html, mode="gfm"):
        errors = cst.check_rendered(html, mode)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(f"({mode})", errors[0])
        self.assertIn(CONTACT, errors[0])

    def test_link_with_text(self):
        self.assertLinked(page(link("ipso")))

    def test_link_text_in_a_nested_element(self):
        self.assertLinked(page(link("<b>ipso</b>")))

    def test_link_text_with_an_entity(self):
        self.assertLinked(page(link("a &amp; b")))

    def test_link_text_with_a_non_ascii_letter(self):
        self.assertLinked(page(link("pr" + E_GRAVE)))

    def test_bare_url_that_github_turned_into_a_link(self):
        self.assertLinked(page(link(CONTACT)))

    def test_one_good_link_among_other_anchors(self):
        self.assertLinked(page(link("other", "https://example.com") + " " + link("ipso")))

    def test_uppercase_tag_and_attribute(self):
        self.assertLinked(page(f'<A HREF="{CONTACT}">ipso</A>'))

    def test_link_in_common_visible_elements(self):
        for wrapper in ("p", "li", "td", "h2", "blockquote", "strong", "em", "code", "kbd", "div", "summary", "ul"):
            with self.subTest(wrapper=wrapper):
                self.assertLinked(f"<{wrapper}>{link('ipso')}</{wrapper}>")

    def test_link_with_deeply_nested_visible_elements(self):
        self.assertLinked(f"<blockquote><p><strong><em>{link('<code>ipso</code>')}</em></strong></p></blockquote>")

    def test_void_elements_do_not_break_the_nesting(self):
        self.assertLinked(page(link("ip<br>so")))
        self.assertLinked(page(link('<img src="https://example.com/i.png" alt="x">ipso')))
        self.assertLinked('<hr><p><img src="https://example.com/i.png" alt="x"> ' + link("ipso") + "</p>")

    def test_stray_end_tags_are_ignored(self):
        self.assertLinked(f'<p><a href="{CONTACT}">ipso</b></i></a></p>')

    def test_ruby_base_text_is_visible(self):
        self.assertLinked(page(link("<ruby>ipso<rp>(</rp><rt>x</rt><rp>)</rp></ruby>")))

    def test_text_that_only_an_rp_element_holds_is_hidden(self):
        self.assertNotLinked(page(link("<ruby><rp>ipso</rp></ruby>")))

    def test_text_in_a_hidden_element_inside_the_anchor_is_not_counted(self):
        for element in ("rp", "template", "style", "script", "svg", "datalist", "noembed", "canvas", "object", "title"):
            with self.subTest(element=element):
                self.assertNotLinked(page(link(f"<{element}>ipso</{element}>")))

    def test_text_in_an_unknown_element_is_not_counted(self):
        self.assertNotLinked(page(link("<made-up>ipso</made-up>")))

    def test_hidden_text_does_not_count_but_visible_text_beside_it_does(self):
        self.assertLinked(page(link("<rp>hidden</rp>shown")))

    def test_an_anchor_inside_a_hidden_element_is_not_counted(self):
        for element in ("rp", "template", "svg", "datalist", "noembed", "canvas", "object", "made-up"):
            with self.subTest(element=element):
                self.assertNotLinked(page(f"<{element}>{link('ipso')}</{element}>"))

    def test_an_unclosed_hidden_element_inside_the_anchor_hides_the_rest(self):
        self.assertNotLinked(f'<p><a href="{CONTACT}"><rp>ipso</a></p>')

    def test_hangul_filler_characters_are_not_visible_text(self):
        for code in (0x3164, 0xFFA0, 0x115F, 0x1160):
            with self.subTest(code=hex(code)):
                self.assertNotLinked(page(link(chr(code))))

    def test_text_with_only_non_ascii_letters_is_not_counted(self):
        self.assertNotLinked(page(link(E_GRAVE)))
        self.assertNotLinked(page(link(chr(0x3B1))))

    def test_text_with_an_ascii_letter_beside_non_ascii_ones_is_counted(self):
        self.assertLinked(page(link(chr(0x3164) + "a")))

    def test_ascii_digit_is_visible_text(self):
        self.assertLinked(page(link("1")))

    def test_empty_page(self):
        self.assertNotLinked("")

    def test_no_anchor(self):
        self.assertNotLinked(page("ipso"))

    def test_url_as_plain_text_is_not_a_link(self):
        self.assertNotLinked(page(CONTACT))

    def test_other_href(self):
        self.assertNotLinked(page(link("ipso", "https://example.com/report")))

    def test_href_that_only_starts_with_the_contact(self):
        self.assertNotLinked(page(link("ipso", CONTACT + "/extra")))

    def test_href_with_a_trailing_slash(self):
        self.assertNotLinked(page(link("ipso", CONTACT + "/")))

    def test_contact_in_the_text_of_another_link(self):
        self.assertNotLinked(page(link(CONTACT, "https://example.com/report")))

    def test_empty_text(self):
        self.assertNotLinked(page(link("")))

    def test_zero_width_space_text(self):
        self.assertNotLinked(page(link(ZERO_WIDTH_SPACE)))

    def test_no_break_space_text(self):
        self.assertNotLinked(page(link(NO_BREAK_SPACE)))

    def test_whitespace_text(self):
        self.assertNotLinked(page(link(" \n ")))

    def test_empty_element_text(self):
        self.assertNotLinked(page(link("<span></span>")))

    def test_image_only(self):
        self.assertNotLinked(page(link('<img src="https://example.com/i.png" alt="ipso">')))

    def test_unclosed_anchor(self):
        self.assertNotLinked(f'<p><a href="{CONTACT}">ipso</p>')

    def test_the_mode_is_named_in_the_error(self):
        self.assertNotLinked("", mode="markdown")


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class FakeOpener:
    """Return the next outcome for each call: bytes are a response, an exception is raised."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.timeouts = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)


def http_error(code):
    return urllib.error.HTTPError(cst.MARKDOWN_API, code, "x", {}, None)


class Render(unittest.TestCase):
    def render(self, opener, token=None, text="# hi", mode="gfm"):
        self.sleeps = []
        return cst.render(text, mode, token, opener=opener, sleep=self.sleeps.append)

    def test_returns_the_decoded_body(self):
        opener = FakeOpener(("<p>caf" + chr(0xE9) + "</p>").encode("utf-8"))
        self.assertEqual(self.render(opener), "<p>caf" + chr(0xE9) + "</p>")
        self.assertEqual(self.sleeps, [])

    def test_request_shape(self):
        opener = FakeOpener(b"<p>x</p>")
        self.render(opener, text="# title", mode="markdown")
        request = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, cst.MARKDOWN_API)
        self.assertEqual(json.loads(request.data), {"text": "# title", "mode": "markdown"})
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("User-agent"), "security-txt-check")
        self.assertEqual(opener.timeouts, [cst.REQUEST_TIMEOUT])

    def test_no_authorization_header_without_a_token(self):
        opener = FakeOpener(b"<p>x</p>")
        self.render(opener)
        self.assertIsNone(opener.requests[0].get_header("Authorization"))

    def test_token_is_sent_as_a_bearer_token(self):
        opener = FakeOpener(b"<p>x</p>")
        self.render(opener, token="TOKEN-VALUE")
        self.assertEqual(opener.requests[0].get_header("Authorization"), "Bearer TOKEN-VALUE")

    def test_retries_a_server_error(self):
        opener = FakeOpener(http_error(502), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")
        self.assertEqual(self.sleeps, [10])

    def test_retries_rate_limits_with_the_longer_delay_second(self):
        opener = FakeOpener(http_error(429), http_error(403), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")
        self.assertEqual(self.sleeps, [10, 30])

    def test_gives_up_after_three_attempts(self):
        opener = FakeOpener(http_error(503), http_error(503), http_error(503))
        with self.assertRaises(cst.RenderError) as caught:
            self.render(opener)
        self.assertIn("3 attempt(s)", str(caught.exception))
        self.assertIn("HTTP 503", str(caught.exception))
        self.assertIn("mode gfm", str(caught.exception))
        self.assertEqual(self.sleeps, [10, 30])
        self.assertEqual(len(opener.requests), 3)

    def test_other_client_errors_are_not_retried(self):
        for code in (400, 401, 404, 422):
            with self.subTest(code=code):
                opener = FakeOpener(http_error(code), b"<p>never used</p>")
                with self.assertRaises(cst.RenderError) as caught:
                    self.render(opener)
                self.assertIn(f"HTTP {code}", str(caught.exception))
                self.assertIn("1 attempt(s)", str(caught.exception))
                self.assertEqual(len(opener.requests), 1)
                self.assertEqual(self.sleeps, [])

    def test_retries_a_network_error(self):
        opener = FakeOpener(urllib.error.URLError("connection reset"), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")

    def test_retries_a_timeout(self):
        opener = FakeOpener(TimeoutError("timed out"), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")

    def test_retries_a_body_that_is_not_utf8(self):
        opener = FakeOpener(bytes([0xFF, 0xFE]), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")

    def test_network_error_message_names_the_reason(self):
        opener = FakeOpener(*[urllib.error.URLError("certificate verify failed")] * 3)
        with self.assertRaises(cst.RenderError) as caught:
            self.render(opener)
        self.assertIn("certificate verify failed", str(caught.exception))

    def test_the_token_never_appears_in_an_error(self):
        opener = FakeOpener(http_error(401))
        with self.assertRaises(cst.RenderError) as caught:
            self.render(opener, token="SECRET-TOKEN-VALUE")
        self.assertNotIn("SECRET-TOKEN-VALUE", str(caught.exception))


class RenderRobustness(unittest.TestCase):
    def render(self, opener, token=None):
        return cst.render("x", "gfm", token, opener=opener, sleep=lambda seconds: None)

    def test_retries_an_incomplete_read(self):
        opener = FakeOpener(http.client.IncompleteRead(b"ab"), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")

    def test_retries_a_bad_status_line(self):
        opener = FakeOpener(http.client.BadStatusLine("garbage"), b"<p>ok</p>")
        self.assertEqual(self.render(opener), "<p>ok</p>")

    def test_gives_up_on_a_connection_that_keeps_dropping(self):
        opener = FakeOpener(*[http.client.IncompleteRead(b"ab")] * 3)
        with self.assertRaises(cst.RenderError) as caught:
            self.render(opener)
        self.assertIn("IncompleteRead", str(caught.exception))
        self.assertIn("3 attempt(s)", str(caught.exception))

    def test_a_value_error_message_is_not_printed(self):
        secret = "SECRET-TOKEN-VALUE"
        opener = FakeOpener(*[ValueError(f"Invalid header value b'Bearer {secret}'")] * 3)
        with self.assertRaises(cst.RenderError) as caught:
            self.render(opener, token=secret)
        self.assertIn("ValueError", str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))

    def test_a_token_with_a_newline_is_refused_before_any_request(self):
        opener = FakeOpener(b"<p>never used</p>")
        with self.assertRaises(cst.RenderError) as caught:
            self.render(opener, token="ghp_SECRET\n")
        self.assertNotIn("ghp_SECRET", str(caught.exception))
        self.assertEqual(opener.requests, [])

    def test_tokens_with_a_space_or_non_ascii_character_are_refused(self):
        for token in ("two words", "caf" + E_GRAVE, "tab\there", "cr\rtoken"):
            with self.subTest(token=repr(token)):
                opener = FakeOpener(b"<p>never used</p>")
                with self.assertRaises(cst.RenderError):
                    self.render(opener, token=token)
                self.assertEqual(opener.requests, [])

    def test_an_empty_token_sends_no_authorization_header(self):
        opener = FakeOpener(b"<p>ok</p>")
        self.render(opener, token="")
        self.assertIsNone(opener.requests[0].get_header("Authorization"))


class RenderLimits(unittest.TestCase):
    def test_a_response_over_the_size_limit_is_refused(self):
        opener = FakeOpener(b"a" * (cst.MAX_RESPONSE_BYTES + 1))
        with self.assertRaises(cst.RenderError) as caught:
            cst.render("x", "gfm", None, opener=opener, sleep=lambda seconds: None)
        self.assertIn("more than", str(caught.exception))

    def test_a_response_at_the_size_limit_is_accepted(self):
        opener = FakeOpener(b"a" * cst.MAX_RESPONSE_BYTES)
        html = cst.render("x", "gfm", None, opener=opener, sleep=lambda seconds: None)
        self.assertEqual(len(html), cst.MAX_RESPONSE_BYTES)


class Redirects(unittest.TestCase):
    """The default opener must not follow a redirect, which would forward the token to another host."""

    def test_render_uses_the_opener_that_refuses_redirects_by_default(self):
        default = inspect.signature(cst.render).parameters["opener"].default
        self.assertEqual(default, cst.NO_REDIRECT_OPENER.open)

    def test_the_handler_refuses_every_redirect(self):
        handler = cst._NoRedirect()
        request = urllib.request.Request("https://api.github.com/markdown", headers={"Authorization": "Bearer X"})
        self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/"))

    def test_a_real_redirect_is_not_followed_and_sends_no_second_request(self):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            # A 302 is the redirect that urllib follows for a POST: it sends a GET with the same Authorization.
            def do_POST(self):
                seen.append(("POST", self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                seen.append(("GET", self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_address[1]}/markdown",
                data=b"{}",
                headers={"Authorization": "Bearer SECRET"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as caught:
                cst.NO_REDIRECT_OPENER.open(request, timeout=5)
            self.assertEqual(caught.exception.code, 302)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(seen, [("POST", "/markdown", "Bearer SECRET")])

    def test_render_reports_a_redirect_as_an_error_without_retrying(self):
        opener = FakeOpener(http_error(307), b"<p>never used</p>")
        with self.assertRaises(cst.RenderError) as caught:
            cst.render("x", "gfm", "T", opener=opener, sleep=lambda seconds: None)
        self.assertIn("HTTP 307", str(caught.exception))
        self.assertEqual(len(opener.requests), 1)


class CheckSecurityMd(unittest.TestCase):
    GOOD = page(link("ipso"))
    BAD = page("no link")

    def renderer(self, outcomes):
        self.calls = []

        def render(text, mode, token):
            self.calls.append((text, mode, token))
            outcome = outcomes[mode]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        return render

    def test_both_modes_are_rendered_and_must_link(self):
        renderer = self.renderer({"gfm": self.GOOD, "markdown": self.GOOD})
        self.assertEqual(cst.check_security_md("# policy", "TOKEN", renderer), [])
        self.assertEqual(self.calls, [("# policy", "gfm", "TOKEN"), ("# policy", "markdown", "TOKEN")])

    def test_modes_are_gfm_and_markdown(self):
        self.assertEqual(cst.MARKDOWN_MODES, ("gfm", "markdown"))

    def test_a_link_missing_in_one_mode_fails(self):
        for good, bad in (("gfm", "markdown"), ("markdown", "gfm")):
            with self.subTest(missing=bad):
                renderer = self.renderer({good: self.GOOD, bad: self.BAD})
                errors = cst.check_security_md("x", None, renderer)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(f"({bad})", errors[0])

    def test_a_render_error_in_one_mode_is_reported_and_the_other_still_checked(self):
        renderer = self.renderer({"gfm": cst.RenderError("gfm is down"), "markdown": self.BAD})
        errors = cst.check_security_md("x", None, renderer)
        self.assertEqual(len(errors), 2, errors)
        self.assertIn("gfm is down", errors[0])
        self.assertIn("(markdown)", errors[1])
        self.assertEqual([call[1] for call in self.calls], ["gfm", "markdown"])


class Main(unittest.TestCase):
    """main() on a temporary repository. check_security_md is replaced, so there is no network."""

    def repo(self, security_txt="valid", security_md=b"# policy\n"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        if security_txt == "valid":
            expires = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
            security_txt = (
                f"Contact: {CONTACT}\nExpires: {expires}\nPreferred-Languages: en\n"
                f"Canonical: {cst.CANONICAL}\nPolicy: {cst.POLICY}\n"
            )
        if security_txt is not None:
            (root / ".well-known").mkdir()
            (root / ".well-known" / "security.txt").write_bytes(security_txt.encode("ascii"))
        if security_md is not None:
            (root / "SECURITY.md").write_bytes(security_md)
        return root

    def main(self, root, environ=None, md_errors=()):
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.object(cst, "ROOT", root), unittest.mock.patch.object(
            cst, "check_security_md", return_value=list(md_errors)
        ) as check_md, unittest.mock.patch.dict(os.environ, environ or {}, clear=False), contextlib.redirect_stdout(
            out
        ), contextlib.redirect_stderr(err):
            code = cst.main()
        return code, out.getvalue(), err.getvalue(), check_md

    def test_ok(self):
        code, out, err, _ = self.main(self.repo())
        self.assertEqual((code, out.strip(), err), (0, "security.txt: ok", ""))

    def test_missing_security_txt_is_an_error_not_a_traceback(self):
        code, _, err, check_md = self.main(self.repo(security_txt=None))
        self.assertEqual(code, 1)
        self.assertIn("cannot read .well-known/security.txt: FileNotFoundError", err)
        check_md.assert_called_once()

    def test_missing_security_md_is_an_error_not_a_traceback(self):
        code, _, err, check_md = self.main(self.repo(security_md=None))
        self.assertEqual(code, 1)
        self.assertIn("cannot read SECURITY.md: FileNotFoundError", err)
        check_md.assert_not_called()

    def test_security_md_that_is_not_utf8_is_an_error_not_a_traceback(self):
        code, _, err, check_md = self.main(self.repo(security_md=bytes([0x63, 0x61, 0x66, 0xE9])))
        self.assertEqual(code, 1)
        self.assertIn("cannot read SECURITY.md: UnicodeDecodeError", err)
        check_md.assert_not_called()

    def test_errors_from_the_rendering_check_fail_the_run(self):
        code, out, err, _ = self.main(self.repo(), md_errors=["no link"])
        self.assertEqual(code, 1)
        self.assertIn("security.txt: no link", err)
        self.assertEqual(out, "")

    def test_errors_in_security_txt_fail_the_run(self):
        code, _, err, _ = self.main(self.repo(security_txt="Contact: https://example.com\n"))
        self.assertEqual(code, 1)
        self.assertIn("Contact must be", err)

    def test_the_token_is_stripped_and_passed_on(self):
        _, _, _, check_md = self.main(self.repo(), environ={"GITHUB_TOKEN": "  abc123\n"})
        self.assertEqual(check_md.call_args.args[1], "abc123")

    def test_no_token_or_a_blank_token_is_passed_as_none(self):
        for environ in ({"GITHUB_TOKEN": ""}, {"GITHUB_TOKEN": "  \n"}):
            with self.subTest(environ=environ):
                _, _, _, check_md = self.main(self.repo(), environ=environ)
                self.assertIsNone(check_md.call_args.args[1])
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            _, _, _, check_md = self.main(self.repo())
            self.assertIsNone(check_md.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
