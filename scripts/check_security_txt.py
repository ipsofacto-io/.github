#!/usr/bin/env python3
"""Check .well-known/security.txt (RFC 9116), and that SECURITY.md shows the same contact.

Run from anywhere: the files are read relative to the repository root.

security.txt is checked offline. It is read as bytes, so no newline translation happens. Every line must be
printable ASCII (space to tilde) and end in LF or CRLF, comments included, because parsers disagree on which
characters end a line, and a comment must not be able to hide a field from one of them.
The weekly workflow fails when Expires is less than 30 days away, so a person renews the file in time.

SECURITY.md is not parsed here. A hand-written Markdown parser disagrees with the renderer, and what readers see is
what the renderer shows. So the file is rendered by GitHub's own Markdown API, in both of its modes, and each
rendering must contain a link to the Contact URL with visible text. That needs api.github.com. GITHUB_TOKEN, when
set, is sent only there, to raise the rate limit. A failed call is retried and then fails the check.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Only the fields this file uses. Encryption, Acknowledgments and Hiring are refused on purpose,
# because nothing backs them and a changed value would send reporters somewhere unintended.
FIELDS = {"canonical", "contact", "expires", "policy", "preferred-languages"}
CONTACT = "https://github.com/ipsofacto-io/ipso/security/advisories/new"
CANONICAL = "https://ipsoplatform.io/.well-known/security.txt"
POLICY = "https://github.com/ipsofacto-io/.github/blob/main/SECURITY.md"
MIN_DAYS = 30
MAX_DAYS = 366

MARKDOWN_API = "https://api.github.com/markdown"
MARKDOWN_MODES = ("gfm", "markdown")
ATTEMPTS = 3
RETRY_DELAYS = (10, 30)  # seconds before the second and the third attempt
RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # a rate limit answers 403 or 429
REQUEST_TIMEOUT = 15

FIELD_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ ]+(\S.*)$")
RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$",
    re.ASCII,
)
LANGUAGE_TAG = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")


def parse_expires(value):
    match = RFC3339.match(value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    zone = match.group(7)
    if second > 60:
        return None
    try:
        if zone in ("Z", "z"):
            tz = timezone.utc
        else:
            offset_hours, offset_minutes = int(zone[1:3]), int(zone[4:6])
            if offset_hours > 23 or offset_minutes > 59:
                return None
            sign = 1 if zone[0] == "+" else -1
            tz = timezone(sign * timedelta(hours=offset_hours, minutes=offset_minutes))
        # RFC 3339 allows a leap second, which datetime cannot hold.
        return datetime(year, month, day, hour, minute, min(second, 59), tzinfo=tz)
    except ValueError:
        return None


def check(text, now):
    """Return a list of problems with the text of security.txt. An empty list means it is valid."""
    errors = []
    values = {}
    segments = text.split("\n")
    for number, raw in enumerate(segments, start=1):
        # A CR is allowed only as the first half of a CRLF line end.
        line = raw[:-1] if raw.endswith("\r") and number < len(segments) else raw
        if any(not " " <= ch <= "~" for ch in line):
            errors.append(f"line {number}: contains a character that is not printable ASCII")
            continue
        if not line.strip() or line.startswith("#"):
            continue
        match = FIELD_LINE.match(line)
        if not match:
            errors.append(f"line {number}: not a field, a comment or a blank line")
            continue
        name = match.group(1).lower()
        if name not in FIELDS:
            errors.append(f"line {number}: field {match.group(1)} is not allowed in this file")
            continue
        values.setdefault(name, []).append(match.group(2).rstrip(" "))

    if text and not text.endswith("\n"):
        errors.append("the last line must end in LF or CRLF")

    if values.get("contact", []) != [CONTACT]:
        errors.append(f"Contact must be exactly one line: {CONTACT}")

    expires = values.get("expires", [])
    if len(expires) != 1:
        errors.append(f"exactly one Expires is required, found {len(expires)}")
    else:
        when = parse_expires(expires[0])
        if when is None:
            errors.append(f"Expires is not an RFC 3339 date-time: {expires[0]}")
        else:
            ahead = when - now
            if ahead < timedelta(days=MIN_DAYS):
                errors.append(f"Expires {expires[0]} is less than {MIN_DAYS} days away: renew the file")
            elif ahead > timedelta(days=MAX_DAYS):
                errors.append(f"Expires {expires[0]} is more than {MAX_DAYS} days away")

    languages = values.get("preferred-languages", [])
    if len(languages) > 1:
        errors.append("at most one Preferred-Languages is allowed")
    for value in languages:
        for tag in (part.strip() for part in value.split(",")):
            if not LANGUAGE_TAG.fullmatch(tag):
                errors.append(f"Preferred-Languages has an invalid tag: {tag!r}")

    if values.get("canonical", []) != [CANONICAL]:
        errors.append(f"Canonical must be exactly one line: {CANONICAL}")
    if values.get("policy", []) != [POLICY]:
        errors.append(f"Policy must be exactly one line: {POLICY}")
    return errors


def read_security_txt(path):
    # latin-1 maps every byte to one character. Nothing is translated, so a lone CR stays a CR,
    # and any byte outside printable ASCII shows up as a character that check() refuses.
    return Path(path).read_bytes().decode("latin-1")


def run(root, now):
    return check(read_security_txt(Path(root) / ".well-known" / "security.txt"), now)


class RenderError(Exception):
    """GitHub's Markdown API did not give a rendering."""


def render(text, mode, token=None, opener=urllib.request.urlopen, sleep=time.sleep):
    """Return the HTML that GitHub's Markdown API renders for text in the given mode."""
    body = json.dumps({"text": text, "mode": mode}).encode("utf-8")
    headers = {
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "security-txt-check",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    problem = "no attempt was made"
    for attempt in range(ATTEMPTS):
        if attempt:
            sleep(RETRY_DELAYS[attempt - 1])
        request = urllib.request.Request(MARKDOWN_API, data=body, headers=headers, method="POST")
        try:
            with opener(request, timeout=REQUEST_TIMEOUT) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            problem = f"HTTP {error.code}"
            if error.code not in RETRY_STATUS:
                break
        except (OSError, ValueError) as error:  # a network error, a timeout, or a body that is not UTF-8
            problem = f"{type(error).__name__}: {str(error)[:200]}"
    raise RenderError(f"GitHub's Markdown API failed in mode {mode} after {attempt + 1} attempt(s): {problem}")


class _Anchors(HTMLParser):
    """Collect the href and the text of every anchor in the rendered HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors = []
        self._open = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._open = [dict(attrs).get("href"), []]

    def handle_data(self, data):
        if self._open is not None:
            self._open[1].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._open is not None:
            self.anchors.append((self._open[0], "".join(self._open[1])))
            self._open = None


def check_rendered(html, mode):
    """Return a list of problems with GitHub's rendering of SECURITY.md in one mode."""
    parser = _Anchors()
    parser.feed(html)
    parser.close()
    # Visible text has a letter or a digit. A zero-width space, a no-break space, an empty element or an image
    # alone does not. GitHub's sanitizer removes hidden, style and class, so they cannot hide a link.
    if any(href == CONTACT and any(ch.isalnum() for ch in text) for href, text in parser.anchors):
        return []
    return [f"SECURITY.md rendered by GitHub ({mode}) has no link with visible text to the Contact URL: {CONTACT}"]


def check_security_md(security_md, token=None, renderer=render):
    """Return a list of problems with how GitHub renders SECURITY.md. Every mode must show the link."""
    errors = []
    for mode in MARKDOWN_MODES:
        try:
            errors += check_rendered(renderer(security_md, mode, token), mode)
        except RenderError as error:
            errors.append(str(error))
    return errors


def main():
    errors = run(ROOT, datetime.now(timezone.utc))
    errors += check_security_md((ROOT / "SECURITY.md").read_text(encoding="utf-8"), os.environ.get("GITHUB_TOKEN"))
    for error in errors:
        print(f"security.txt: {error}", file=sys.stderr)
    if errors:
        return 1
    print("security.txt: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
