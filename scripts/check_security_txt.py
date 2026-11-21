#!/usr/bin/env python3
"""Check .well-known/security.txt (RFC 9116) against SECURITY.md.

Run from anywhere: the files are read relative to the repository root.
The weekly workflow fails when Expires is less than 30 days away, so a person renews the file in time.
"""
import re
import sys
from datetime import datetime, timedelta, timezone
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

FIELD_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]+(\S.*?)[ \t]*$")
RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$",
    re.ASCII,
)
LANGUAGE_TAG = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
URL = re.compile(r"https://[^\s)\]>\"'`<]+")


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


def check(text, security_md, now):
    """Return a list of problems. An empty list means the file is valid."""
    errors = []
    values = {}
    # RFC 9116 ends a line at LF or CRLF only. str.splitlines() also splits on other characters.
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
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
        values.setdefault(name, []).append(match.group(2))

    if values.get("contact", []) != [CONTACT]:
        errors.append(f"Contact must be exactly one line: {CONTACT}")
    elif CONTACT not in set(URL.findall(security_md)):
        errors.append(f"SECURITY.md does not name the Contact URL: {CONTACT}")

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


def main():
    text = (ROOT / ".well-known" / "security.txt").read_text(encoding="utf-8")
    security_md = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    errors = check(text, security_md, datetime.now(timezone.utc))
    for error in errors:
        print(f"security.txt: {error}", file=sys.stderr)
    if errors:
        return 1
    print("security.txt: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
