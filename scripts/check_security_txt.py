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
FIELDS = {
    "acknowledgments",
    "canonical",
    "contact",
    "encryption",
    "expires",
    "hiring",
    "policy",
    "preferred-languages",
}
URI_FIELDS = {"acknowledgments", "canonical", "contact", "encryption", "hiring", "policy"}
CANONICAL = "https://ipsoplatform.io/.well-known/security.txt"
POLICY = "https://github.com/ipsofacto-io/.github/blob/main/SECURITY.md"
MIN_DAYS = 30
MAX_DAYS = 366

FIELD_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]+(\S.*?)[ \t]*$")
RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
LANGUAGE_TAG = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")


def parse_expires(value):
    match = RFC3339.match(value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    zone = match.group(7)
    if zone == "Z":
        tz = timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except ValueError:
        return None


def check(text, security_md, now):
    """Return a list of problems. An empty list means the file is valid."""
    errors = []
    values = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        match = FIELD_LINE.match(line)
        if not match:
            errors.append(f"line {number}: not a field, a comment or a blank line")
            continue
        name = match.group(1).lower()
        if name not in FIELDS:
            errors.append(f"line {number}: unknown field {match.group(1)}")
            continue
        values.setdefault(name, []).append(match.group(2))

    for name in sorted(URI_FIELDS):
        for value in values.get(name, []):
            if not value.startswith("https://"):
                errors.append(f"{name} must be an https URI: {value}")

    contacts = values.get("contact", [])
    if not contacts:
        errors.append("at least one Contact is required")
    for contact in contacts:
        if contact not in security_md:
            errors.append(f"Contact is not named in SECURITY.md: {contact}")

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
            if not LANGUAGE_TAG.match(tag):
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
