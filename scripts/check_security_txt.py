#!/usr/bin/env python3
"""Check .well-known/security.txt (RFC 9116) against SECURITY.md.

Run from anywhere: the files are read relative to the repository root.
The file is read as bytes, so no newline translation happens. Every line must be printable ASCII
(space to tilde) and end in LF or CRLF, comments included, because parsers disagree on which
characters end a line, and a comment must not be able to hide a field from one of them.
SECURITY.md must contain a Markdown link, with visible text, to the Contact URL. link_targets()
follows the CommonMark rules for code blocks, code spans and HTML. It fails closed: a form it does
not understand, such as a reference-style link or a bare URL, does not count as a link.
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

FIELD_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ ]+(\S.*?)[ ]*$")
RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-]\d{2}:\d{2})$",
    re.ASCII,
)
LANGUAGE_TAG = re.compile(r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
# Markdown. A container prefix is any blockquote markers and one list marker.
QUOTE = re.compile(r"[ ]{0,3}>[ ]?")
LIST_MARKER = re.compile(r"[ ]*(?:[-*+]|\d{1,9}[.)])[ ]")
FENCE_OPEN = re.compile(r"^[ ]*(`{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^[ ]{0,3}#{1,6}(?:[ ]|$)")
SETEXT_UNDERLINE = re.compile(r"^[ ]{0,3}(?:=+|-+)[ ]*$")
THEMATIC_BREAK = re.compile(r"^[ ]{0,3}([-*_])(?:[ ]*\1){2,}[ ]*$")
HTML_RAW = re.compile(r"^[ ]{0,3}<(script|pre|style|textarea)(?:[ \t>]|$)", re.I)
HTML_SPECIAL = re.compile(r"^[ ]{0,3}(<\?|<!\[CDATA\[|<![A-Za-z])")
HTML_SPECIAL_END = {"<?": "?>", "<![CDATA[": "]]>"}
HTML_BLOCK_TAG = re.compile(
    r"^[ ]{0,3}</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details"
    r"|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html"
    r"|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary"
    r"|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:[ \t/>]|$)",
    re.I,
)
# A complete open or closing tag alone on its line.
HTML_LONE_TAG = re.compile(
    r"^[ ]{0,3}(?:<[A-Za-z][A-Za-z0-9-]*(?:[ \t]+[A-Za-z_:][A-Za-z0-9_.:-]*"
    r"(?:[ \t]*=[ \t]*(?:[^ \t\"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*[ \t]*/?>|</[A-Za-z][A-Za-z0-9-]*[ \t]*>)[ \t]*$"
)
# A link needs text with something visible in it. Images and escaped brackets are not links.
LINK = re.compile(r"(?<![!\\])\[([^\[\]]*)\]\((https://[^\s)]+)(?:[ ]+\"[^\"]*\")?\)")


def _strip_inline(text):
    """Remove what does not render as link text: code spans and HTML comments."""
    out = []
    i = 0
    size = len(text)
    while i < size:
        ch = text[i]
        if ch == "\\" and i + 1 < size:
            out.append(text[i : i + 2])
            i += 2
        elif ch == "`":
            j = i
            while j < size and text[j] == "`":
                j += 1
            run = j - i
            close = None
            k = j
            while k < size:
                s = text.find("`", k)
                if s == -1:
                    break
                e = s
                while e < size and text[e] == "`":
                    e += 1
                if e - s == run:
                    close = e
                    break
                k = e
            if close is None:
                out.append(text[i:j])
                i = j
            else:
                out.append("X")  # the span renders as code, which is still link text
                i = close
        elif text.startswith("<!--", i) and text.find("-->", i + 4) != -1:
            i = text.find("-->", i + 4) + 3
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _split_quotes(line, limit=None):
    """Return (blockquote markers at the start of the line, how many, the rest).

    This is a loop, not a repeated regex group: the group would be ambiguous about which iteration owns a space,
    and a line of nested markers would then backtrack exponentially.
    """
    pos = depth = 0
    while limit is None or depth < limit:
        match = QUOTE.match(line, pos)
        if not match:
            break
        pos, depth = match.end(), depth + 1
    return line[:pos], depth, line[pos:]


def _html_block_end(body):
    """Return what ends the HTML block that starts on this line, or None if none starts here.

    "" means the next blank line. A lone tag always starts a block here, even after a paragraph:
    CommonMark lets it start one when the paragraph belongs to a deeper container, so this is the safe side.
    """
    raw = HTML_RAW.match(body)
    if raw:
        return "</%s>" % raw.group(1).lower()
    special = HTML_SPECIAL.match(body)
    if special:
        return HTML_SPECIAL_END.get(special.group(1), ">")
    if body.lstrip(" ").startswith("<!--") and len(body) - len(body.lstrip(" ")) < 4:
        return "-->"
    if HTML_BLOCK_TAG.match(body) or HTML_LONE_TAG.match(body):
        return ""
    return None


def _paragraphs(markdown):
    """Return the blocks of lines whose Markdown renders: not code, not an HTML block.

    An HTML comment or a raw-text block that its blockquote or list item cuts off before its end marker is left
    unterminated in the rendered page, which then swallows what follows. That case drops the rest of the document.
    """
    blocks = []
    block = []

    def flush():
        nonlocal block
        if block:
            blocks.append("\n".join(block))
            block = []

    fence = None  # (character, length, quote depth, list indent) while inside a fenced code block
    html = None  # (end marker, quote depth, list indent) while inside an HTML block
    previous = "blank"  # blank, text, heading or code
    for raw in markdown.split("\n"):
        line = raw[:-1] if raw.endswith("\r") else raw
        _, depth, rest = _split_quotes(line)
        after = rest.replace("\t", "    ")
        indent = len(after) - len(after.lstrip(" "))
        marker = LIST_MARKER.match(rest)
        body = rest[marker.end() :] if marker else rest
        blank = not body.strip()
        list_indent = len(after) - len(body.replace("\t", "    ")) if marker else 0
        if fence:
            if not blank and (depth < fence[2] or indent < fence[3]):
                fence = None  # the blockquote or the list item that held the fence ended
            else:
                closing = re.escape(fence[0]) + "{%d,}[ ]*$" % fence[1]
                if depth == fence[2] and 0 <= indent - fence[3] <= 3 and re.match(closing, after.lstrip(" ")):
                    fence = None
                continue
        if html:
            # Quote markers deeper than the block's own are raw content, so they do not make a line blank.
            inside = _split_quotes(line, html[1])[2]
            inside_blank = not inside.strip()
            if not inside_blank and (depth < html[1] or indent < html[2]):
                if html[0] and html[0] != "</pre>":
                    break  # cut off before its end marker: the rest of the page is swallowed
                html = None
            elif html[0] == "" and inside_blank:
                html = None
            elif html[0] and html[0] in line.lower():
                html = None
                continue
            else:
                continue
        if blank:
            flush()
            previous = "blank"
            continue
        if previous != "text" and (indent >= 4 or body.startswith("    ") or body.startswith("\t")):
            previous = "code"
            continue
        opener = FENCE_OPEN.match(body)
        if opener and not (opener.group(1)[0] == "`" and "`" in opener.group(2)):
            flush()
            fence = (opener.group(1)[0], len(opener.group(1)), depth, list_indent)
            previous = "code"
            continue
        end_tag = _html_block_end(body)
        if end_tag is not None:
            flush()
            start = body.lower().index("<!--") + 4 if end_tag == "-->" else 0
            if not (end_tag and end_tag in body.lower()[start:]):
                html = (end_tag, depth, list_indent)
            previous = "code"
            continue
        if previous == "text" and SETEXT_UNDERLINE.match(body):
            flush()
            previous = "heading"
            continue
        if THEMATIC_BREAK.match(body):
            flush()
            previous = "heading"
            continue
        if marker or HEADING.match(body):
            flush()
        block.append(body)
        previous = "heading" if HEADING.match(body) else "text"
        if previous == "heading":
            flush()
    flush()
    return blocks


def link_targets(markdown):
    """Return the URLs of the Markdown links that render with visible text."""
    targets = set()
    for paragraph in _paragraphs(markdown):
        targets.update(url for text, url in LINK.findall(_strip_inline(paragraph)) if text.strip())
    return targets


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
        values.setdefault(name, []).append(match.group(2))

    if text and not text.endswith("\n"):
        errors.append("the last line must end in LF or CRLF")
    if values.get("contact", []) != [CONTACT]:
        errors.append(f"Contact must be exactly one line: {CONTACT}")
    elif CONTACT not in link_targets(security_md):
        errors.append(f"SECURITY.md does not link to the Contact URL: {CONTACT}")

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
    text = read_security_txt(Path(root) / ".well-known" / "security.txt")
    security_md = (Path(root) / "SECURITY.md").read_text(encoding="utf-8")
    return check(text, security_md, now)


def main():
    errors = run(ROOT, datetime.now(timezone.utc))
    for error in errors:
        print(f"security.txt: {error}", file=sys.stderr)
    if errors:
        return 1
    print("security.txt: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
