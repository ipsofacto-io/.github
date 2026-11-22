import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import check_security_txt as cst

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
CONTACT = cst.CONTACT
SECURITY_MD = f"Report it in [ipso]({CONTACT}).\n"
VALID = "\n".join(
    [
        "# comment",
        f"Contact: {CONTACT}",
        "Expires: 2027-11-20T23:00:00Z",
        "Preferred-Languages: en, it",
        f"Canonical: {cst.CANONICAL}",
        f"Policy: {cst.POLICY}",
        "",
    ]
)

# Built with chr() so this file stays plain ASCII.
LINE_SEPARATORS = [chr(code) for code in (0x2028, 0x2029, 0x85, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E)]
ARABIC_INDIC_2027 = "".join(chr(code) for code in (0x662, 0x660, 0x662, 0x667))
NO_BREAK_SPACE = chr(0xA0)
BYTE_ORDER_MARK = chr(0xFEFF)


def replace(old, new):
    assert old in VALID
    return VALID.replace(old, new)


class CheckSecurityTxt(unittest.TestCase):
    def errors(self, text, security_md=SECURITY_MD):
        return cst.check(text, security_md, NOW)

    def assertOneError(self, text, fragment, security_md=SECURITY_MD):
        errors = self.errors(text, security_md)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(fragment, errors[0])

    def test_valid_file(self):
        self.assertEqual(self.errors(VALID), [])

    def test_crlf_file_is_valid(self):
        self.assertEqual(self.errors(VALID.replace("\n", "\r\n")), [])

    def test_missing_contact(self):
        self.assertOneError(replace(f"Contact: {CONTACT}\n", ""), "Contact must be")

    def test_contact_is_pinned(self):
        text = replace(CONTACT, "https://github.com/ipsofacto-io/ipso-server/security/advisories/new")
        self.assertOneError(text, "Contact must be")

    def test_second_contact(self):
        self.assertOneError(VALID + "Contact: mailto:security@ipsoplatform.io\n", "Contact must be")

    def test_contact_not_in_security_md(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md="no contact here\n")

    def test_contact_url_prefix_in_security_md_is_not_enough(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"see [x]({CONTACT}/extra)\n")

    def test_contact_only_in_backticks_is_not_a_link(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"use `{CONTACT}` to report\n")

    def test_contact_as_bare_text_is_not_a_link(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"report at {CONTACT}\n")

    def test_contact_as_link_text_with_another_target(self):
        self.assertOneError(
            VALID, "SECURITY.md does not link to", security_md=f"[{CONTACT}](https://attacker.example/report)\n"
        )

    def test_contact_link_inside_html_comment_does_not_count(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"<!-- [x]({CONTACT}) -->\n")

    def test_contact_link_inside_unclosed_html_comment_does_not_count(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"<!-- [x]({CONTACT})\n")

    def test_contact_link_inside_code_span_does_not_count(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"`[x]({CONTACT})`\n")

    def test_contact_link_inside_double_backtick_span_does_not_count(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"``[x]({CONTACT})``\n")

    def test_contact_link_inside_fenced_block_does_not_count(self):
        for fence in ("```", "~~~"):
            with self.subTest(fence=fence):
                md = f"{fence}sh\n[x]({CONTACT})\n{fence}\n"
                self.assertOneError(VALID, "SECURITY.md does not link to", security_md=md)

    def test_contact_link_inside_unclosed_fence_does_not_count(self):
        self.assertOneError(VALID, "SECURITY.md does not link to", security_md=f"```\n[x]({CONTACT})\n")

    def test_link_after_a_code_block_still_counts(self):
        md = f"```sh\necho hi\n```\n\nReport in [ipso]({CONTACT}).\n"
        self.assertEqual(self.errors(VALID, security_md=md), [])

    def test_link_after_a_comment_still_counts(self):
        md = f"<!-- note -->\nReport in [ipso]({CONTACT}).\n"
        self.assertEqual(self.errors(VALID, security_md=md), [])

    def test_link_between_two_code_spans_still_counts(self):
        md = f"`a` then [ipso]({CONTACT}) then `b`\n"
        self.assertEqual(self.errors(VALID, security_md=md), [])

    def test_missing_expires(self):
        self.assertOneError(replace("Expires: 2027-11-20T23:00:00Z\n", ""), "exactly one Expires")

    def test_duplicate_expires(self):
        self.assertOneError(VALID + "Expires: 2027-11-19T23:00:00Z\n", "exactly one Expires")

    def test_expires_in_less_than_30_days(self):
        self.assertOneError(replace("2027-11-20", "2026-12-20"), "less than 30 days")

    def test_expires_already_past(self):
        self.assertOneError(replace("2027-11-20", "2026-11-01"), "less than 30 days")

    def test_expires_30_days_ahead_is_accepted(self):
        self.assertEqual(self.errors(replace("2027-11-20T23:00:00Z", "2026-12-21T12:00:00Z")), [])

    def test_expires_more_than_366_days_ahead(self):
        self.assertOneError(replace("2027-11-20", "2027-11-23"), "more than 366 days")

    def test_expires_not_rfc3339(self):
        self.assertOneError(replace("2027-11-20T23:00:00Z", "20 November 2027"), "RFC 3339")

    def test_expires_impossible_date(self):
        self.assertOneError(replace("2027-11-20", "2027-02-30"), "RFC 3339")

    def test_expires_with_offset(self):
        self.assertEqual(self.errors(replace("2027-11-20T23:00:00Z", "2027-11-20T23:00:00+01:00")), [])

    def test_expires_offset_out_of_range_does_not_crash(self):
        for offset in ("+25:00", "+24:00", "+00:99", "-23:60"):
            with self.subTest(offset=offset):
                self.assertOneError(replace("2027-11-20T23:00:00Z", f"2027-11-20T23:00:00{offset}"), "RFC 3339")

    def test_expires_lowercase_t_and_z(self):
        self.assertEqual(self.errors(replace("2027-11-20T23:00:00Z", "2027-11-20t23:00:00z")), [])

    def test_expires_leap_second(self):
        self.assertEqual(self.errors(replace("2027-11-20T23:00:00Z", "2027-11-20T23:59:60Z")), [])

    def test_expires_second_61(self):
        self.assertOneError(replace("2027-11-20T23:00:00Z", "2027-11-20T23:59:61Z"), "RFC 3339")

    def test_expires_non_ascii_digits(self):
        errors = self.errors(replace("2027-11-20", ARABIC_INDIC_2027 + "-11-20"))
        self.assertTrue(any("printable ASCII" in error for error in errors), errors)

    def test_unknown_field(self):
        self.assertOneError(VALID + "Bounty: https://example.com\n", "Bounty is not allowed")

    def test_unused_rfc_fields_are_refused(self):
        for field in ("Encryption", "Acknowledgments", "Hiring"):
            with self.subTest(field=field):
                self.assertOneError(VALID + f"{field}: https://attacker.example/x\n", f"{field} is not allowed")

    def test_malformed_line(self):
        self.assertOneError(VALID + "this is not a field\n", "not a field")

    def test_signed_file_is_refused(self):
        self.assertTrue(self.errors("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + VALID))

    def test_line_separator_characters_are_refused_in_a_field(self):
        for separator in LINE_SEPARATORS:
            with self.subTest(separator=hex(ord(separator))):
                text = replace("Preferred-Languages: en, it", f"Preferred-Languages: en, it{separator}Hiring: https://x.example")
                self.assertOneError(text, "printable ASCII")

    def test_line_separator_characters_cannot_hide_a_field_in_a_comment(self):
        for separator in LINE_SEPARATORS:
            with self.subTest(separator=hex(ord(separator))):
                text = replace("# comment", f"# comment{separator}Encryption: https://attacker.example/key.asc")
                self.assertOneError(text, "printable ASCII")

    def test_non_ascii_blank_line_is_refused(self):
        self.assertOneError(VALID + NO_BREAK_SPACE + "\n", "printable ASCII")

    def test_byte_order_mark_is_refused(self):
        self.assertOneError(BYTE_ORDER_MARK + VALID, "printable ASCII")

    def test_bare_carriage_return_inside_a_line_is_refused(self):
        self.assertOneError(replace("# comment", "# com\rment"), "printable ASCII")

    def test_tab_is_refused(self):
        self.assertOneError(replace("en, it", "en,\tit"), "printable ASCII")

    def test_two_carriage_returns_at_a_line_end_are_refused(self):
        self.assertOneError(replace("# comment", "# comment\r\r"), "printable ASCII")

    def test_carriage_return_at_the_end_of_the_file_is_refused(self):
        errors = self.errors(VALID + "# end\r")
        self.assertTrue(any("printable ASCII" in error for error in errors), errors)
        self.assertTrue(any("last line must end" in error for error in errors), errors)

    def test_last_line_must_end_in_lf(self):
        self.assertOneError(VALID.rstrip("\n"), "last line must end")

    def test_last_line_must_end_in_crlf_or_lf(self):
        self.assertOneError(VALID.replace("\n", "\r\n").rstrip("\r\n"), "last line must end")

    def test_empty_file_reports_the_missing_fields_not_a_line_end(self):
        errors = self.errors("")
        self.assertTrue(errors)
        self.assertFalse(any("last line must end" in error for error in errors), errors)

    def test_http_canonical(self):
        text = replace(cst.CANONICAL, "http://ipsoplatform.io/.well-known/security.txt")
        self.assertOneError(text, "Canonical must be")

    def test_wrong_canonical(self):
        text = replace(cst.CANONICAL, "https://example.com/.well-known/security.txt")
        self.assertOneError(text, "Canonical must be")

    def test_missing_canonical(self):
        self.assertOneError(replace(f"Canonical: {cst.CANONICAL}\n", ""), "Canonical must be")

    def test_wrong_policy(self):
        text = replace(cst.POLICY, "https://github.com/ipsofacto-io/ipso/blob/main/SECURITY.md")
        self.assertOneError(text, "Policy must be")

    def test_duplicate_preferred_languages(self):
        self.assertOneError(VALID + "Preferred-Languages: fr\n", "at most one Preferred-Languages")

    def test_invalid_language_tag(self):
        self.assertOneError(replace("en, it", "en, not a tag"), "invalid tag")

    def test_field_names_are_case_insensitive(self):
        self.assertEqual(self.errors(replace("Contact:", "contact:")), [])


class RunThroughFiles(unittest.TestCase):
    """Go through run(), which reads the file as bytes, as main() does."""

    def run_with(self, content, security_md=SECURITY_MD):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".well-known").mkdir()
            (root / ".well-known" / "security.txt").write_bytes(content)
            (root / "SECURITY.md").write_text(security_md, encoding="utf-8")
            return cst.run(root, NOW)

    def assertRefused(self, content):
        errors = self.run_with(content)
        self.assertTrue(any("printable ASCII" in error for error in errors), errors)

    def test_valid_file(self):
        self.assertEqual(self.run_with(VALID.encode("ascii")), [])

    def test_file_without_a_final_line_end_is_refused(self):
        errors = self.run_with(VALID.rstrip("\n").encode("ascii"))
        self.assertTrue(any("last line must end" in error for error in errors), errors)

    def test_crlf_file_is_valid(self):
        self.assertEqual(self.run_with(VALID.replace("\n", "\r\n").encode("ascii")), [])

    def test_lone_cr_line_endings_are_refused(self):
        self.assertRefused(VALID.replace("\n", "\r").encode("ascii"))

    def test_lone_cr_hiding_a_field_after_a_comment_is_refused(self):
        self.assertRefused(replace("# comment", "# comment\rEncryption: https://attacker.example/key.asc").encode("ascii"))

    def test_byte_order_mark_bytes_are_refused(self):
        self.assertRefused(bytes([0xEF, 0xBB, 0xBF]) + VALID.encode("ascii"))

    def test_utf8_bytes_are_refused(self):
        self.assertRefused(replace("# comment", "# caf").encode("ascii") + chr(0xE9).encode("utf-8"))

    def test_line_separator_bytes_are_refused(self):
        self.assertRefused(replace("# comment", "# comment" + chr(0x2028)).encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
