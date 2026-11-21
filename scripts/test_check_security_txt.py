import unittest
from datetime import datetime, timezone

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
        self.assertOneError(VALID, "SECURITY.md does not name", security_md="no contact here\n")

    def test_contact_url_prefix_in_security_md_is_not_enough(self):
        self.assertOneError(VALID, "SECURITY.md does not name", security_md=f"see {CONTACT}/extra\n")

    def test_contact_in_security_md_inside_backticks(self):
        self.assertEqual(self.errors(VALID, security_md=f"use `{CONTACT}` to report\n"), [])

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
        self.assertOneError(replace("2027-11-20", "٢٠٢٧-11-20"), "RFC 3339")

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

    def test_unicode_line_separator_is_not_a_line_break(self):
        text = replace("Preferred-Languages: en, it", "Preferred-Languages: en, it Hiring: https://x.example")
        self.assertTrue(self.errors(text))

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


if __name__ == "__main__":
    unittest.main()
