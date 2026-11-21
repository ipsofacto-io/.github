import unittest
from datetime import datetime, timezone

import check_security_txt as cst

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
CONTACT = "https://github.com/ipsofacto-io/ipso/security/advisories/new"
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
    def errors(self, text):
        return cst.check(text, SECURITY_MD, NOW)

    def assertOneError(self, text, fragment):
        errors = self.errors(text)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(fragment, errors[0])

    def test_valid_file(self):
        self.assertEqual(self.errors(VALID), [])

    def test_missing_contact(self):
        text = VALID.replace(f"Contact: {CONTACT}\n", "")
        self.assertOneError(text, "at least one Contact")

    def test_contact_not_in_security_md(self):
        self.assertEqual(
            len(cst.check(VALID, "no contact here\n", NOW)), 1
        )

    def test_missing_expires(self):
        self.assertOneError(replace("Expires: 2027-11-20T23:00:00Z\n", ""), "exactly one Expires")

    def test_duplicate_expires(self):
        text = VALID + "Expires: 2027-11-19T23:00:00Z\n"
        self.assertOneError(text, "exactly one Expires")

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

    def test_unknown_field(self):
        self.assertOneError(VALID + "Bounty: https://example.com\n", "unknown field Bounty")

    def test_malformed_line(self):
        self.assertOneError(VALID + "this is not a field\n", "not a field")

    def test_signed_file_is_refused(self):
        self.assertTrue(self.errors("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" + VALID))

    def test_http_uri(self):
        text = replace(f"Policy: {cst.POLICY}", "Policy: http://github.com/ipsofacto-io/.github/blob/main/SECURITY.md")
        errors = self.errors(text)
        self.assertTrue(any("https URI" in error for error in errors), errors)

    def test_mailto_contact(self):
        errors = self.errors(VALID + "Contact: mailto:security@ipsoplatform.io\n")
        self.assertTrue(any("https URI" in error for error in errors), errors)

    def test_wrong_canonical(self):
        text = replace(cst.CANONICAL, "https://example.com/.well-known/security.txt")
        self.assertOneError(text, "Canonical must be")

    def test_missing_canonical(self):
        text = replace(f"Canonical: {cst.CANONICAL}\n", "")
        self.assertOneError(text, "Canonical must be")

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
