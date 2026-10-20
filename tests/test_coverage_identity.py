import unittest

from tools.coverage_identity import CoverageIdentityError, coverage_id


class CoverageIdentityTests(unittest.TestCase):
    def test_builds_stable_id_from_canonical_dimensions(self):
        self.assertEqual(
            "src%2Fapi::authz%23owner::packages%2Fapi::Access%20control",
            coverage_id(
                surface="src/api",
                boundary="authz#owner",
                subsystem="packages/api",
                attack_class="Access control",
            ),
        )

    def test_normalizes_unicode_before_encoding(self):
        composed = coverage_id(
            surface="café",
            boundary="tenant",
            subsystem="api",
            attack_class="auth",
        )
        decomposed = coverage_id(
            surface="cafe\u0301",
            boundary="tenant",
            subsystem="api",
            attack_class="auth",
        )
        self.assertEqual(composed, decomposed)

    def test_lifecycle_is_an_explicit_dimension(self):
        self.assertEqual(
            "route::authz::api::replay::rollback",
            coverage_id(
                surface="route",
                boundary="authz",
                subsystem="api",
                attack_class="replay",
                lifecycle="rollback",
            ),
        )

    def test_rejects_empty_whitespace_and_control_references(self):
        for invalid in ("", " leading", "trailing ", "line\nfeed", "zero\u200bwidth"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(CoverageIdentityError):
                    coverage_id(
                        surface=invalid,
                        boundary="authz",
                        subsystem="api",
                        attack_class="auth",
                    )


if __name__ == "__main__":
    unittest.main()
