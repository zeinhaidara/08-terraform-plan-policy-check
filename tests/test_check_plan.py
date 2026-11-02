import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import check_plan

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")
POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "policy.json")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


class CheckPlanTests(unittest.TestCase):
    def setUp(self):
        self.policy = check_plan.load_json(POLICY_PATH, "policy")

    def run_checks(self, plan):
        violations = []
        unknown = []
        changes = plan["resource_changes"]
        check_plan.check_public_access_blocks(changes, violations, unknown)
        for rc in changes:
            check_plan.check_tags(rc, self.policy, violations, unknown)
            check_plan.check_instance_type(rc, self.policy, violations, unknown)
        return violations, unknown

    def test_clean_plan_passes(self):
        violations, _ = self.run_checks(load_fixture("pass.json"))
        self.assertEqual(violations, [])

    def test_bucket_without_public_access_block_fails(self):
        violations, _ = self.run_checks(load_fixture("fail.json"))
        rules = [v[1] for v in violations]
        self.assertIn("s3-public-access-block", rules)

    def test_missing_required_tag_fails(self):
        violations, _ = self.run_checks(load_fixture("fail.json"))
        rules = [v[1] for v in violations]
        self.assertIn("required-tags", rules)

    def test_disallowed_instance_type_fails(self):
        violations, _ = self.run_checks(load_fixture("fail.json"))
        rules = [v[1] for v in violations]
        self.assertIn("instance-type-allowlist", rules)

    def test_unknown_value_is_reported_not_counted(self):
        violations, unknown = self.run_checks(load_fixture("unknown.json"))
        self.assertEqual(violations, [])
        self.assertEqual(len(unknown), 1)
        self.assertIn("instance_type", unknown[0])

    def test_unknown_bucket_name_is_reported(self):
        violations, unknown = self.run_checks(load_fixture("unknown_bucket.json"))
        self.assertEqual(violations, [])
        self.assertEqual(len(unknown), 1)
        self.assertIn("bucket", unknown[0])


if __name__ == "__main__":
    unittest.main()
