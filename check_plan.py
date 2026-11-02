#!/usr/bin/env python3
"""Check a Terraform plan JSON against policy.json. Exit 1 on violations."""
import argparse
import json
import sys

PAB_SETTINGS = [
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
]


def load_json(path, label):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read {label} {path}: {exc}")
        sys.exit(2)


def is_active(change):
    actions = change.get("actions", [])
    return "create" in actions or "update" in actions


def check_tags(rc, policy, violations, unknown):
    change = rc["change"]
    if not is_active(change):
        return
    after = change.get("after") or {}
    after_unknown = change.get("after_unknown") or {}
    if after_unknown.get("tags"):
        unknown.append(f"{rc['address']}: tags value unknown, skipped")
        return
    tags = after.get("tags") or {}
    missing = [t for t in policy["required_tags"] if not tags.get(t)]
    if missing:
        violations.append((rc["address"], "required-tags", f"missing tags: {', '.join(missing)}"))


def check_instance_type(rc, policy, violations, unknown):
    if rc["type"] != "aws_instance":
        return
    change = rc["change"]
    if not is_active(change):
        return
    after = change.get("after") or {}
    after_unknown = change.get("after_unknown") or {}
    if after_unknown.get("instance_type"):
        unknown.append(f"{rc['address']}: instance_type value unknown, skipped")
        return
    instance_type = after.get("instance_type")
    if instance_type not in policy["allowed_instance_types"]:
        violations.append((rc["address"], "instance-type-allowlist", f"{instance_type} not allowed"))


def check_public_access_blocks(changes, violations, unknown):
    buckets = [rc for rc in changes if rc["type"] == "aws_s3_bucket" and is_active(rc["change"])]
    pabs = [rc for rc in changes if rc["type"] == "aws_s3_bucket_public_access_block" and is_active(rc["change"])]

    for bucket_rc in buckets:
        after = bucket_rc["change"].get("after") or {}
        after_unknown = bucket_rc["change"].get("after_unknown") or {}
        if after_unknown.get("bucket"):
            unknown.append(f"{bucket_rc['address']}: bucket value unknown, skipped")
            continue
        bucket_name = after.get("bucket")

        match = None
        for pab in pabs:
            pab_after = pab["change"].get("after") or {}
            if pab_after.get("bucket") == bucket_name:
                match = pab
                break

        if match is None:
            violations.append((bucket_rc["address"], "s3-public-access-block", "no public access block found"))
            continue

        pab_after = match["change"].get("after") or {}
        pab_unknown = match["change"].get("after_unknown") or {}
        if any(pab_unknown.get(s) for s in PAB_SETTINGS):
            unknown.append(f"{match['address']}: public access block settings unknown, skipped")
            continue

        not_blocked = [s for s in PAB_SETTINGS if not pab_after.get(s)]
        if not_blocked:
            violations.append(
                (bucket_rc["address"], "s3-public-access-block", f"not blocked: {', '.join(not_blocked)}")
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("plan")
    parser.add_argument("--policy", default="policy.json")
    args = parser.parse_args()

    plan = load_json(args.plan, "plan")
    policy = load_json(args.policy, "policy")

    if "resource_changes" not in plan:
        print("error: plan is missing resource_changes")
        sys.exit(2)

    changes = plan["resource_changes"]
    violations = []
    unknown = []

    check_public_access_blocks(changes, violations, unknown)
    for rc in changes:
        check_tags(rc, policy, violations, unknown)
        check_instance_type(rc, policy, violations, unknown)

    for message in unknown:
        print(f"unknown: {message}")

    for address, rule, message in violations:
        print(f"violation: {address}: {rule}: {message}")

    print(f"{len(violations)} violation(s) found")
    sys.exit(1 if violations else 0)


if __name__ == "__main__":
    main()
