package terraform.cloudtrail

import rego.v1

# 1 Must be multi-region
violations contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after
	not rc.change.after.is_multi_region_trail
	msg := sprintf("CloudTrail %q must be multi-region (is_multi_region_trail = true).", [rc.change.after.name])
}

# 2 Must use KMS (kms_key_id) — allow "unknown at plan time"

violations contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after
	not rc.change.after.kms_key_id
	not rc.change.after_unknown.kms_key_id
	msg := sprintf("CloudTrail %q must use KMS (kms_key_id).", [rc.change.after.name])
}

# 3 Must enable log file validation
violations contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after
	not rc.change.after.enable_log_file_validation
	msg := sprintf("CloudTrail %q must enable log file validation.", [rc.change.after.name])
}

# 4 Must include global service events

violations contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after
	not rc.change.after.include_global_service_events
	msg := sprintf("CloudTrail %q must include global service events.", [rc.change.after.name])
}

# 5 Must deliver to an S3 bucket (allow "unknown at plan time")

violations contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after
	not rc.change.after.s3_bucket_name # <-- no parentheses
	not rc.change.after_unknown.s3_bucket_name
	msg := sprintf("CloudTrail %q must deliver to an S3 bucket (s3_bucket_name).", [rc.change.after.name])
}

violations contains msg if {
	rc := input.resource_changes[_]
	rc.type == "aws_cloudtrail"
	rc.change.after
	rc.change.after.s3_bucket_name == "" # handle empty-string plans
	not rc.change.after_unknown.s3_bucket_name
	msg := sprintf("CloudTrail %q must deliver to an S3 bucket (s3_bucket_name).", [rc.change.after.name])
}

messages := [m | violations[m]]

result := {
	"passed": count(messages) == 0,
	"messages": messages
}
