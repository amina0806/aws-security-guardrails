package terraform.cloudtrail_test

import data.terraform.cloudtrail as ct
import rego.v1

# Build a minimal tfplan shape containing one aws_cloudtrail "after" object
trail(after) := {"resource_changes": [{
	"type": "aws_cloudtrail",
	"change": {"after": after},
}]}

# Empty plan (no CloudTrail at all)
empty_plan := {"resource_changes": []}

# --- PASS CASES ---

test_passes_when_multi_region_kms_and_recommendeds if {
	mock := trail({
		"name": "org-trail",
		"is_multi_region_trail": true,
		"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
		"enable_log_file_validation": true,
		"include_global_service_events": true,
		"s3_bucket_name": "central-logs",
	})

	res := ct.result with input as mock
	res.passed
	count(res.messages) == 0
}

# With our minimal policy, no CloudTrail resources => no violations => pass
test_passes_when_no_cloudtrail_defined if {
	res := ct.result with input as empty_plan
	res.passed
	count(res.messages) == 0
}

# --- VIOLATION: NOT MULTI-REGION ---

test_violates_when_not_multi_region if {
	mock := trail({
		"name": "bad-trail",
		"is_multi_region_trail": false,
		"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
		"enable_log_file_validation": true,
		"include_global_service_events": true,
		"s3_bucket_name": "central-logs",
	})

	msgs := ct.messages with input as mock
	some i
	contains(msgs[i], "must be multi-region")
}

# --- VIOLATION: NO KMS KEY ---

test_violates_when_kms_missing if {
	mock := trail({
		"name": "plain-trail",
		"is_multi_region_trail": true,
		"enable_log_file_validation": true,
		"include_global_service_events": true,
		"s3_bucket_name": "central-logs",
	})

	msgs := ct.messages with input as mock
	some i
	contains(msgs[i], "must use KMS")
}

# --- VIOLATION: LOG FILE VALIDATION DISABLED ---

test_violates_when_log_file_validation_disabled if {
	mock := trail({
		"name": "no-lfv",
		"is_multi_region_trail": true,
		"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
		"enable_log_file_validation": false,
		"include_global_service_events": true,
		"s3_bucket_name": "central-logs",
	})

	msgs := ct.messages with input as mock
	some i
	contains(msgs[i], "log file validation")
}

# --- VIOLATION: GLOBAL SERVICE EVENTS DISABLED ---

test_violates_when_global_service_events_disabled if {
	mock := trail({
		"name": "no-global-events",
		"is_multi_region_trail": true,
		"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
		"enable_log_file_validation": true,
		"include_global_service_events": false,
		"s3_bucket_name": "central-logs",
	})

	msgs := ct.messages with input as mock
	some i
	contains(msgs[i], "include global service events")
}

# --- VIOLATION: MISSING S3 BUCKET NAME ---

test_violates_when_no_s3_bucket_configured if {
	mock := trail({
		"name": "no-bucket",
		"is_multi_region_trail": true,
		"kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
		"enable_log_file_validation": true,
		"include_global_service_events": true,
	})

	msgs := ct.messages with input as mock
	some i
	contains(msgs[i], "deliver to an S3 bucket")
}
