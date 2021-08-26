package terraform_block_public_acls_s3

test_has_block_public_acl {
	count(violation) == 0 with input as {"resource": {
		"aws_s3_bucket": {"example": {"bucket": "example"}},
		"aws_s3_bucket_public_access_block": {"example": {
			"block_public_acls": true,
			"bucket": "${aws_s3_bucket.example.id}",
		}},
	}}
}

test_missing_block_public_acl {
	count(violation) == 1 with input as {"resource": {
		"aws_s3_bucket": {"example1": {"bucket": "example1"}},
		"aws_s3_bucket_public_access_block": {"example": {"bucket": "${aws_s3_bucket.example1.id}"}},
	}}
}

test_has_block_public_acl_set_to_false {
	count(violation) == 1 with input as {"resource": {
		"aws_s3_bucket": {"example2": {"bucket": "example2"}},
		"aws_s3_bucket_public_access_block": {"example": {
			"block_public_acls": false,
			"bucket": "${aws_s3_bucket.example2.id}",
		}},
	}}
}

test_has_block_public_acl_set_to_true_in_one_but_is_incorrect_in_second_bucket {
	count(violation) == 1 with input as {"resource": {
		"aws_s3_bucket": {
			"example": {"bucket": "example"},
			"other_bucket": {"bucket": "other_example"},
		},
		"aws_s3_bucket_public_access_block": {
			"example": {
				"block_public_acls": true,
				"bucket": "${aws_s3_bucket.example.id}",
			},
			"other_block": {
				"block_public_acls": false,
				"bucket": "${aws_s3_bucket.other_bucket.id}",
			},
		},
	}}
}

test_has_block_public_acl_set_to_false_in_one_but_is_correct_in_second_bucket {
	count(violation) == 1 with input as {"resource": {
		"aws_s3_bucket": {
			"example": {"bucket": "example"},
			"other_bucket": {"bucket": "other_example"},
		},
		"aws_s3_bucket_public_access_block": {
			"example": {
				"block_public_acls": false,
				"bucket": "${aws_s3_bucket.example.id}",
			},
			"other_block": {
				"block_public_acls": true,
				"bucket": "${aws_s3_bucket.other_bucket.id}",
			},
		},
	}}
}

test_missing_block_public_acl_block_object {
	count(violation) == 1 with input as {"resource": {"aws_s3_bucket": {"example": {"bucket": "example"}}}}
}

test_not_s3_bucket {
	count(violation) == 0 with input as {"resource": {"aws_instance": {"fake-server": {}}}}
}

test_missing_block_public_acl_for_defined_bucket {
	count(violation) == 1 with input as {"resource": {
		"aws_s3_bucket": {"example": {"bucket": "example"}},
		"aws_s3_bucket_public_access_block": {"example": {
			"block_public_acls": true,
			"bucket": "${aws_s3_bucket.example3.id}",
		}},
	}}
}

test_multiple_buckets_each_have_valid_acls {
	count(violation) == 0 with input as {"resource": {
		"aws_s3_bucket": {
			"example": {"bucket": "example"},
			"other_bucket": {"bucket": "other_example"},
		},
		"aws_s3_bucket_public_access_block": {
			"example": {
				"block_public_acls": true,
				"bucket": "${aws_s3_bucket.example.id}",
			},
			"other_block": {
				"block_public_acls": true,
				"bucket": "${aws_s3_bucket.other_bucket.id}",
			},
		},
	}}
}

test_multiple_buckets_each_have_invalid_acls {
	count(violation) == 2 with input as {"resource": {
		"aws_s3_bucket": {
			"example": {"bucket": "example"},
			"other_bucket": {"bucket": "other_example"},
		},
		"aws_s3_bucket_public_access_block": {
			"example": {
				"block_public_acls": false,
				"bucket": "${aws_s3_bucket.example.id}",
			},
			"other_block": {
				"block_public_acls": false,
				"bucket": "${aws_s3_bucket.other_bucket.id}",
			},
		},
	}}
}
