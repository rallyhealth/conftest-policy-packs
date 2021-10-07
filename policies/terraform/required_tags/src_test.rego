package terraform_required_tags

test_has_required_tags {
	count(warn) == 0 with input as {"resource": {"aws_security_group": {"sg-group-name": {"tags": {
		"owner_application": "application",
		"owner_domain": "domain",
		"owner_iam_role": "role",
		"owner_team": "team",
	}}}}}
}

test_missing_required_tags {
	count(warn) == 1 with input as {"resource": {"aws_security_group": {"sg-group-name": {"tags": {"Name": "MyName"}}}}}
}

test_no_tags {
	count(warn) == 0 with input as {"resource": {"aws_security_group": {"sg-group-name": {}}}}
}
