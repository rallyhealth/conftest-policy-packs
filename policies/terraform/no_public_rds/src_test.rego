package terraform_no_public_rds

test_is_not_public {
	count(violation) == 0 with input as {"resource": {"aws_db_instance": {"encrypted-db": {
		"allocated_storage": 10,
		"engine": "mysql",
		"engine_version": "5.7",
		"instance_class": "db.t3.micro",
		"name": "mydb",
	}}}}
}

test_is_public {
	count(violation) == 1 with input as {"resource": {"aws_db_instance": {"encrypted-db": {
		"allocated_storage": 10,
		"engine": "mysql",
		"engine_version": "5.7",
		"instance_class": "db.t3.micro",
		"name": "mydb",
		"publicly_accessible": true,
	}}}}
}

test_explicitly_is_not_public {
	count(violation) == 0 with input as {"resource": {"aws_db_instance": {"encrypted-db": {
		"allocated_storage": 10,
		"engine": "mysql",
		"engine_version": "5.7",
		"instance_class": "db.t3.micro",
		"name": "mydb",
		"publicly_accessible": false,
	}}}}
}
