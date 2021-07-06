package util_functions

has_key(x, k) {
	_ = x[k]
}

item_startswith_in_list(item, list) {
	some i
	list_item := list[i]
	startswith(item, list_item)
}
