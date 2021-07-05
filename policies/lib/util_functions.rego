package util_functions

has_key(x, k) {
	_ = x[k]
}

# Count decreases if the item matches any value found in the list.
# So any value less than the length of the list means that the item is found
item_contained_in_list(item, list) {
	count({y | y := list[_]; not startswith(item, y)}) < count(list)
}
