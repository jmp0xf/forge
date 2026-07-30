# Reading this file must never execute Make expansion.
side_effect := $(shell printf 'runner parser executed shell' > FORGE-MUST-NOT-EXECUTE)

.PHONY: check
check:
	@printf 'this target must run only after an explicit evidence request\n'
