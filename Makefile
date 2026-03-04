
CHECKS_DIR := checks

fmt:
	opa fmt $(CHECKS_DIR) -w

test:
	go run . test -v $(CHECKS_DIR)

.PHONY: fmt test