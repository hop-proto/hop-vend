help: ## List tasks with documentation
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' "$(firstword $(MAKEFILE_LIST))" | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

GOLANGCI_LINT := golangci-lint
ifeq (, $(shell command -v "$(GOLANGCI_LINT)"))
	GOLANGCI_LINT_ERR = $(error install golangci-lint with e.g. brew install golangci/tap/golangci-lint)
endif

.PHONY: lint
lint: ## lint go code
lint: ; $(GOLANGCI_LINT_ERR)
	@echo "lint-go"
	@$(GOLANGCI_LINT) run --timeout 1m

.PHONY: format
format: ## format Go code
	@echo "Formatting Go code"
	@$(GOLANGCI_LINT) fmt

.PHONY: build
build: ## compile
build:
	go build ./...

.PHONY: debug
debug: ## compile in debug mode
debug:
	go build -tags debug ./...

.PHONY: test
test: ## test. To run with trace logging, add "-tags debug" to the arguments
test:
	go test ./... -timeout 10s
