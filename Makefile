MODULE  := github.com/AUTORQ/adl-signing-server
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"
TF_ENV  := deploy/terraform/environments/example

CLI_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build lambda ec2 cli dist test test-dynamo lint tf-check check clean local

all: build

## build: adl and adl-signer for this machine into bin/
build:
	$(GOBUILD) -o bin/adl ./cmd/adl
	$(GOBUILD) -o bin/adl-signer ./cmd/adl-signer

## lambda: dist/adl-signer-lambda.zip for the Lambda module (linux/arm64)
lambda:
	@mkdir -p dist/lambda
	GOOS=linux GOARCH=arm64 $(GOBUILD) -tags lambda.norpc -o dist/lambda/bootstrap ./cmd/adl-signer
	cd dist/lambda && rm -f ../adl-signer-lambda.zip && zip -q -X ../adl-signer-lambda.zip bootstrap
	@echo "built dist/adl-signer-lambda.zip"

## ec2: dist/adl-signer-linux-arm64 for the EC2 module
ec2:
	@mkdir -p dist
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o dist/adl-signer-linux-arm64 ./cmd/adl-signer
	@echo "built dist/adl-signer-linux-arm64"

## cli: adl for every platform developers and stations use, plus the EoL scripts
cli:
	@mkdir -p dist/cli
	@for p in $(CLI_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "adl $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) -o dist/cli/adl-$$os-$$arch$$ext ./cmd/adl || exit 1; \
	done
	cp scripts/eol/*.sh dist/cli/
	cd dist/cli && sha256sum * > SHA256SUMS

dist: lambda ec2 cli

## test: unit, service, e2e tests
test:
	go test -race ./...

## test-dynamo: also run the registry tests against DynamoDB Local in docker
test-dynamo:
	@docker rm -f adl-dynamo-test >/dev/null 2>&1 || true
	docker run -d --rm --name adl-dynamo-test -p 18000:8000 amazon/dynamodb-local >/dev/null
	@sleep 3
	ADL_TEST_DYNAMO_ENDPOINT=http://127.0.0.1:18000 go test -count=1 ./internal/store/... ; \
		status=$$?; docker rm -f adl-dynamo-test >/dev/null; exit $$status

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...

## tf-check: fmt, validate and the mocked-provider plan tests
tf-check:
	terraform fmt -check -recursive deploy/terraform
	cd $(TF_ENV) && terraform init -backend=false -input=false >/dev/null && terraform validate && terraform test

check: lint test tf-check

## local: run the whole server in memory on 127.0.0.1:8080
local: build
	./bin/adl-signer serve -local-insecure

clean:
	rm -rf bin dist
