GO_SRC := $(shell find -type f -name '*.go' ! -path '*/vendor/*')

PROGNAME := pdns_exporter
CONTAINER_NAME ?= wrouesnel/$(PROGNAME):latest
VERSION ?= $(shell git describe --dirty)

all: style vet test $(PROGNAME)

# Cross compilation (e.g. if you are on a Mac)
cross: docker-build docker

# Simple go build
$(PROGNAME): $(GO_SRC)
	CGO_ENABLED=0 go build -a -ldflags "-extldflags '-static' -X main.Version=$(VERSION)" -o $(PROGNAME) .

$(PROGNAME)_integration_test: $(GO_SRC)
	CGO_ENABLED=0 go test -c -tags integration \
	    -a -ldflags "-extldflags '-static' -X main.Version=$(VERSION)" -o $(PROGNAME)_integration_test -cover -covermode count .

# Take a go build and turn it into a minimal container
docker: $(PROGNAME)
	docker build -t $(CONTAINER_NAME) .

lint:
	go lint 

vet:
	go vet

# Check code conforms to go fmt
style:
	! gofmt -s -l $(GO_SRC) 2>&1 | read 2>/dev/null

# Format the code
fmt:
	gofmt -s -w $(GO_SRC)

test:
	go test -v -covermode count -coverprofile=cover.test.out

test-integration: $(PROGNAME) $(PROGNAME)_integration_test
	# TODO(wrouesnel): add docker-based test suite
	/bin/true
#	tests/test-smoke "$(shell pwd)/postgres_exporter" "$(shell pwd)/postgres_exporter_integration_test_script $(shell pwd)/postgres_exporter_integration_test $(shell pwd)/cover.integration.out"

# Do a self-contained docker build - we pull the official upstream container
# and do a self-contained build.
docker-build:
	docker run -v $(shell pwd):/go/src/github.com/wrouesnel/$(PROGNAME) \
	    -v $(shell pwd):/real_src \
	    -e SHELL_UID=$(shell id -u) -e SHELL_GID=$(shell id -g) \
	    -w /go/src/github.com/wrouesnel/$(PROGNAME) \
		golang:1.8-wheezy \
		/bin/bash -c "make >&2 && chown $$SHELL_UID:$$SHELL_GID ./$(PROGNAME)"
	docker build -t $(CONTAINER_NAME) .

push:
	docker push $(CONTAINER_NAME)

.PHONY: docker-build docker test vet push cross
