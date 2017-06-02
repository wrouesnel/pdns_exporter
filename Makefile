
GO_SRC := $(shell find . -name '*.go' ! -path '*/vendor/*' ! -path 'tools/*' )
GO_DIRS := $(shell find . -type d -name '*.go' ! -path '*/vendor/*' ! -path 'tools/*' )
GO_PKGS := $(shell go list ./... | grep -v '/vendor/')

BINARY = pdns_exporter
VERSION ?= $(shell git describe --dirty)

COVERDIR = ".coverage"
TOOLDIR = tools

export PATH := $(TOOLDIR):$(PATH)

all: style lint test $(BINARY).x86_64

$(BINARY).x86_64: $(GO_SRC)
	CGO_ENABLED=0 GOARCH=amd64 go build -a -ldflags "-extldflags '-static' -X main.Version=$(VERSION)" -o $(BINARY).x86_64 .

style: tools
	gometalinter --vendored-linters --disable-all --enable=gofmt --vendor

lint: tools
	gometalinter --vendored-linters --disable=gotype $(GO_DIRS)

fmt: tools
	gofmt -s -w $(GO_SRC)

test: tools
	@mkdir -p $(COVERDIR)
	for pkg in $(GO_PKGS) ; do \
		go test -v -covermode count -coverprofile=$(COVERDIR)/$(echo $$pkg | tr '/' '-').out $(pkg) ; \
	done
	gocovmerge $(shell find $(COVERDIR) -name '*.out') > cover.out

tools:
	$(MAKE) -C tools

.PHONY: tools style fmt test all
