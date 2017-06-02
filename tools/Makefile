# Makefile to build the tools used in the build system.
# If recreating from scratch, you will need a local install of govendor
# and to run govendor init in this folder before running govendor fetch.
GO_SRC := $(shell find $(SOURCEDIR) -name '*.go')

all: gocovmerge gometalinter govendor

govendor: $(GO_SRC)
	go build -o govendor ./vendor/github.com/kardianos/govendor

gocovmerge: $(GO_SRC)
	go build -o gocovmerge ./vendor/github.com/wadey/gocovmerge

gometalinter: $(GO_SRC)
	go build -o gometalinter ./vendor/github.com/alecthomas/gometalinter

goveralls: $(GO_SRC)
	go build -o gometalinter ./vendor/github.com/mattn/goveralls

update:
	govendor fetch -v github.com/kardianos/govendor
	govendor fetch -v github.com/wadey/gocovmerge
	govendor fetch -v github.com/alecthomas/gometalinter
	govendor fetch -v github.com/mattn/goveralls

.PHONY: all update
