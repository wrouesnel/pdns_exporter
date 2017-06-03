#!/bin/bash
# Helper script which lists all the recursive source file dependencies of a
# Go package for the Makefile.

filetypes=(\
GoFiles \
CgoFiles \
IgnoredGoFiles \
CFiles \
CXXFiles \
MFiles \
HFiles \
FFiles \
SFiles \
SwigFiles \
SwigCXXFiles \
SysoFiles \
TestGoFiles \
XTestGoFiles \
)

go list -f "{{ join .GoFiles \" {{ .Dir }}\" }}" $(go list -f '{{ join .Deps " " }}' $1)



