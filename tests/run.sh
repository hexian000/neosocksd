#!/bin/sh
# tests/run.sh: build and run tests
cd "$(dirname "$0")/.."
set -ex

cmake --build build
build/bin/neosocksd -l 127.0.1.1:31080 --api 127.0.1.1:39080 -r tests/main.lua --traceback
