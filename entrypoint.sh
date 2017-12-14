#!/usr/bin/env bash

rm -rf bin/ build/ .direnv/
direnv allow
eval $(direnv export bash)

export LC_ALL=C.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8
# cd /code/build; make -j $(nproc)
exec bash
