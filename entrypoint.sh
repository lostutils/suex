#!/usr/bin/env bash

git clone https://github.com/odedlaz/suex.git /code
cd /code
git pull
git checkout snap
direnv allow
eval $(direnv export bash)
exec bash
# cd /code/build; make -j $(nproc)
