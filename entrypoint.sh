#!/usr/bin/env bash

# git clone https://github.com/odedlaz/suex.git /code
cd /code
exec fish -c 'direnv allow'
exec fish -c 'direnv reload'
