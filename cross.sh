#!/bin/bash

[[ -s ~/.rvm/scripts/rvm ]] && source ~/.rvm/scripts/rvm

cd "$(dirname "$0")"

touch MAINTAINER

for ruby in 1.8.7 1.9.3
do
  rvm use $ruby
  rake clean
  rake || {
    echo "BUILD FAILED!" >&2
    exit 1
  }
done
