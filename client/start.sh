#!/bin/bash

shopt -s expand_aliases

type python &> /dev/null && alias PY='python'
type python3 &> /dev/null && alias PY='python3'

PY ssl-client.py $@

