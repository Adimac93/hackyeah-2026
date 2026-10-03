#!/bin/sh
# Serve, then load the model into GPU memory before any real request arrives:
# a cold load takes seconds, the judge's timeout is under two.
set -e
ollama serve &
until ollama list >/dev/null 2>&1; do sleep 1; done
ollama run "$MODEL" "" </dev/null >/dev/null
wait
