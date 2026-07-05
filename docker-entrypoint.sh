#!/bin/sh
# Build the `codescan serve` invocation from environment variables so the image
# is configurable without overriding the command.
set -e

ARGS="serve"
ARGS="$ARGS --host ${CODESCAN_HOST:-0.0.0.0}"
ARGS="$ARGS --port ${CODESCAN_PORT:-8000}"
ARGS="$ARGS --config ${CODESCAN_CONFIG:-/app/config/config.example.yaml}"
ARGS="$ARGS --fixtures ${CODESCAN_FIXTURES:-/app/fixtures}"

# Enable the AI stages (needs ANTHROPIC_API_KEY in the environment).
[ "${CODESCAN_AI:-false}" = "true" ] && ARGS="$ARGS --ai"
# Scan Bitbucket/Snyk/Xray instead of the sample fixtures (needs credentials).
[ "${CODESCAN_LIVE:-false}" = "true" ] && ARGS="$ARGS --live"

# shellcheck disable=SC2086
exec codescan $ARGS
