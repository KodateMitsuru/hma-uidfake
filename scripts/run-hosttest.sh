#!/usr/bin/env bash
# Host-side unit test for policy.c: compiles the real file against the linux/* shims in
# scripts/hosttest/ and checks that every configured (caller, target) pair is matched and
# that nothing else is. Catches C-level mistakes the Python model cannot see (word sizes,
# ordering, field mixups).
set -eu
cd "$(dirname "$0")/.."
out=build/policy_host_test
cc -O1 -g -I src -I scripts/hosttest -I src/include -o "$out" scripts/policy_host_test.c
"$out"
