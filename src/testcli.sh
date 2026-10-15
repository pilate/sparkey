#!/bin/sh
# Tests for the sparkey command line tool.
# Usage: testcli.sh <path to the sparkey binary>
sparkey=$1

fail() {
  echo "FAIL: $*"
  exit 1
}

# Checks that key $2 in index $1 has the value $3.
expect_value() {
  actual=$("$sparkey" get "$1" "$2") || fail "get $2 from $1 failed"
  [ "$actual" = "$3" ] || fail "expected '$3' for key $2 in $1, but got '$actual'"
}

rm -f cli.spl cli.spi cli-rewrite.spl cli-rewrite.spi

"$sparkey" createlog cli.spl || fail "createlog failed"

# The last line does not need a trailing newline, and values may contain the delimiter.
printf 'a\t1\nb\tx\ty\nlast\tno newline' | "$sparkey" appendlog cli.spl || fail "appendlog failed"
# Empty input appends nothing.
printf '' | "$sparkey" appendlog cli.spl || fail "appendlog of empty input failed"
# Other delimiters can be used.
printf 'c,3\n' | "$sparkey" appendlog -d , cli.spl || fail "appendlog with -d failed"
# A line without a delimiter is an error, and stops appending.
printf 'd\t4\nno-delimiter\ne\t5\n' | "$sparkey" appendlog cli.spl 2>/dev/null && fail "appendlog accepted a line without a delimiter"
# Lines longer than the initial read buffer work, including a last line that
# exactly fills it.
long=$(printf '%01000d' 0)
edge=$(printf '%0250d' 0)
printf 'long\t%s\nedge\t%s' "$long" "$edge" | "$sparkey" appendlog cli.spl || fail "appendlog of long lines failed"
# A key that appears again replaces the earlier value.
printf 'a\t1b\n' | "$sparkey" appendlog cli.spl || fail "appendlog failed"

"$sparkey" writehash cli.spl || fail "writehash failed"
expect_value cli.spi a 1b
expect_value cli.spi b "x	y"
expect_value cli.spi last "no newline"
expect_value cli.spi c 3
expect_value cli.spi d 4
expect_value cli.spi long "$long"
expect_value cli.spi edge "$edge"
"$sparkey" get cli.spi e
[ $? -eq 2 ] || fail "get of a missing key should exit with 2"

# Rewriting the hash file keeps its permissions.
chmod 600 cli.spi
printf 'f\t6\n' | "$sparkey" appendlog cli.spl || fail "appendlog failed"
"$sparkey" writehash cli.spl || fail "writehash failed"
[ "$(ls -l cli.spi | cut -c1-10)" = "-rw-------" ] || fail "writehash changed the permissions of cli.spi"
expect_value cli.spi f 6

# rewrite keeps only the live entries.
"$sparkey" rewrite cli.spi cli-rewrite.spi || fail "rewrite failed"
"$sparkey" info cli-rewrite.spl | grep -q "Puts: 8," || fail "rewrite did not drop the replaced entry"
expect_value cli-rewrite.spi a 1b

echo "Success!"
