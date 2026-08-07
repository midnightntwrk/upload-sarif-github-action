#!/usr/bin/env bats
#
# The differential gate's verdict: pass only when the finding count goes down.

load helper

# gate <head> <base>
gate() {
    run bash "$GATE_SH" "$1" "$2"
}

@test "a genuine fix passes: 2 -> 1" {
    gate 1 2
    [ "$status" -eq 0 ]
}

@test "fixing everything passes: 2 -> 0" {
    gate 0 2
    [ "$status" -eq 0 ]
}

# The stop-the-line rule: while findings are outstanding on the target, only
# changes that remove one may land.
@test "an unchanged count is blocked" {
    gate 1 1
    [ "$status" -eq 1 ]
}

# A swap removes one finding and adds another, so the count is level - which is
# exactly the case an "or equal" comparison would wave through.
@test "a swap is blocked, because the count is level" {
    gate 2 2
    [ "$status" -eq 1 ]
}

@test "a regression is blocked" {
    gate 2 1
    [ "$status" -eq 1 ]
}

@test "adding a finding to a clean target is blocked" {
    gate 1 0
    [ "$status" -eq 1 ]
}

@test "nothing anywhere passes" {
    gate 0 0
    [ "$status" -eq 0 ]
}

# Unreachable via the action - a clean head scan never triggers the base pass -
# but a gate that blocked a PR with no findings would be indefensible.
@test "a clean head passes whatever the base count" {
    gate 0 0
    [ "$status" -eq 0 ]
    gate 0 7
    [ "$status" -eq 0 ]
}

@test "large counts compare numerically, not as strings" {
    gate 9 10
    [ "$status" -eq 0 ]
    gate 100 99
    [ "$status" -eq 1 ]
}

# `[ -lt ]` parses base 10, unlike `(( ))` and `[[ ]]` where a leading zero
# means octal. Nothing writes a padded count today, but the verdict must not
# hinge on which comparison operator someone reaches for next.
@test "counts with leading zeros are read as decimal" {
    gate 007 8
    [ "$status" -eq 0 ]
    gate 010 9
    [ "$status" -eq 1 ]
}

@test "a plus-signed count is rc 2, not silently accepted" {
    gate +1 2
    [ "$status" -eq 2 ]
}

# One in, one out, on a target with nothing outstanding: the count is level at
# zero, so there is nothing to reduce and nothing to block.
@test "zero to zero passes rather than deadlocking" {
    gate 0 0
    [ "$status" -eq 0 ]
}

@test "a missing base count is rc 2, not a pass" {
    gate 1 ''
    [ "$status" -eq 2 ]
}

@test "a missing head count is rc 2" {
    run bash "$GATE_SH"
    [ "$status" -eq 2 ]
}

@test "a non-numeric count is rc 2" {
    gate x 2
    [ "$status" -eq 2 ]
    gate 2 y
    [ "$status" -eq 2 ]
}

@test "a negative count is rc 2" {
    gate -1 2
    [ "$status" -eq 2 ]
}

@test "a fractional count is rc 2" {
    gate 1.5 2
    [ "$status" -eq 2 ]
}

@test "a count with whitespace is rc 2" {
    gate '1 ' 2
    [ "$status" -eq 2 ]
}

@test "the passing message reports both counts" {
    gate 1 2
    [[ "$output" == *"2"* ]]
    [[ "$output" == *"1"* ]]
}

@test "a regression says how many findings were introduced" {
    gate 5 2
    [[ "$output" == *"introduces 3"* ]]
}

# The blocked-while-level case is the surprising one, so the message has to
# explain itself rather than just refusing.
@test "a level count explains the stop-the-line rule" {
    gate 2 2
    [[ "$output" == *"reduce the count"* ]]
}
