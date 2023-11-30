#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT


BIN=./rep-pe-party.x

#$BIN -p 0 -N 3 -x 91 -y 1 & ; pid0=$!
#$BIN -p 1 -N 3 -x 91 -y 1 & ; pid1=$!
#$BIN -p 2 -N 3 -x 91 -y 1 & ; pid2=$!
#wait $pid0 $pid1 $pid2

$BIN -p 0 -N 3 -y 1 & ; pid0=$!
$BIN -p 1 -N 3 -y 1 & ; pid1=$!
$BIN -p 2 -N 3 -y 1 & ; pid2=$!
wait $pid0 $pid1 $pid2

#BIN=./mascot-pc-party.x
#
#$BIN -p 0 -N 2 -y 1 & ; pid0=$!
#$BIN -p 1 -N 2 -y 1 & ; pid1=$!
#wait $pid0 $pid1 $pid2