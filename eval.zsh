#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT


#BIN=./rep-ring-switch-party.x

#$BIN -p 0 -N 3 -n 92 & ; pid0=$!
#$BIN -p 1 -N 3 -n 92 & ; pid1=$!
#$BIN -p 2 -N 3 -n 92 & ; pid2=$!
#wait $pid0 $pid1 $pid2
#
echo "====================";

#BIN=./rep-pe-party.x
BIN=./sy-rep-pe-party.x


#$BIN -p 0 -N 3 -n 120000 -i 0 & ; pid0=$!
$BIN -p 1 -N 3 -n 110000 -i 0 & ; pid1=$!
$BIN -p 2 -N 3 -n 110000 -i 0 & ; pid2=$!
wait $pid0 $pid1 $pid2

