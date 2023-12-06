#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT


BIN=./rep-ring-switch-party.x
#BIN=./sy-rep-ring-switch-party.x

N_BITS=31

#$BIN -p 0 -N 3 --n_bits $N_BITS -t -d & ; pid0=$!
$BIN -p 1 -N 3 --n_bits $N_BITS -te -d & ; pid1=$!
$BIN -p 2 -N 3 --n_bits $N_BITS -te -d & ; pid2=$!
wait $pid0 $pid1 $pid2

#
#BIN=./sy-rep-ring-switch-party.x
#$BIN -p 0 -N 3 --n_bits $$N_BITS -t -d & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits $$N_BITS -t -d & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits $$N_BITS -t -d & ; pid2=$!
#wait $pid0 $pid1 $pid2
