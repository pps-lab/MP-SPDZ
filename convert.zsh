#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT


#BIN=./rep-ring-switch-party.x
BIN=./sy-rep-ring-switch-party.x

N_BITS=32
#$BIN -p 0 -N 3 -n 92 & ; pid0=$!
#$BIN -p 1 -N 3 -n 92 & ; pid1=$!
#$BIN -p 2 -N 3 -n 92 & ; pid2=$!
#wait $pid0 $pid1 $pid2
##
#echo "====================";


#$BIN -p 0 -N 3 -n 60000 -b $N_BITS & ; pid0=$!
#$BIN -p 1 -N 3 -n 60000 -b $N_BITS & ; pid1=$!
#$BIN -p 2 -N 3 -n 60000 -b $N_BITS & ; pid2=$!
#wait $pid0 $pid1 $pid2
##
#echo "====================";

$BIN -p 0 -N 3 -i f60000 -i f60000 -i 0 -b $N_BITS -o 0 & ; pid0=$!
$BIN -p 1 -N 3 -i f60000 -i f60000 -i 0 -b $N_BITS -o 0 & ; pid1=$!
$BIN -p 2 -N 3 -i f60000 -i f60000 -i 0 -b $N_BITS -o 0 & ; pid2=$!
wait $pid0 $pid1 $pid2
#
echo "====================";