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

BIN=./rep-pc-party.x
#BIN=./sy-rep-pc-party.x

$BIN -p 0 -N 3 -y 1 -x 20 --curve sec256k1 & ; pid0=$!
$BIN -p 1 -N 3 -y 1 -x 20 --curve sec256k1 &> /dev/null & ; pid1=$!
$BIN -p 2 -N 3 -y 1 -x 20 --curve sec256k1 & ; pid2=$!
wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 -m 2977 -s 2396508 & ; pid0=$!
#$BIN -p 1 -N 3 -m 2977 -s 2396508 &> /dev/null & ; pid1=$!
#$BIN -p 2 -N 3 -m 2977 -s 2396508 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 -x 91 -y 1 -s 0 & ; pid0=$!
#$BIN -p 1 -N 3 -x 91 -y 1 -s 0 &> /dev/null & ; pid1=$!
#$BIN -p 2 -N 3 -x 91 -y 1 -s 0 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#BIN=./mascot-pc-party.x
##
##$BIN -p 0 -N 2 -x 89 -y 3 -s 0 & ; pid0=$!
#$BIN -p 1 -N 2 -x 89 -y 3 -s 0 &> /dev/null & ; pid1=$!
###$BIN -p 2 -N 3 -x 91 -y 1 -s 0 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#BIN=./semi-pc-party.x

#$BIN -p 0 -N 2 -x 89 -y 3 -s 0 & ; pid0=$!
#$BIN -p 1 -N 2 -x 89 -y 3 -s 0 &> /dev/null & ; pid1=$!
##$BIN -p 2 -N 3 -x 91 -y 1 -s 0 & ; pid2=$!
#wait $pid0 $pid1 $pid2


#BIN=./rep-pe-party.x
#$BIN -p 0 -N 3 -n 92 & ; pid0=$!
#$BIN -p 1 -N 3 -n 92 & ; pid1=$!
#$BIN -p 2 -N 3 -n 92 & ; pid2=$!
#wait $pid0 $pid1 $pid2

