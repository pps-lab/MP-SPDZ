#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT



BIN=./rep-pe-party.x
#BIN=./sy-rep-pe-party.x
#
#
#
##$BIN -p 0 -N 3 -n 120000 -i 0 & ; pid0=$!
##$BIN -p 1 -N 3 -n 110000 -i 0 & ; pid1=$!
##$BIN -p 2 -N 3 -n 110000 -i 0 & ; pid2=$!
##wait $pid0 $pid1 $pid2
#
##$BIN -p 0 -N 3 --n_shares 5297138 --eval_point 3090174033069088738712039487548204773548520248725210634374129034378083167182 --start 0 --input_party_i 1 & ; pid0=$!
##$BIN -p 1 -N 3 --n_shares 5297138 --eval_point 3090174033069088738712039487548204773548520248725210634374129034378083167182 --start 0 --input_party_i 1 & ; pid1=$!
##$BIN -p 2 -N 3 --n_shares 5297138 --eval_point 3090174033069088738712039487548204773548520248725210634374129034378083167182 --start 0 --input_party_i 1 & ; pid2=$!
##wait $pid0 $pid1 $pid2
#
##51500211
##1026147646161729028664823768439224818093630915464063659532331820111890328541
#
#$BIN -p 0 -N 3 --n_shares 41497138 --eval_point 1 --start 0 --input_party_i 1 & ; pid0=$!
#$BIN -p 1 -N 3 --n_shares 41497138 --eval_point 1 --start 0 --input_party_i 1 & ; pid1=$!
#$BIN -p 2 -N 3 --n_shares 41497138 --eval_point 1 --start 0 --input_party_i 1 & ; pid2=$!
#wait $pid0 $pid1 $pid2

$BIN -p 0 -N 3 --n_shares 32 --start 0 --input_party_i 0 --curve sec256k1 & ; pid0=$!
$BIN -p 1 -N 3 --n_shares 32 --start 0 --input_party_i 0 --curve sec256k1 & ; pid1=$!
$BIN -p 2 -N 3 --n_shares 32 --start 0 --input_party_i 0 --curve sec256k1 & ; pid2=$!
wait $pid0 $pid1 $pid2
#


#BIN=./mascot-pe-party.x
#BIN=./semi-pe-party.x
##
#$BIN -p 0 -N 2 --n_shares 32 --start 0 --input_party_i 0 & ; pid0=$!
#$BIN -p 1 -N 2 --n_shares 32 --start 0 --input_party_i 0 & ; pid1=$!
#wait $pid0 $pid1
