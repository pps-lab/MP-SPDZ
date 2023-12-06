#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT


BIN=./rep-ring-switch-party.x
#BIN=./sy-rep-ring-switch-party.x

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


#$BIN -p 0 -N 3 -i f60000 -i f60000 -i 0 -b $N_BITS -o 0 & ; pid0=$!
#$BIN -p 1 -N 3 -i f60000 -i f60000 -i 0 -b $N_BITS -o 0 & ; pid1=$!
#$BIN -p 2 -N 3 -i f60000 -i f60000 -i 0 -b $N_BITS -o 0 & ; pid2=$!
#wait $pid0 $pid1 $pid2
##
#echo "====================";

#BIN=./mascot-switch-party.x

#$BIN -p 0 -N 3 --n_bits 34 --n_shares 92 --out_start 0 --n_threads 4 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 34 --n_shares 92 --out_start 0 --n_threads 4 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 34 --n_shares 92 --out_start 0 --n_threads 4 & ; pid2=$!
#wait $pid0 $pid1 $pid2

##
echo "====================";

#$BIN -p 0 -N 3 --n_bits 64 -i i8684,f790244,i1,f91 -i i8746,f795886 -i i8618,f784238 -d --n_threads 2 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 64 -i i8684,f790244,i1,f91 -i i8746,f795886 -i i8618,f784238 -d --n_threads 2 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 64 -i i8684,f790244,i1,f91 -i i8746,f795886 -i i8618,f784238 -d --n_threads 2 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 --n_bits 64 --chunk_size 250000 -i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i 0 -i 0 -d --n_threads 2 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 64 --chunk_size 250000 -i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i 0 -i 0 -d --n_threads 2 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 64 --chunk_size 250000 -i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i 0 -i 0 -d --n_threads 2 & ; pid2=$!
#wait $pid0 $pid1 $pid2

$BIN -p 0 -N 3 --n_bits 31 -i i8684 -i 0 -i 0 --n_threads 36 -d & ; pid0=$!
$BIN -p 1 -N 3 --n_bits 31 -i i8684 -i 0 -i 0 --n_threads 36 -d & ; pid1=$!
$BIN -p 2 -N 3 --n_bits 31 -i i8684 -i 0 -i 0 --n_threads 36 -d & ; pid2=$!
wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 --n_bits 64 -i i868 -i 0 -i 0 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 64 -i i868 -i 0 -i 0 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 64 -i i868 -i 0 -i 0 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 --n_shares 2977 --n_bits 64 --n_threads 10 --out_start 2396508 & ; pid0=$!
#$BIN -p 1 -N 3 --n_shares 2977 --n_bits 64 --n_threads 10 --out_start 2396508 & ; pid1=$!
#$BIN -p 2 -N 3 --n_shares 2977 --n_bits 64 --n_threads 10 --out_start 2396508 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 --n_bits 33 --n_shares 92 --n_bits 33 --out_start 0 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 33 --n_shares 92 --n_bits 33 --out_start 0 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 33 --n_shares 92 --n_bits 33 --out_start 0 & ; pid2=$!
#wait $pid0 $pid1 $pid2
