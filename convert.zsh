#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT


BIN=./rep-ring-switch-party.x
#BIN=./sy-rep-ring-switch-party.x

#BIN=./rep-field-switch-party.x
#BIN=./mascot-switch-party.x
#BIN=./semi-switch-party.x

N_BITS=31
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

#-i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i i8746,f795886 -i i8618,f784238


$BIN -p 0 -N 3 -i f32 -i 0 -i 0 -b $N_BITS -o 0 --n_threads 32 -sp --curve sec256k1 & ; pid0=$!
$BIN -p 1 -N 3 -i f32 -i 0 -i 0 -b $N_BITS -o 0 --n_threads 32 -sp --curve sec256k1 & ; pid1=$!
$BIN -p 2 -N 3 -i f32 -i 0 -i 0 -b $N_BITS -o 0 --n_threads 32 -sp --curve sec256k1 & ; pid2=$!
wait $pid0 $pid1 $pid2
##
#echo "====================";

#BIN=./semi-switch-party.x

#$BIN -p 0 -N 3 --n_bits 31 --n_shares 431080 --out_start 0 --chunk_size 250000 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 31 --n_shares 431080 --out_start 0 --chunk_size 250000 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 31 --n_shares 431080 --out_start 0 --chunk_size 250000 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 2 --n_bits 31 --n_shares 92 --out_start 0 --chunk_size 250000 --n_threads 1 -pr 128 & ; pid0=$!
#$BIN -p 1 -N 2 --n_bits 31 --n_shares 92 --out_start 0 --chunk_size 250000 --n_threads 1 -pr 128 & ; pid1=$!
#$BIN -p 2 -N 2 --n_bits 31 --n_shares 92 --out_start 0 --chunk_size 250000 --n_threads 1 -pr 128 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 2 --n_bits 31 -i i92 -i 0 --out_start 0 --chunk_size 250000 --n_threads 1 & ; pid1=$!
#$BIN -p 1 -N 2 --n_bits 31 -i i92 -i 0 --out_start 0 --chunk_size 250000 --n_threads 1 & ; pid1=$!
#$BIN -p 0 -N 2 --n_bits 31 -i f2912,f32,f32,f1 -i 0 --out_start 0 --chunk_size 250000 --n_threads 1 -pr 128 & ; pid0=$!
#$BIN -p 0 -N 2 --n_bits 31 -i f32 -i 0 --out_start 0 --chunk_size 250000 --n_threads 1 -pr 128 & ; pid1=$!
#$BIN -p 1 -N 2 --n_bits 31 -i f32 -i 0 --out_start 0 --chunk_size 250000 --n_threads 1 -pr 128 & ; pid1=$!
#wait $pid0 $pid1
##
echo "====================";



#$BIN -p 0 -N 3 --n_bits 64 -i i8684,f790244,i1,f91 -i i8746,f795886 -i i8618,f784238 -d --n_threads 2 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 64 -i i8684,f790244,i1,f91 -i i8746,f795886 -i i8618,f784238 -d --n_threads 2 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 64 -i i8684,f790244,i1,f91 -i i8746,f795886 -i i8618,f784238 -d --n_threads 2 & ; pid2=$!
#wait $pid0 $pid1 $pid2
#$BIN -p 0 -N 3 --n_bits 31 -i i167090,f51330048,i1,f3072 -i 0 -i 0 -d --n_threads 1 & ; pid0=$!

#$BIN -p 0 -N 3 --n_bits 31 -i i167090,f5130048 -i 0 -i 0 -d --n_threads 1 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 31 -i i167090,f5130048 -i 0 -i 0 -d --n_threads 1 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 31 -i i167090,f5130048 -i 0 -i 0 -d --n_threads 1 & ; pid2=$!
#wait $pid0 $pid1 $pid2
#$BIN -p 0 -N 3 --n_bits 31 -i i167090 -i 0 -i 0 -d --n_threads 1 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 31 -i i167090 -i 0 -i 0 -d --n_threads 1 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 31 -i i167090 -i 0 -i 0 -d --n_threads 1 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 --n_bits 64 --chunk_size 250000 -i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i 0 -i 0 -d --n_threads 2 & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 64 --chunk_size 250000 -i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i 0 -i 0 -d --n_threads 2 & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 64 --chunk_size 250000 -i i8684,f790244,i1,f91,f2912,f32,f32,f1 -i 0 -i 0 -d --n_threads 2 & ; pid2=$!
#wait $pid0 $pid1 $pid2

#$BIN -p 0 -N 3 --n_bits 31 -i i8684 -i 0 -i 0 --n_threads 8 -d & ; pid0=$!
#$BIN -p 1 -N 3 --n_bits 31 -i i8684 -i 0 -i 0 --n_threads 8 -d & ; pid1=$!
#$BIN -p 2 -N 3 --n_bits 31 -i i8684 -i 0 -i 0 --n_threads 8 -d & ; pid2=$!
#wait $pid0 $pid1 $pid2

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
