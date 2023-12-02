#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT

ADDR_ONE=ec2-3-67-134-221.eu-central-1.compute.amazonaws.com
ADDR_TWO=ec2-18-153-73-205.eu-central-1.compute.amazonaws.com
ADDR_THREE=ec2-3-75-226-178.eu-central-1.compute.amazonaws.com


# scp persistence file
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Persistence/Transactions-P1-P251.data Persistence/Transactions-P1-P251.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Persistence/Transactions-P0-P251.data Persistence/Transactions-P0-P251.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Persistence/Transactions-P2-P251.data Persistence/Transactions-P2-P251.data

scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Player-Data/Input-Binary-P0-0 Player-Data/Input-Binary-P0-0
scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Player-Data/Input-Binary-P1-0 Player-Data/Input-Binary-P1-0
scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Player-Data/Input-Binary-P2-0 Player-Data/Input-Binary-P2-0