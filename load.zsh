#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT

#ADDR_ONE=ec2-3-123-20-235.eu-central-1.compute.amazonaws.com
#ADDR_TWO=ec2-18-153-91-249.eu-central-1.compute.amazonaws.com
#ADDR_THREE=ec2-18-184-174-48.eu-central-1.compute.amazonaws.com

ADDR_ONE=ec2-18-184-121-68.eu-central-1.compute.amazonaws.com
ADDR_TWO=ec2-18-184-57-69.eu-central-1.compute.amazonaws.com
ADDR_THREE=ec2-3-67-83-162.eu-central-1.compute.amazonaws.com

# scp persistence file
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Persistence/Transactions-P0-P251.data Persistence/Transactions-P0-P251.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Persistence/Transactions-P1-P251.data Persistence/Transactions-P1-P251.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Persistence/Transactions-P2-P251.data Persistence/Transactions-P2-P251.data

scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Persistence/Transactions-P0.data Persistence/Transactions-P0.data
scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Persistence/Transactions-P1.data Persistence/Transactions-P1.data
scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Persistence/Transactions-P2.data Persistence/Transactions-P2.data

#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Player-Data/Input-Binary-P0-0 Player-Data/Input-Binary-P0-0
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Player-Data/Input-Binary-P1-0 Player-Data/Input-Binary-P1-0
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Player-Data/Input-Binary-P2-0 Player-Data/Input-Binary-P2-0
##
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Player-Data/Input-Binary-P0-0-format Player-Data/Input-Binary-P0-0-format
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Player-Data/Input-Binary-P1-0-format Player-Data/Input-Binary-P1-0-format
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Player-Data/Input-Binary-P2-0-format Player-Data/Input-Binary-P2-0-format

#ADDR_ONE=ec2-3-120-247-100.eu-central-1.compute.amazonaws.com
#ADDR_TWO=ec2-3-67-11-41.eu-central-1.compute.amazonaws.com
#ADDR_THREE=ec2-3-75-189-220.eu-central-1.compute.amazonaws.com
#
#
## scp persistence file
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Persistence/Transactions-P0-P251.data Persistence/Transactions-P0-P251.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Persistence/Transactions-P1-P251.data Persistence/Transactions-P1-P251.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Persistence/Transactions-P2-P251.data Persistence/Transactions-P2-P251.data
#
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Persistence/Transactions-P0.data Persistence/Transactions-P0.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Persistence/Transactions-P1.data Persistence/Transactions-P1.data
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Persistence/Transactions-P2.data Persistence/Transactions-P2.data

#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Player-Data/Input-Binary-P0-0 Player-Data/Input-Binary-P0-0
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Player-Data/Input-Binary-P1-0 Player-Data/Input-Binary-P1-0
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Player-Data/Input-Binary-P2-0 Player-Data/Input-Binary-P2-0
##
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_ONE":code/MP-SPDZ/Player-Data/Input-Binary-P0-0-format Player-Data/Input-Binary-P0-0-format
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_TWO":code/MP-SPDZ/Player-Data/Input-Binary-P1-0-format Player-Data/Input-Binary-P1-0-format
#scp -i ~/.ssh/aws_ppl.pem "$ADDR_THREE":code/MP-SPDZ/Player-Data/Input-Binary-P2-0-format Player-Data/Input-Binary-P2-0-format