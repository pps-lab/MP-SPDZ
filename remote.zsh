#!/usr/bin/env zsh
set -xe
trap "exit" INT TERM
trap "kill 0" EXIT

#ADDR_ONE=ec2-3-123-20-235.eu-central-1.compute.amazonaws.com
#ADDR_TWO=ec2-18-153-91-249.eu-central-1.compute.amazonaws.com
#ADDR_THREE=ec2-18-184-174-48.eu-central-1.compute.amazonaws.com

ADDR_ONE=ec2-3-77-200-128.eu-central-1.compute.amazonaws.com
ADDR_TWO=ec2-3-71-35-211.eu-central-1.compute.amazonaws.com
ADDR_THREE=ec2-54-93-196-68.eu-central-1.compute.amazonaws.com

echo "$ADDR_ONE" >> hosts.txt;
echo "$ADDR_TWO" >> hosts.txt;
echo "$ADDR_THREE" >> hosts.txt;

command="cd code/MP-SPDZ; ./sy-rep-pe-party.x -p 0 -N 3 -h ip-10-100-0-66.eu-central-1.compute.internal --n_shares 51500211 --start 0 --input_party_i 0";

for host in $(cat hosts.txt); do ssh "$host" "$command" >"output.$host"; done
