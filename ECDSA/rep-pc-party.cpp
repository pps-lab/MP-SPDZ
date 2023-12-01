/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "Protocols/Rep3Share.h"


#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"

#include "hm-pc-party.hpp"

int main(int argc, const char** argv)
{
    run<Rep3Share>(argc, argv);
}
