/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "Protocols/MaliciousRep3Share.h"
#include "ECDSA/mal_poly_commit.hpp"

#include "hm-pc-party.hpp"




int main(int argc, const char** argv)
{
    run<MaliciousRep3Share>(argc, argv);
}
