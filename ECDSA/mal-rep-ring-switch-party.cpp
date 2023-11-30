/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/MalRepRingShare.h"

#include "hm-switch-party.hpp"

int main(int argc, const char** argv)
{
    run<MalRepRingShare<64, 40>, Rep3Share<P377Element::Scalar>>(argc, argv);
}
