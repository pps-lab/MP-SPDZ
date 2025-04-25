/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "Protocols/SPDZ.h"

#include "ot-share-party.hpp"

#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "GC/Secret.hpp"
#include "GC/TinierSharePrep.hpp"
#include "Protocols/MascotPrep.hpp"


int main(int argc, const char** argv)
{
    run<Share<P377Element::Scalar>>(argc, argv, -1, 2);
}
