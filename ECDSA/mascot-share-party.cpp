/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "GC/VectorInput.h"

#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "GC/Secret.hpp"
#include "GC/TinierSharePrep.hpp"
#include "Protocols/MascotPrep.hpp"

#include "ot-share-party.hpp"

int main(int argc, const char** argv)
{
    run<Share<P377Element::Scalar>>(argc, argv, -1, 2);
}
