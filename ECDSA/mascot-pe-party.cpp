/*
 * fake-spdz-ecdsa-party.cpp
 *
 */


//#include "GC/TinierSecret.h"
//#include "GC/TinyMC.h"
//#include "GC/VectorInput.h"
//
//#include "Protocols/LowGearShare.h"
//
//#include "Machines/SPDZ.hpp"
//#include "Protocols/CowGearPrep.hpp"
//
//
//#include "OT/NPartyTripleGenerator.hpp"
//
//#include "Protocols/Share.hpp"
//#include "Protocols/MAC_Check.hpp"
//
//#include "GC/TinierSharePrep.hpp"
//#include "GC/Secret.hpp"
#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "GC/VectorInput.h"

#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "GC/Secret.hpp"
#include "GC/TinierSharePrep.hpp"

#include "ot-pe-party.hpp"


int main(int argc, const char** argv)
{
    run<Share>(argc, argv);
}
