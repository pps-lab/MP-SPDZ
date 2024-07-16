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

#include "hm-switch-party.hpp"

//#define VERBOSE 1
#define DEBUG_NETWORKING 1

int main(int argc, const char** argv)
{
    run<Share, Share>(argc, argv);
}
