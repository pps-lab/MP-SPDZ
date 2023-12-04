/*
 * fake-spdz-ecdsa-party.cpp
 *
 */

#define NO_MIXED_CIRCUITS

#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "GC/VectorInput.h"

#include "Protocols/Share.hpp"
#include "Protocols/MAC_Check.hpp"
#include "GC/Secret.hpp"
#include "GC/TinierSharePrep.hpp"
#include "ot-pc-party.hpp"

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"

#include <assert.h>


int main(int argc, const char** argv)
{
    run<Share>(argc, argv);
}
