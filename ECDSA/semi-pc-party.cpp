/*
 * fake-spdz-ecdsa-party.cpp
 *
 */



#include "GC/SemiSecret.h"
#include "GC/SemiPrep.h"

#include "Protocols/SemiMC.hpp"
#include "Protocols/SemiPrep.hpp"
#include "Protocols/SemiInput.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "GC/SemiSecret.hpp"
#include "ot-pc-party.hpp"

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"

#include <assert.h>


int main(int argc, const char** argv)
{
    run<SemiShare>(argc, argv);
}
