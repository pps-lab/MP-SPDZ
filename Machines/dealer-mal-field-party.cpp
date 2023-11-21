/*
 * dealer-ring-party.cpp
 *
 */

#include "Protocols/DealerShare.h"
//#include "Math/gf2nlong.h"
#include "Math/gfp.hpp"


#include "Protocols/DealerMaliciousShare.h"
#include "Protocols/DealerMaliciousInput.h"
#include "Protocols/Dealer.h"

#include "Processor/FieldMachine.hpp"
#include "Processor/Machine.hpp"

#include "Protocols/Replicated.hpp"
#include "Protocols/DealerPrep.hpp"
#include "Protocols/DealerMaliciousInput.hpp"
#include "Protocols/DealerMaliciousMC.hpp"
#include "Protocols/DealerInput.hpp"
#include "Protocols/DealerMC.hpp"

#include "Protocols/DealerMatrixPrep.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/SemiInput.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "Protocols/MAC_Check.hpp"

#include "SPDZ.hpp"

#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/MalRepRingPrep.hpp"
#include "Protocols/SemiMC.hpp"

#include "GC/DealerPrep.h"
#include "GC/SemiPrep.h"
#include "GC/SemiSecret.hpp"

#include "GC/TinierSecret.h"
#include "GC/TinyMC.h"
#include "GC/TinierSharePrep.h"

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    DishonestMajorityFieldMachine<DealerMaliciousShare, DealerMaliciousShare, gf2n_short>(argc, argv, opt);
}
