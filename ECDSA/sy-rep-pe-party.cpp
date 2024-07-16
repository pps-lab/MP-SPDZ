/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/SpdzWiseMC.h"
#include "Protocols/SpdzWiseRingPrep.h"
#include "Protocols/SpdzWiseInput.h"
#include "Protocols/MalRepRingPrep.h"
#include "Processor/RingOptions.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/SemiHonestRepPrep.h"

#include "Protocols/Replicated.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/SpdzWise.hpp"
#include "Protocols/SpdzWiseRing.hpp"
#include "Protocols/SpdzWisePrep.hpp"
#include "Protocols/SpdzWiseInput.hpp"
#include "Protocols/SpdzWiseShare.hpp"
#include "Protocols/PostSacrifice.hpp"
#include "Protocols/SpdzWiseRep3Shuffler.hpp"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Processor/Data_Files.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"
#include "Machines/MalRep.hpp"

#include "hm-pe-party.hpp"

int main(int argc, const char** argv)
{
    run<SpdzWiseRepFieldShare>(argc, argv);

}
