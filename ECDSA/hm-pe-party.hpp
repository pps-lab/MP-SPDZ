/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Protocols/Replicated.h"
#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/ReplicatedInput.h"
#include "Protocols/AtlasShare.h"
#include "Protocols/Rep4Share.h"
#include "Protocols/ProtocolSet.h"
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"
#include "Tools/Bundle.h"
#include "GC/TinyMC.h"
#include "GC/MaliciousCcdSecret.h"
#include "GC/CcdSecret.h"
#include "GC/VectorInput.h"

#include "ECDSA/P377Element.h"
#include "ECDSA/poly_eval.hpp"
#include "ECDSA/PEOptions.h"

#include "Protocols/MaliciousRepMC.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Processor/Input.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"
#include "GC/Secret.hpp"
#include "Machines/ShamirMachine.hpp"
#include "Machines/MalRep.hpp"
#include "Machines/Rep.hpp"

#include <assert.h>

template<template<class U> class T>
void run(int argc, const char** argv)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    PEOptions opts(opt, argc, argv);
//    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;
    Names N(opt, argc, argv,
            3 + is_same<T<P256Element>, Rep4Share<P256Element>>::value);

    CryptoPlayer P(N, "pc");

    P377Element::init();
    P377Element::Scalar::next::init_field(P377Element::Scalar::pr(), false);

    typedef T<P377Element::Scalar> inputShare;

    typename inputShare::mac_key_type input_mac_key;
    inputShare::read_or_generate_mac_key("", P, input_mac_key);

    ProtocolSet< inputShare> set(P, input_mac_key);

    typename inputShare::MAC_Check inputMCp(input_mac_key);

    typename T<P377Element>::Direct_MC inputMCc(inputMCp.get_alphai());
    eval_point<T>(set, inputMCc, P, opts);

    P377Element::finish();

}
