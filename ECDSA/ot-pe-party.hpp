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
#include "Protocols/MascotPrep.hpp"
#include "Processor/Input.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"
#include "GC/Secret.hpp"

#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"

#include <assert.h>

template<template<class U> class T>
void run(int argc, const char** argv)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    PEOptions opts(opt, argc, argv);

    Names N(opt, argc, argv,
            2);

    CryptoPlayer P(N, "pc");

    libff::bls12_377_pp::init_public_params();
    mpz_t t;
    mpz_init(t);
    P377Element::G1::order().to_mpz(t);


    typedef T<P377Element::Scalar> inputShare;

    // TODO: this is fixed to BLS12
    string prefix = get_prep_sub_dir<inputShare>("Player-Data", 2, 253);
    std::cout << "Loading mac from " << prefix << endl;

    ProtocolSetup< inputShare > setup(bigint(t), P, prefix);
//    ProtocolSetup< inputShare > setup(bigint(t), P);
    ProtocolSet< inputShare> set(P, setup);

    OnlineOptions::singleton.batch_size = 1;

    std::cout << "Prime " << P377Element::Scalar::pr() << std::endl;

//    typename pShare::TriplePrep sk_prep(0, usage);
    // TODO here: fix so we actually sample a random point
//    inputShare beta_share = inputShare::constant(4757838273, P.my_num(), setup.get_mac_key());
    inputShare beta_share,__;

    P377Element::Scalar beta;
    if (opts.eval_point.length() > 0) {
        std::cout << "Evaluating at fixed point " << opts.eval_point << std::endl;
        beta = P377Element::Scalar(bigint(opts.eval_point));
        std::cout << "Parsed beta: " << beta << std::endl;
    } else {
        set.preprocessing.get_two(DATA_INVERSE, beta_share, __);
        set.output.init_open(P);
        set.output.prepare_open(beta_share);
        set.output.exchange(P);
        set.check();
        beta = set.output.finalize_open();
    }

    eval_point<T>(beta, set, P, opts);

    P377Element::finish();
}
