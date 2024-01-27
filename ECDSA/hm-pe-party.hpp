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

template<class inputShare>
void run(int argc, const char** argv, bigint prime_length)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    PEOptions opts(opt, argc, argv);

    const int n_parties = 3;
    Names N(opt, argc, argv,
            n_parties);


    CryptoPlayer P(N, "pc");

//    libff::bls12_377_pp::init_public_params();
//    mpz_t t;
//    mpz_init(t);
//    P377Element::G1::order().to_mpz(t);

    std::cout << "Prime " << inputShare::clear::pr() << std::endl;

    string prefix = get_prep_sub_dir<inputShare>("Player-Data", n_parties, inputShare::clear::length());
    std::cout << "Loading mac from " << prefix << endl;

    ProtocolSetup< inputShare > setup(prime_length, P, prefix);
//    ProtocolSetup< inputShare > setup(bigint(t), P);
    ProtocolSet< inputShare> set(P, setup);
//    inputShare::clear::init_field(bigint(t));
//    inputShare::clear::next::init_field(bigint(t), false);


//    beta = P377Element::Scalar(bigint("6578911705820052831726078019867999857858229676316950877123218490548071891330"));

    typename inputShare::clear beta;
    if (opts.eval_point.length() > 0) {
        std::cout << "Evaluating at fixed point " << opts.eval_point << std::endl;
        beta = P377Element::Scalar(bigint(opts.eval_point));
        std::cout << "Parsed beta: " << beta << std::endl;
    } else {
        inputShare beta_share = set.protocol.get_random();
        set.output.init_open(P);
        set.output.prepare_open(beta_share);
        set.output.exchange(P);
        set.check();
        beta = set.output.finalize_open();
    }

    eval_point<inputShare>(beta, set, P, opts);

}

template<template<class T> class share>
void run(int argc, const char** argv) {
    ez::ezOptionParser opt;
    PEOptions opts(opt, argc, argv);

    if (opts.curve == "bls12377") {
        libff::bls12_377_pp::init_public_params();
        mpz_t t;
        mpz_init(t);
        P377Element::G1::order().to_mpz(t);
        bigint t_big(t);

        run<share<P377Element::Scalar>>(argc, argv, t_big);

        P377Element::finish();
    } else if (opts.curve == "sec256k1") {

        P256Element::init(false);

        bigint order = P256Element::get_order();
        run<share<P256Element::Scalar>>(argc, argv, order);

        P256Element::finish();
    } else {
        std::cerr << "Unknown curve " << opts.curve << endl;
        exit(1);
    }
}
