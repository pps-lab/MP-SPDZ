/*
 * fake-spdz-ecdsa-party.cpp
 *
 */

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"
#include "Protocols/SemiShare.h"
#include "Processor/BaseMachine.h"

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"
#include "ECDSA/poly_commit.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MascotPrep.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Input.hpp"
#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"
#include "ECDSA/auditable.hpp"

#include <assert.h>


//template<template<class U> class T>
//void get_poly_input(int n_parameters, typename T<P256Element::Scalar>::TriplePrep prep, Polynomial<T> *poly) {
//
//    // Polynomial input should not take any shares ?
//
//    for (int i = 0; i < n_parameters; i++)
//    {
//        // inefficient, uses a triple for each input!
//        T<P256Element::Scalar> k[3];
//        prep.get(DATA_TRIPLE, k);
//        poly->coeffs.push_back(k[0]);
//    }
//}




template<template<class U> class T>
void run(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    PCOptions opts(opt, argc, argv);
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use SimpleOT instead of OT extension", // Help description.
            "-S", // Flag token.
            "--simple-ot" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Don't check correlation in OT extension (only relevant with MASCOT)", // Help description.
            "-U", // Flag token.
            "--unchecked-correlation" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Fewer rounds for authentication (only relevant with MASCOT)", // Help description.
            "-A", // Flag token.
            "--auth-fewer-rounds" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use Fiat-Shamir for amplification (only relevant with MASCOT)", // Help description.
            "-H", // Flag token.
            "--fiat-shamir" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Skip sacrifice (only relevant with MASCOT)", // Help description.
            "-E", // Flag token.
            "--embrace-life" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "No MACs (only relevant with MASCOT; implies skipping MAC checks)", // Help description.
            "-M", // Flag token.
            "--no-macs" // Flag token.
    );

    Names N(opt, argc, argv, 2);

    PlainPlayer P(N, "pc");
    P256Element::init();
    P256Element::Scalar::next::init_field(P256Element::Scalar::pr(), false);

    P256Element::Scalar keyp;
    SeededPRNG G;
    keyp.randomize(G);

    typedef T<P256Element::Scalar> pShare;
    DataPositions usage;

    pShare::MAC_Check::setup(P);
    T<P256Element>::MAC_Check::setup(P);

    OnlineOptions::singleton.batch_size = 1;
    typename pShare::Direct_MC MCp(keyp);
    ArithmeticProcessor _({}, 0);
    typename pShare::TriplePrep sk_prep(0, usage);
    SubProcessor<pShare> sk_proc(_, MCp, sk_prep, P);
    pShare sk, __;
    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    sk_prep.get_two(DATA_INVERSE, sk, __);
    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    // Calculation: 1 + 1 triple per signature
    int n_signatures = 1;

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * n_signatures;
    typename pShare::TriplePrep prep(0, usage);
    prep.params.correlation_check &= not opt.isSet("-U");
    prep.params.fewer_rounds = opt.isSet("-A");
    prep.params.fiat_shamir = opt.isSet("-H");
    prep.params.check = not opt.isSet("-E");
    prep.params.generateMACs = not opt.isSet("-M");
    opts.check_beaver_open &= prep.params.generateMACs;
    opts.check_open &= prep.params.generateMACs;
    SubProcessor<pShare> proc(_, MCp, prep, P);
    typename pShare::prep_type::Direct_MC MCpp(keyp);
    prep.triple_generator->MC = &MCpp;

    prep.params.use_extension = not opt.isSet("-S");

//    Polynomial<T> poly;
//    get_poly_input<T>(n_parameters, prep, &poly);

//    Polynomial<T> poly;
//    for (int i = 0; i < n_parameters; i++)
//    {
//        // inefficient, uses a triple for each input!
//        T<P256Element::Scalar> k[3];
//        prep.get(DATA_TRIPLE, k);
//        poly.coeffs.push_back(k[0]);
//    }


    // Maybe here: read poly coeffs from secret shares insta
//    vector<> dvec;
//    sk_proc.Proc.read_shares_from_file(0, 100, dvec);

    typename T<P256Element>::Direct_MC MCc(MCp.get_alphai());
    auditable_inference<T>(MCc, P, opts, prep);
//    preprocessing(tuples, n_tuples, sk, proc, opts);
//    sign_benchmark(tuples, sk, MCp, P, opts, prep_mul ? 0 : &proc);

    pShare::MAC_Check::teardown();
    T<P256Element>::MAC_Check::teardown();
    P256Element::finish();
}
