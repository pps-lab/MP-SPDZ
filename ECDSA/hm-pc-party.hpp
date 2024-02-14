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

#include "ECDSA/auditable.hpp"
#include "ECDSA/P377Element.h"
#include "ECDSA/poly_commit.hpp"

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



//// Function for Scalar multiplication of a clear p256 and a shared gfp
template<>
void ecscalarmulshare(P377Element point, MaliciousRep3Share<P377Element::Scalar> multiplierShare, MaliciousRep3Share<P377Element>& result){

    // This is ugly and specific for Rep3Share!!
    // We need: for each share in multiplierShare, get the value, multiply with point
    const array<P377Element::Scalar, 2>& shares = multiplierShare.get();
    array<P377Element, 2> result_shares;
    for (int i = 0; i < 2; i++) {
        P377Element::Scalar share = shares[i];
        P377Element result_share = point * share;
        result_shares[i] = result_share;
    }

    result = MaliciousRep3Share<P377Element>(result_shares);
}




template<template <class U> class T, class Curve>
void run(int argc, const char** argv, bigint order)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    PCOptions opts(opt, argc, argv);
//    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;
    opts.R_after_msg = false;
    Names N(opt, argc, argv,
            3);

    CryptoPlayer P(N, "pc");

    string message;
    if (opts.n_y == 0 && opts.n_x == 0 && opts.n_model == 0) {
        std::cout << "No inputs found, only signing!" << std::endl;
        message = "Related work commitment";
    } else {
        typedef T<typename Curve::Scalar> inputShare;

        string prefix = get_prep_sub_dir<inputShare>("Player-Data", 3, inputShare::clear::length());
        std::cout << "Loading mac from " << prefix << endl;
        ProtocolSetup< inputShare > setup(order, P, prefix);
        ProtocolSet< inputShare> set(P, setup);

        Timer timer_all;
        timer_all.start();
        auto stats_all = P.total_comm();

        typename inputShare::mac_key_type input_mac_key;
        inputShare::read_or_generate_mac_key("", P, input_mac_key);
        typename inputShare::MAC_Check inputMCp(input_mac_key);

        typename T<Curve>::Direct_MC inputMCc(inputMCp.get_alphai());
        if (opts.commit_type == "ec_vec") {
            message = generate_vector_commitments<T, Curve, ECVectorCommitment>(inputMCc, P, opts);
        } else if (opts.commit_type == "ec_individual") {
            message = generate_individual_commitments<T, Curve>(inputMCc, set, P, opts);
        }

        auto diff_all = P.total_comm() - stats_all;
        print_timer("commit_with_gen", timer_all.elapsed());
        print_stat("commit_with_gen", diff_all);
        print_global("commit_with_gen", P, diff_all);
    }

//    std::cout << "Message: " << message << endl;

    // Signing
    P256Element::init();
    typedef T<P256Element::Scalar> pShare;
    OnlineOptions::singleton.batch_size = 1;
    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);

    typename pShare::mac_key_type mac_key;
    pShare::read_or_generate_mac_key("", P, mac_key);

    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    ProtocolSet<typename T<P256Element::Scalar>::Honest> set(P, mac_key);
    pShare sk = set.protocol.get_random();
    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
//    (P.total_comm() - stats).print(true);

    auto diff_sk = P.total_comm() - stats;
    print_timer("sign_sk", timer.elapsed());
    print_stat("sign_sk", diff_sk);
    print_global("sign_sk", P, diff_sk);

    Timer timer_sign;
    timer_sign.start();
    auto stats_sign = P.total_comm();

    int n_signatures = 1;

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * n_signatures;
    DataPositions usage;
    typename pShare::TriplePrep prep(0, usage);
    typename pShare::MAC_Check MCp(mac_key);
    typename T<P256Element>::Direct_MC MCc(MCp.get_alphai());
    ArithmeticProcessor _({}, 0);
    SubProcessor<pShare> proc(_, MCp, prep, P);

    P256Element pk = MCc.open(sk, P);
    MCc.Check(P);

    vector<EcTuple<T>> tuples;
    preprocessing(tuples, n_signatures, sk, proc, opts);

    bool prep_mul = not opt.isSet("-D");
    auto sig = sign((const unsigned char *)message.c_str(), message.length(), tuples[0], MCp, MCc, P, opts, pk, sk, prep_mul ? 0 : &proc);

    std::cout << " " << sig.R << " " << sig.s << endl;
    // No online checking!
//    Timer timer_sig;
//    timer_sig.start();
//    auto& check_player = MCp.get_check_player(P);
//    stats = check_player.total_comm();
//    MCp.Check(P);
//    MCc.Check(P);
//    auto diff = (check_player.total_comm() - stats);
//    cout << "Online checking took " << timer_sig.elapsed() * 1e3 << " ms and sending "
//         << diff.sent << " bytes" << endl;
//    diff.print();

    auto diff_sign = P.total_comm() - stats_sign;
    print_timer("sign", timer_sign.elapsed());
    print_stat("sign", diff_sign);
    print_global("sign", P, diff_sign);

    // we dont have to check the sig because its validity implies correctness.
    MCp.Check(P);
    MCc.Check(P);

    check(sig, (const unsigned char *)message.c_str(), message.length(), pk);
}

template<template<class T> class share>
void run(int argc, const char** argv) {
    ez::ezOptionParser opt;
    PCOptions opts(opt, argc, argv);


    if (opts.curve == "bls12377") {
        P256Element::init(true);

        libff::bls12_377_pp::init_public_params();
        mpz_t t;
        mpz_init(t);
        P377Element::G1::order().to_mpz(t);
        bigint t_big(t);

        run<share, P377Element>(argc, argv, t_big);

        P377Element::finish();
    } else if (opts.curve == "sec256k1") {
        P256Element::init(false);

        bigint order = P256Element::get_order();
        run<share, P256Element>(argc, argv, order);

    } else {
        std::cerr << "Unknown curve " << opts.curve << endl;
        exit(1);
    }

    P256Element::finish();
}

