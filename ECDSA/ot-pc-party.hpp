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
#include "Protocols/ProtocolSet.h"

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
#include "ECDSA/P377Element.h"

#include <assert.h>


//template<template<class U> class T>
//void get_poly_input(int n_parameters, typename T<P256Element::Scalar>::TriplePrep prep, InputPolynomial<T> *poly) {
//
//    // InputPolynomial input should not take any shares ?
//
//    for (int i = 0; i < n_parameters; i++)
//    {
//        // inefficient, uses a triple for each input!
//        T<P256Element::Scalar> k[3];
//        prep.get(DATA_TRIPLE, k);
//        poly->coeffs.push_back(k[0]);
//    }
//}

// Ugly copies of classes because the share type abstraction doesnt work perfectly
template<class Curve>
std::vector<Share<Curve>> commit_individual(
        InputPolynomial<Share<typename Curve::Scalar>> tuple,
        std::vector<Share<typename Curve::Scalar>> randomness,
        ECPublicParameters<Curve> kzgPublicParameters)
{
    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());
    assert(tuple.coeffs.size() == randomness.size());

    Timer msm_timer;
    msm_timer.start();

    std::vector<Share<Curve>> result;
    for (unsigned long i = 0; i < tuple.coeffs.size(); i++) {
        Share<Curve> result_g;
        ecscalarmulshare(kzgPublicParameters.powers_of_g[0], tuple.coeffs[i], result_g);
        Share<Curve> result_h;
        ecscalarmulshare(kzgPublicParameters.powers_of_g[1], randomness[i], result_h);

        result.push_back(result_g + result_h);
    }

    auto diff_msm = msm_timer.elapsed();
    cout << "Exponentiation took " << diff_msm * 1e3 << " ms" << endl;
    // optimize with MSM

    return result;
}

template<class Curve>
std::vector<SemiShare<Curve>> commit_individual(
        InputPolynomial<SemiShare<typename Curve::Scalar>> tuple,
        std::vector<SemiShare<typename Curve::Scalar>> randomness,
        ECPublicParameters<Curve> kzgPublicParameters)
{
    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());
    assert(tuple.coeffs.size() == randomness.size());

    Timer msm_timer;
    msm_timer.start();

    std::vector<SemiShare<Curve>> result;
    for (unsigned long i = 0; i < tuple.coeffs.size(); i++) {
        SemiShare<Curve> result_g = kzgPublicParameters.powers_of_g[0] * tuple.coeffs[i];
//        ecscalarmulshare(kzgPublicParameters.powers_of_g[0], tuple.coeffs[i], result_g);
        SemiShare<Curve> result_h = kzgPublicParameters.powers_of_g[1] * randomness[i];
//        ecscalarmulshare(kzgPublicParameters.powers_of_g[1], randomness[i], result_h);

        result.push_back(result_g + result_h);
    }

    auto diff_msm = msm_timer.elapsed();
    cout << "Exponentiation took " << diff_msm * 1e3 << " ms" << endl;
    // optimize with MSM

    return result;
}


void test_arith() {

    P377Element::Scalar a = P377Element::Scalar(bigint("27742317777372353535851937790883648493"));
    P377Element gen = P377Element();

    cout << "a " << a << endl;
    cout << "gen " << gen << endl;
    cout << "a * gen " << a * gen << endl;

    SeededPRNG G;
    P377Element::Scalar r_scalar;
    r_scalar.randomize(G);
    P377Element ran = P377Element(r_scalar);

    cout << "ran " << ran << endl;
    cout << "a * ran " << a * ran << endl;

    P377Element::Scalar s_scalar;
    s_scalar.randomize(G);
    P377Element s_elem = P377Element(s_scalar);

    P377Element sum_elem = P377Element(r_scalar + s_scalar);
    cout << "sum_elem " << sum_elem << endl;

    cout << ((ran + s_elem) == sum_elem) << endl;
}


template<template<class U> class T, class Curve>
void run(int argc, const char** argv, bigint order)
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

//    typedef T<P377Element::Scalar> inputShare;
//    string prefix = get_prep_sub_dir<inputShare>("Player-Data", 2, inputShare::clear::length());
//    std::cout << "Loading mac from " << prefix << endl;


//    libff::bls12_377_pp::init_public_params();
//    mpz_t t;
//    mpz_init(t);
//    P377Element::G1::order().to_mpz(t);
//
//    P377Element::Scalar::init_field(bigint(t), true);
//    if (opts.prime.length() > 0) {
//        P377Element::Scalar::next::init_field(bigint(opts.prime), false);
//        std::cout << "Setting prime to " << bigint(opts.prime) << endl;
//    } else {
//        P377Element::Scalar::next::init_field(P377Element::Scalar::pr(), false);
//    }
//    std::cout << "Prime length " << P377Element::Scalar::pr() << endl;
////    test_arith();
    DataPositions usage;


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

    std::cout<< "Signing now" << std::endl;

//    string message = "Hello";
    // Now onto signing
    P256Element::init();
    P256Element::Scalar::next::init_field(P256Element::Scalar::pr(), false);

    P256Element::Scalar keyp;
    SeededPRNG G;
    keyp.randomize(G);

    // p256 domain
    typedef T<P256Element::Scalar> pShare;
    pShare::MAC_Check::setup(P);
    T<P256Element>::MAC_Check::setup(P);

    // Load secret key into share
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


    auto diff_sk = P.total_comm() - stats;
    print_timer("sign_sk", timer.elapsed());
    print_stat("sign_sk", diff_sk);
    print_global("sign_sk", P, diff_sk);

    Timer timer_sign;
    timer_sign.start();
    auto stats_sign = P.total_comm();

    // Calculation: 1 + 1 triple per signature
    int n_signatures = 1;

    typename T<P256Element>::Direct_MC MCc(MCp.get_alphai());

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

    P256Element pk = MCc.open(sk, P);
    MCc.Check(P);

    vector<EcTuple<T>> tuples;
    preprocessing(tuples, n_signatures, sk, proc, opts);

    bool prep_mul = not opt.isSet("-D");
    auto sig = sign((const unsigned char *)message.c_str(), message.length(), tuples[0], MCp, MCc, P, opts, pk, sk, prep_mul ? 0 : &proc);

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

    check(sig, (const unsigned char *)message.c_str(), message.length(), pk);

//    pShare::MAC_Check::teardown();
//    T<P256Element>::MAC_Check::teardown();

    P256Element::finish();
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
//        P256Element::init(false);
//
//        bigint order = P256Element::get_order();
//        run<share, P256Element>(argc, argv, order);

        exit(1); // not implemented yet

    } else {
        std::cerr << "Unknown curve " << opts.curve << endl;
        exit(1);
    }

    P256Element::finish();
}


