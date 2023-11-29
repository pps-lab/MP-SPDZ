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

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"
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

template<template<class U> class T>
void run(int argc, const char** argv)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    PCOptions opts(opt, argc, argv);
    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;
    Names N(opt, argc, argv,
            3 + is_same<T<P256Element>, Rep4Share<P256Element>>::value);

    CryptoPlayer P(N, "pc");



//    P256Element::init();
//    P377Element::init();
//    P377Element::Scalar::next::init_field(P377Element::Scalar::pr(), false);

    // TODO: adapt
    typedef Z2<64> input_type;
    typedef P377Element::Scalar output_type;
    typedef T<input_type> inputShare;
    typedef T<output_type > outputShare;

//    (void)input_type;
//    (void)output_type;

    // protocol setup (domain, MAC key if needed etc)
    libff::bls12_377_pp::init_public_params();
    mpz_t t;
    mpz_init(t);
    P377Element::G1::order().to_mpz(t);

    int prime_length = 128;
    MixedProtocolSetup<inputShare> setup_input(P, prime_length);
    MixedProtocolSet<inputShare> set_input(P, setup_input);

    ProtocolSetup<outputShare> setup_output(bigint(t), P);
    ProtocolSet<outputShare> set_output(P, setup_output);

    // TODO: compute how many bits we need
    OnlineOptions::singleton.batch_size = 2 * 1;
    DataPositions usage;

//    typename inputShare::mac_key_type input_mac_key;
//    inputShare::read_or_generate_mac_key("", P, input_mac_key);
//
//    typename inputShare::LivePrep input_prep(0, usage);
//    typename inputShare::MAC_Check input_MCp(input_mac_key);
//    typename T<input_type>::Direct_MC input_MCc(input_MCp.get_alphai());
//    ArithmeticProcessor _({}, 0);
//    SubProcessor<inputShare> input_proc(_, input_MCp, input_prep, P);

//    typename outputShare::mac_key_type output_mac_key;
//    outputShare::read_or_generate_mac_key("", P, output_mac_key);
//    typename outputShare::LivePrep output_prep(0, usage);
//    typename outputShare::MAC_Check output_MCp(output_mac_key);
//    typename T<output_type>::Direct_MC output_MCc(input_MCp.get_alphai());
//    ArithmeticProcessor _2({}, 0);
//    SubProcessor<outputShare> output_proc(_2, output_MCp, output_prep, P);

    // we want two sets of edabits, one for input type to bits and one for output type to bits
//    typename inputShare::bit_type bit_b;
//    inputShare bit_a;
//    input_prep.get_dabit(bit_a, bit_b);
    bool strict = true;
    int n_bits = 32;

//    std::cout << "Singleton " << BaseMachine::singleton << endl;

    // read inputs
    // buffer edabits
    // decompose, add bits to r, open,
    // compose

    edabitvec<inputShare> buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits);
    edabitvec<outputShare> buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits);
//
    std::cout << "bit_a: " << buffer_in.size() << std::endl;
    std::cout << "bit_b: " << buffer_out.size() << std::endl;
//
//
//    typedef T<P377Element::Scalar> inputShare;
//
//    typename inputShare::mac_key_type input_mac_key;
//    inputShare::read_or_generate_mac_key("", P, input_mac_key);
//    typename inputShare::MAC_Check inputMCp(input_mac_key);
//
//    typename T<P377Element>::Direct_MC inputMCc(inputMCp.get_alphai());
//    string message = auditable_inference<T>(inputMCc, P, opts);
//
////    inputShare::MAC_Check::teardown();
////    T<P377Element>::MAC_Check::teardown();
//    P377Element::finish();
//
//    // Signing
//    P256Element::init();
//    typedef T<P256Element::Scalar> pShare;
//    OnlineOptions::singleton.batch_size = 1;
//    // synchronize
//    Bundle<octetStream> bundle(P);
//    P.unchecked_broadcast(bundle);
//
//
//    Timer timer;
//    timer.start();
//    auto stats = P.total_comm();
//    ProtocolSet<typename T<P256Element::Scalar>::Honest> set(P, mac_key);
//    pShare sk = set.protocol.get_random();
//    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
//    (P.total_comm() - stats).print(true);
//
//    int n_signatures = 1;
//
//    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * n_signatures;
//    DataPositions usage;
//    typename pShare::TriplePrep prep(0, usage);
//    typename pShare::MAC_Check MCp(mac_key);
//    typename T<P256Element>::Direct_MC MCc(MCp.get_alphai());
//    ArithmeticProcessor _({}, 0);
//    SubProcessor<pShare> proc(_, MCp, prep, P);
//
//
//
//    P256Element pk = MCc.open(sk, P);
//    MCc.Check(P);
//
//    vector<EcTuple<T>> tuples;
//    preprocessing(tuples, n_signatures, sk, proc, opts);
//
//    bool prep_mul = not opt.isSet("-D");
//    auto sig = sign((const unsigned char *)message.c_str(), message.length(), tuples[0], MCp, MCc, P, opts, pk, sk, prep_mul ? 0 : &proc);
//
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
//
//    check(sig, (const unsigned char *)message.c_str(), message.length(), pk);

    P377Element::finish();
}
