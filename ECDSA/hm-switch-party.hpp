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
#include "ECDSA/share_utils.hpp"
#include "ECDSA/SwitchOptions.h"

#include <assert.h>

template<class inputShare, class outputShare>
vector<outputShare> convert_shares(vector<inputShare>& input_shares,
                                   MixedProtocolSet<inputShare>& set_input,
                                   ProtocolSet<outputShare>& set_output,
                                   typename inputShare::bit_type::mac_key_type binary_mac_key,
                                   Player &P, const int prime_length) {
    const bool debug = false;

    // for now we need to use all the bits;
    const int input_size = input_shares.size();
    int n_bits_per_input = prime_length;

    bool strict = true;

//    std::cout << "Singleton " << BaseMachine::singleton << endl;

    // read inputs
    // buffer edabits
    // decompose, add bits to r, open,
    // compose

    DataPositions usage;
    OnlineOptions::singleton.batch_size = input_size;

//    edabitvec<inputShare> buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
//    edabitvec<outputShare> buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
////
//    std::cout << "bit_a: " << buffer_in.size() << std::endl;
//    std::cout << "bit_b: " << buffer_out.size() << std::endl;
//    std::cout << "max " << edabitvec<inputShare>::MAX_SIZE << std::endl;
//    std::cout << "buffer size " << set_input.protocol.get_buffer_size() << endl;

//    const int n_edabit_buffers_needed = DIV_CEIL(input_size, edabitvec<inputShare>::MAX_SIZE);
//    vector<edabitvec<inputShare> > buffer_in(n_edabit_buffers_needed);
//    vector<edabitvec<outputShare> > buffer_out(n_edabit_buffers_needed);
//    for (int i = 0; i < n_edabit_buffers_needed; i++) {
//        buffer_in[i] = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
//        buffer_out[i] = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
//    }
//    std::cout << "Buffered " << 2 * n_edabit_buffers_needed * edabitvec<inputShare>::MAX_SIZE << " edabits" << std::endl;
//    std::cout << "Total edabits " << set_input.preprocessing.proc->DataF.usage.total_edabits(n_bits_per_input) << endl;
//    std::cout << "Total edabits out " << set_output.preprocessing.proc->DataF.usage.total_edabits(n_bits_per_input) << endl;


    Timer timer_all;
    timer_all.start();
    auto overall_stats = P.total_comm();

    Timer timer_edabit_mask;
    timer_edabit_mask.start();
    auto edabit_stats = P.total_comm();

    vector<edabit<inputShare> > edabits_in;
    vector<edabit<outputShare> > edabits_out;

    edabitvec<inputShare> buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
    edabitvec<outputShare> buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);

    std::cout << buffer_in.size() << " " << buffer_in.get_b(0).size() << endl;
    // open for debug
    vector<typename inputShare::clear> reals;
    if (debug) {
        set_input.output.init_open(P, input_size);
        for (size_t i = 0; i < input_shares.size(); i++) {
            inputShare c = input_shares[i];
            set_input.output.prepare_open(c);
        }
        set_input.output.exchange(P);
        for (int i = 0; i < input_size; i++) {
            typename inputShare::clear c = set_input.output.finalize_open();
            reals.push_back(c);
        }
        std::cout << "input_1" << " = " << reals[1] << endl;
    }
    // end debug

    set_input.output.init_open(P, input_size);
    for (size_t i = 0; i < input_shares.size(); i++) {
        if (buffer_in.empty()) {
            buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
        }
        if (buffer_out.empty()) {
            std::cout << "empty filling" << endl;
            buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
        }
        auto edabit_in = buffer_in.next();
        auto edabit_out = buffer_out.next();
        edabits_in.push_back(edabit_in);

        edabits_out.push_back(edabit_out);

        inputShare c = input_shares[i] - edabit_in.first;

        set_input.output.prepare_open(c);
    }

    cout << "Generating " << 2 * input_size << " edabits " << timer_edabit_mask.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - edabit_stats).print(true);

    Timer timer_open_c;
    timer_open_c.start();
    auto stats = P.total_comm();

    set_input.output.exchange(P);
    set_input.check();

    cout << "Opening " << input_size << " masked input values " << timer_open_c.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    vector<typename inputShare::clear> cs;
    for (int i = 0; i < input_size; i++) {
        typename inputShare::clear c = set_input.output.finalize_open();
        cs.push_back(c);
    }

    int dl = inputShare::clear::MAX_EDABITS;
    int buffer_size = edabitvec<inputShare>::MAX_SIZE;
    (void)buffer_size;

    typedef typename inputShare::bit_type bt;

    Timer timer_adders;
    timer_adders.start();
    stats = P.total_comm();

    BitAdder bit_adder;
    // dim 0: n_bits, dim 1: (x,y), dim 2; element?
    vector<vector<vector<bt> > > summands_one(n_bits_per_input, vector<vector<bt> >(2, vector<bt>(input_size)));
    vector<vector<bt>> sums_one(input_size);
    for (int i = 0; i < n_bits_per_input; i++) {
        for (int j = 0; j < input_size; j++) {
            summands_one[i][0][j] = bt::constant(Integer(bigint(cs[j])).get_bit(i), P.my_num(), binary_mac_key);
            summands_one[i][1][j] = edabits_in[j].second[i];
        }
    }

    // TODO: Fix this OOM issue, its likely released when this gets deconstructed
    typename bt::LivePrep bit_prep(usage);
    SubProcessor<bt> bit_proc(set_input.binary.thread.MC->get_part_MC(), bit_prep, P);
    int begin = 0;
    int end = input_size;
    bit_adder.add(sums_one, summands_one, begin, end, bit_proc,
                  dl, 0);

    // Now we add the second masking bits
    vector<vector<vector<bt> > > summands_two(n_bits_per_input, vector<vector<bt> >(2, vector<bt>(input_size)));
    for (int i = 0; i < n_bits_per_input; i++) {
        for (int j = 0; j < input_size; j++) {
//            std::cout << "numbits " << i << " " << j << ": " << bigint(cs[j]) << " " << Integer(bigint(cs[j])).get_bit(i) << endl;
            summands_two[i][0][j] = sums_one[j][i];
            summands_two[i][1][j] = edabits_out[j].second[i];
        }
    }
    vector<vector<bt>> sums_two(input_size);
    bit_adder.add(sums_two, summands_two, begin, end, bit_proc,
                  bt::default_length, 0);

    cout << "Adding " << input_size * n_bits_per_input << " bits: " << timer_adders.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);


//    // now we open each bit
    if (debug) {
//        set_input.binary.output.init_open(P, n_bits_per_input * input_size);
//        for (int i = 0; i < n_bits_per_input; i++) {
//            for (int j = 0; j < input_size; j++) {
//                set_input.binary.output.prepare_open(sums_one[j][i]);
//            }
//        }
//        set_input.binary.output.exchange(P);
//
//        vector <vector<typename bt::clear>> open_bits(n_bits_per_input, vector<typename bt::clear>(input_size));
//        std::cout << "open bits type " << typeid(open_bits).name() << endl;
//        for (int i = 0; i < (int) n_bits_per_input; i++) {
//            for (int j = 0; j < (int) input_size; j++) {
//                open_bits[i][j] = set_input.binary.output.finalize_open();
//            }
//        }
//        for (int i = 0; i < (int) input_size; i++) {
//            std::cout << open_bits[0][i].get_bit(0) << " ";
//            std::cout << n_bits_per_input << " Number " << cs[i]
//                      << " has bits (these should be the original, unmasked value): ";
//            for (int j = 0; j < (int) n_bits_per_input; j++) {
////            std::cout << " j" << j << " " << open_bits[n_bits_per_input - j - 1][i].get_bit(0);
//                std::cout << open_bits[n_bits_per_input - j - 1][i].get_bit(0);
//            }
//            std::cout << endl;
//        }
    }

    Timer timer_bits;
    timer_bits.start();
    stats = P.total_comm();

    set_input.binary.output.init_open(P, n_bits_per_input * input_size);
    for (int i = 0; i < (int)n_bits_per_input; i++) {
        for (int j = 0; j < (int)input_size; j++) {
            set_input.binary.output.prepare_open(sums_two[j][i]);
        }
    }
    set_input.binary.output.exchange(P);
    vector< typename outputShare::clear > open_mask(input_size);

//    std::cout << open_bits[0][0].get_bit(0) << " open " << open_bits[1][0].get_bit(0) << endl;
//    std::cout << open_bits[0][2].get_bit(0) << " open " << open_bits[1][2].get_bit(0) << endl;

    vector<vector<bool> > open_bits_bool(n_bits_per_input, vector<bool>(input_size));

    // now we compose the bits into a c_prime of type output_type
    for (int i = 0; i < (int)n_bits_per_input; i++) {
        for (int j = 0; j < (int)input_size; j++) {
            auto bv = set_input.binary.output.finalize_open();
            open_mask[j] = open_mask[j] | typename outputShare::clear(bv.get_bit(0)) << i;
//            open_bits[i][j].xor_bit(bv.get_bit(0));
            open_bits_bool[i][j] = bv.get_bit(0);
        }
    }

    cout << "Opening " << input_size * n_bits_per_input << " masked bits: " << timer_bits.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    // now everyone subtracts c_prime from the mask
    vector<outputShare > result;
    for (int i = 0; i < (int)input_size; i++) {
//        std::cout << open_mask[i] << " ";
//        for (int j = 0; j < (int)n_bits_per_input; j++) {
//            std::cout << open_bits_bool[n_bits_per_input - j - 1][i];
//        }
//        cout << std::endl;
//        result.push_back(outputShare::constant(open_mask[i], P.my_num()) - edabits_out[i].first);
        result.push_back(outputShare::constant(open_mask[i], P.my_num()) - edabits_out[i].first);
    }

    // open for debug
    if (debug) {
        set_output.output.init_open(P, input_size);
        for (unsigned long i = 0; i < result.size(); i++) {
            outputShare c = result[i];
            set_output.output.prepare_open(c);
        }
        set_output.output.exchange(P);
        vector <outputShare> outputs;
        for (int i = 0; i < input_size; i++) {
            typename outputShare::clear c = set_output.output.finalize_open();
            if (debug)
                assert(c == reals[i]);
            outputs.push_back(c);
        }
        std::cout << "output_1" << " = " << outputs[1] << endl;
    }
    // end debug

    cout << "Overall conversion of " << input_size << " input values " << timer_all.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - overall_stats).print(true);

    return result;
}

template<class inputShare, class outputShare>
void run(int argc, const char** argv)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    SwitchOptions opts(opt, argc, argv);
//    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;
    Names N(opt, argc, argv, 3);

    assert(opts.n_shares > 0);
    CryptoPlayer P(N, "pc");

    // protocol setup (domain, MAC key if needed etc)
    libff::bls12_377_pp::init_public_params();
    mpz_t t;
    mpz_init(t);
    P377Element::G1::order().to_mpz(t);

    int prime_length = 64;
    MixedProtocolSetup<inputShare> setup_input(P, prime_length);
    MixedProtocolSet<inputShare> set_input(P, setup_input);

    ProtocolSetup<outputShare> setup_output(bigint(t), P);
    ProtocolSet<outputShare> set_output(P, setup_output);

    vector<inputShare> input_shares = read_inputs<inputShare>(P, opts.n_shares);

    vector<outputShare> result = convert_shares(input_shares, set_input, set_output, setup_input.binary.get_mac_key(), P, prime_length);

    std::cout << "Share 0 " << result[0] << std::endl;

    write_shares<outputShare>(P, result, KZG_SUFFIX, true);

    vector<outputShare> check_shares = read_inputs<outputShare>(P, 2, KZG_SUFFIX);

    std::cout << "Share 0 after reading " << check_shares[0] << std::endl;
    std::cout << "Prime " << P377Element::Scalar::pr() << std::endl;

    P377Element::finish();
}
