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

#include "omp.h"

#include <assert.h>

template<class inputShare, class outputShare>
vector<outputShare> compose_shares(const vector<vector<typename inputShare::bit_type::part_type>> sums_one,
                                   const int input_size,
                                   SubProcessor<typename inputShare::bit_type::part_type>& bit_proc,
                                   MixedProtocolSet<inputShare>& set_input,
                                   ProtocolSet<outputShare>& set_output,
                                   typename outputShare::mac_key_type out_arithmetic_mac_key,
                                   Player &P, const int n_bits_per_input,
                                   const typename inputShare::clear shift_int_t,
                                   const typename outputShare::clear shift_out_t,
                                   const bool debug,
                                   vector<typename inputShare::clear> reals, // potential debug symbols
                                   vector<typename inputShare::clear> cs_debug) {

    BitAdder bit_adder;
    typedef typename inputShare::bit_type bt;
    typedef typename inputShare::bit_type::part_type BT;
    const int dl = BT::default_length;
    const int buffer_size = sums_one.size() * dl;
    const bool strict = true;
    const int bit_overflow_two = 1;
    const outputShare shift_out_share = outputShare::constant(shift_out_t, P.my_num(), out_arithmetic_mac_key);

    auto stats = P.total_comm();

    // Now we are at output
//    std::cout << "Composing bits " << buffer_size << std::endl;

    // rewrite the above loop
    vector <outputShare> edabits_out_a;
    edabitvec <outputShare> buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
    vector<vector<vector<BT> > > summands_two(n_bits_per_input, vector<vector<BT> >(2, vector<BT>(buffer_size / dl)));

    for (int j = 0; j < buffer_size / dl; j++) {
        for (int i = 0; i < n_bits_per_input; i++) {
            summands_two[i][0][j] = sums_one[j][i];
        }
    }

    for (int j = 0; j < input_size; j++) {
        if (buffer_out.empty()) {
            buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
        }
        auto edabit_out = buffer_out.next();
        edabits_out_a.push_back(edabit_out.first);
//        std::cout << "Edabit with shift " << j % dl << ": " << (edabit_out.second[0] << j % dl) << endl;
        for (int i = 0; i < n_bits_per_input; i++) {
            // set the j / dl'th chunk with edabit_out bit
//            std::cout << "Set " << j / dl << " with edabit shifted by " << j % dl << " " << (BT(edabit_out.second[i]) << (j % dl)) << endl;
//            summands_two[i][1][j / dl] ^= (BT(edabit_out.second[i]) << (j % dl));
//            summands_two[i][1][j / dl] = summands_two[i][1][j / dl] | (BT(1) << (j % dl));
//            if (j % dl == 0)
//                summands_two[i][1][j / dl] = {};
            summands_two[i][1][j / dl].xor_bit(j % dl, edabit_out.second[i]);
        }
    }

    vector<vector<BT>> sums_two(buffer_size / dl);

    int begin = 0;
    int end = buffer_size / dl;

//    (P.total_comm() - stats).print(true);
//    stats = P.total_comm();
//    std::cerr << "Now sum " << std::endl;
    bit_adder.add(sums_two, summands_two, begin, end, bit_proc,
                  bt::default_length, 0);

//    (P.total_comm() - stats).print(true);
//    stats = P.total_comm();
//    std::cerr << "After sum" << endl;

//    Timer timer_bits;
//    timer_bits.start();


    set_input.binary.output.init_open(P, (n_bits_per_input + bit_overflow_two) * buffer_size / dl);
    for (int i = 0; i < (int)n_bits_per_input + bit_overflow_two; i++) {
        for (int j = 0; j < (int)buffer_size / dl; j++) {
            set_input.binary.output.prepare_open(sums_two[j][i], dl);
        }
    }
    set_input.binary.output.exchange(P);
    set_input.binary.check();

    vector< typename outputShare::clear > open_mask(input_size);

//    std::cout << open_bits[0][0].get_bit(0) << " open " << open_bits[1][0].get_bit(0) << endl;
//    std::cout << open_bits[0][2].get_bit(0) << " open " << open_bits[1][2].get_bit(0) << endl;

    vector<vector<bool> > open_bits_bool(n_bits_per_input + bit_overflow_two, vector<bool>(input_size));
    vector <vector<typename bt::clear>> open_bits_res(n_bits_per_input + bit_overflow_two, vector<typename bt::clear>(buffer_size / dl));

    // now we compose the bits into a c_prime of type output_type
    for (int i = 0; i < (int)n_bits_per_input + bit_overflow_two; i++) {
        for (int j = 0; j < (int)buffer_size / dl; j++) {
            open_bits_res[i][j] = set_input.binary.output.finalize_open();
        }
    }
    for (int i = 0; i < (int) input_size; i++) {
//        cout << "Bits " << i << " ";
        for (int j = 0; j < (int) n_bits_per_input + bit_overflow_two; j++) {
            // get the bits from open_bits[(n_bits_per_input) - j - 1] but from the right chunk of size dl
            bool bit_result = open_bits_res[(n_bits_per_input + bit_overflow_two) - j - 1][i / dl].get_bit(i % dl);
            open_mask[i] = open_mask[i] | typename outputShare::clear(bit_result) << ((n_bits_per_input + bit_overflow_two) - j - 1);
            open_bits_bool[j][i] = bit_result;
//            std::cout << bit_result;
        }
//        std::cout << " mask: " << open_mask[i];
//        cout << std::endl;
    }


//    cout << "Opening " << input_size * n_bits_per_input << " masked bits: " << timer_bits.elapsed() * 1e3 << " ms" << endl;
//    (P.total_comm() - stats).print(true);

    // now everyone subtracts c_prime from the mask

    vector<outputShare > result;
    for (int i = 0; i < (int)input_size; i++) {
        result.push_back(outputShare::constant(open_mask[i], P.my_num(), out_arithmetic_mac_key) - shift_out_share - edabits_out_a[i]);
//        result.push_back(outputShare::constant(open_mask[i], P.my_num(), out_arithmetic_mac_key) - shift_out_share); // X

    }

    (void)shift_out_share;
    (void)shift_out_t;

    // open for debug
    if (debug) {
        set_output.output.init_open(P, input_size);
        for (unsigned long i = 0; i < result.size(); i++) {
            outputShare c = result[i];
            set_output.output.prepare_open(c);
        }
        set_output.output.exchange(P);
        set_output.check();
        vector <typename outputShare::clear> outputs;
        for (int i = 0; i < input_size; i++) {
            typename outputShare::clear c = set_output.output.finalize_open();
            if (debug) {
//                if (bigint(c) != bigint(reals[i])) {
                if (bigint(typename outputShare::clear(bigint(c + shift_out_t) - bigint(reals[i] + shift_int_t))) != 0) {
//                auto str1 = to_string(bigint(c));
//                auto str2 = to_string(bigint(reals[i]));
//                if (str1 != str2) {
                    //                    std::cout << reals[i] << " " << c << reals[i] - c << std::endl;
//                    std::cout << bigint(c).get_str(2) << " != "
//                              << bigint(typename inputShare::clear(reals[i])).get_str(2)
//                              << std::endl; //base 2 representation
//
//                    std::cout << "Error: " << i << " " << bigint(c) << " != " << bigint(reals[i]) << endl;

//                    std::cout << "What I want: " << bigint(typename outputShare::clear(reals[i])).get_str(2) << " ("
//                              << bigint(typename outputShare::clear(reals[i])) << ")" << endl;
//                    std::cout << "What I have: " << bigint(c).get_str(2) << endl;
// it may be that some of these comparison outputs are invalid now because we switch to bigint
                    std::cout << c << " !=  "<< reals[i] << " Need shift   " << bigint(typename outputShare::clear(bigint(c + shift_out_t) - bigint(reals[i] + shift_int_t))).get_str(2) << "(" << typename outputShare::clear(bigint(c + shift_out_t) - bigint(reals[i] + shift_int_t)) << ")" << endl;
                    std::cout << bigint(c) << " !=bg " << bigint(reals[i]) << endl;
//                    std::cout << str1 << " !=st " << str2 << endl;
                    std::cout << "Bits were " << open_mask[i] << endl;
                    std::cout << "Masked open" << cs_debug[i] << endl;
                    std::cout << "Masking was " << edabits_out_a[i] << endl;
                    std::cout << "Shift out was " << shift_out_t << endl;
                    std::cout << "n bits were " << n_bits_per_input << endl;
                    std::cout << "input size was " << input_size << endl;
                    std::cout << "thread number was " << omp_get_thread_num() << endl;
                    std::cout << "index is " << i << endl;
//                    std::cout << "Shift (inv)  " << bigint(typename outputShare::clear(reals[i] - c)).get_str(2) << "(" << bigint(typename outputShare::clear(reals[i] - c)) << ")" << endl;
//                    std::cout << "Shift of minu" << bigint(shift_out_t).get_str(2) << " (" << bigint(shift_out_t) << ")"
//                              << endl;
//                    std::cout << "Then we get  " << bigint(c - (c - typename outputShare::clear(reals[i]))).get_str(2) << "(" << bigint(c - (c - typename outputShare::clear(reals[i]))) << ")"
//                              << endl;

                    assert(false);
                } else {
//                    std::cout << "Correct: " << i << " " << bigint(c) << " == " << bigint(reals[i]) << endl;
                }
            }

            outputs.push_back(c);
        }
        std::cout << "output_1" << " = " << outputs[1] << endl;
    }
    // end debug
//    cout << "Overall conversion of " << input_size << " input values " << timer_all.elapsed() * 1e3 << " ms" << endl;


    return result;
}

template<class inputShare, class outputShare>
vector<outputShare> convert_shares_ring(const typename vector<inputShare>::iterator input_shares_begin,
                                        const typename vector<inputShare>::iterator input_shares_end,
                                        MixedProtocolSet<inputShare>& set_input,
                                        ProtocolSet<outputShare>& set_output,
                                        typename inputShare::mac_key_type in_arithmetic_mac_key,
                                        typename inputShare::bit_type::mac_key_type binary_mac_key,
                                        typename outputShare::mac_key_type out_arithmetic_mac_key,
                                        Player &P, const int n_bits_per_input,
                                        const typename inputShare::clear shift_int_t,
                                        const typename outputShare::clear shift_out_t,
                                        const bool debug) {


    // for now we need to use all the bits;
    const int input_size = std::distance(input_shares_begin, input_shares_end);
//    int n_bits_per_input = prime_length;

    bool strict = true;

//    std::cout << "Singleton " << BaseMachine::singleton << endl;

    // read inputs
    // buffer edabits
    // decompose, add bits to r, open,
    // compose

    DataPositions usage;

    auto overall_stats = P.total_comm();

    std::cout << "shift_out_t initially " << shift_out_t << " " << n_bits_per_input << " " << outputShare::clear::n_bits() << " t" << omp_get_thread_num() << endl;
//    std::cout << "recomp " << (out_one << (n_bits_per_input - 1)) << " " << outputShare::clear::pr() << endl;

    if (shift_out_t == bigint("0")) {
        std::cout << "shift_out_t is zero " << endl;
        assert(false);
    }

    const inputShare shift_in_share = inputShare::constant(shift_int_t, P.my_num(), in_arithmetic_mac_key);

    BitAdder bit_adder;
    typedef typename inputShare::bit_type::part_type BT;
    int dl = BT::default_length;
    int buffer_size = DIV_CEIL(input_size, dl) * dl;
    vector <vector<BT>> sums_one(buffer_size / dl);
    vector<vector<vector<BT> > > summands_one(n_bits_per_input, vector<vector<BT> >(2, vector<BT>(buffer_size / dl)));

    vector<typename inputShare::clear> reals;
    vector<typename inputShare::clear> cs_debug;
    (void)cs_debug;

    {
//        vector <edabit<inputShare>> edabits_in;
        vector <FixedVector<typename inputShare::bit_type::part_type::small_type, (inputShare::clear::MAX_EDABITS + 5)>> edabits_in;

        edabitvec <inputShare> buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);

        std::cout << buffer_in.size() << " " << buffer_in.get_b(0).size() << endl;
        // open for debug
        if (debug) {
            set_input.output.init_open(P, input_size);
            for (auto iterator = input_shares_begin; iterator != input_shares_end; iterator++) {
                inputShare c = *iterator;
                set_input.output.prepare_open(c);
            }
            set_input.output.exchange(P);
            set_input.check();
            for (int i = 0; i < input_size; i++) {
                typename inputShare::clear c = set_input.output.finalize_open();
//                std::cout << "input_" << i << " = " << c << endl;
                if (bigint(c + (typename inputShare::clear(1) << (n_bits_per_input - 1))) >= bigint(typename inputShare::clear(1) << n_bits_per_input)) {
                    std::cout << "input_" << i << " = " << c << " " << bigint(c) << endl;
                    std::cout << "shifted " << bigint(c + (typename inputShare::clear(1) << (n_bits_per_input - 1))) << " < " << bigint(typename inputShare::clear(1) << n_bits_per_input) << endl;
                    std::cout << "Value is not in range of " << n_bits_per_input << " bits [" << -bigint(typename inputShare::clear(1) << (n_bits_per_input - 1)) << ", " << bigint(typename inputShare::clear(1) << (n_bits_per_input - 1)) << "]" << endl;
                    assert(false);
                }// make sure our values are within range
                reals.push_back(c);
            }
            std::cout << "input_1" << " = " << reals[1] << endl;
        }
        // end debug

        set_input.output.init_open(P, input_size);
        for (auto iterator = input_shares_begin; iterator != input_shares_end; iterator++) {
            if (buffer_in.empty()) {
                buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
            }
            auto edabit_in = buffer_in.next();
            edabits_in.push_back(edabit_in.second);

            inputShare c = *iterator + shift_in_share - edabit_in.first;
//            inputShare c = *iterator + shift_in_share; // X

            set_input.output.prepare_open(c);
        }


//        Timer timer_open_c;
//        timer_open_c.start();
        auto stats = P.total_comm();

        set_input.output.exchange(P);
        set_input.check();

//        cout << "Opening " << input_size << " masked input values " << timer_open_c.elapsed() * 1e3 << " ms" << endl;
        (P.total_comm() - stats).print(true);
        vector<typename inputShare::clear> cs;
        for (int i = 0; i < input_size; i++) {
            typename inputShare::clear c = set_input.output.finalize_open();
            cs.push_back(c);
            if (debug) {
                cs_debug.push_back(c);
            }
        }

        // dim 0: n_bits, dim 1: (x,y), dim 2; element?
//        for (int i = 0; i < n_bits_per_input; i++) {
//            for (int j = 0; j < input_size; j++) {
//                summands_one[i][0][j] = BT::constant(Integer(bigint(cs[j])).get_bit(i), P.my_num(), binary_mac_key);
//                summands_one[i][1][j] = edabits_in[j][i];
////                summands_one[i][1][j] = 0; // X
//            }
//        }
        for (int j = 0; j < input_size; j++) {
            for (int i = 0; i < n_bits_per_input; i++) {
                summands_one[i][0][j / dl].xor_bit(j % dl, BT::constant(Integer(bigint(cs[j])).get_bit(i), P.my_num(), binary_mac_key));
                summands_one[i][1][j / dl].xor_bit(j % dl, edabits_in[j][i]);
            }
        }
    }

    // TODO: Properly account for usage?
//    this->usage.count_edabit(strict, n_bits);

//    Timer timer_adders;
//    timer_adders.start();
    auto stats = P.total_comm();

    // TODO: look into this for SPDZ conversion
//    auto bit_MC = bt::MAC_Check(set_input.binary.thread.MC.get_alphai());
//    SubProcessor<bt> bit_proc(set_input.binary.thread.MC->get_part_MC(), set_input.binary.prep, P);
//    SubProcessor<bt> bit_proc(set_input.binary.thread.MC->get_part_MC(), set_input.binary.prep, P);

//    typename bt::LivePrep bit_prep(usage);
//    auto &party = GC::ShareThread<bt>::s();

    SubProcessor<BT> bit_proc(set_input.binary.thread.MC->get_part_MC(), set_input.arithmetic.processor.bit_prep, P);

    int begin = 0;
    int end = buffer_size / dl;
    bit_adder.add(sums_one, summands_one, begin, end, bit_proc,
                  dl, 0);


    auto diff = (P.total_comm() - overall_stats);
//    print_global("log", P, diff);


    vector<outputShare> result = compose_shares(sums_one, input_size, bit_proc, set_input, set_output, out_arithmetic_mac_key,
                                                P, n_bits_per_input, shift_int_t, shift_out_t, debug, reals, cs_debug);


    (P.total_comm() - overall_stats).print(true);

    bit_proc.check();

    return result;
}

template<class inputShare, class outputShare>
vector<outputShare> convert_shares_ring_split(const typename vector<inputShare>::iterator input_shares_begin,
                                        const typename vector<inputShare>::iterator input_shares_end,
                                        MixedProtocolSet<inputShare>& set_input,
                                        ProtocolSet<outputShare>& set_output,
                                        typename inputShare::mac_key_type in_arithmetic_mac_key,
                                        typename inputShare::bit_type::mac_key_type binary_mac_key,
                                        typename outputShare::mac_key_type out_arithmetic_mac_key,
                                        Player &P, const int n_bits_per_input,
                                        const typename inputShare::clear shift_int_t,
                                        const typename outputShare::clear shift_out_t,
                                        const bool debug) {


    // for now we need to use all the bits;
    const int input_size = std::distance(input_shares_begin, input_shares_end);

    DataPositions usage;

    auto overall_stats = P.total_comm();

    std::cout << "shift_out_t initially " << shift_out_t << " " << n_bits_per_input << " "
              << outputShare::clear::n_bits() << " t" << omp_get_thread_num() << endl;
//    std::cout << "recomp " << (out_one << (n_bits_per_input - 1)) << " " << outputShare::clear::pr() << endl;

    if (shift_out_t == bigint("0")) {
        std::cout << "shift_out_t is zero " << endl;
        assert(false);
    }

    const inputShare shift_in_share = inputShare::constant(shift_int_t, P.my_num(), in_arithmetic_mac_key);
//    const outputShare shift_out_share = outputShare::constant(shift_out_t, P.my_num(), out_arithmetic_mac_key);

    BitAdder bit_adder;
    typedef typename inputShare::bit_type bt;
    typedef typename inputShare::bit_type::part_type BT;
    int dl = BT::default_length;
    int buffer_size = DIV_CEIL(input_size, dl) * dl;
    vector<vector<BT>> sums_one(buffer_size / dl);
    vector<vector<vector<BT> > > summands_one;

    vector<typename inputShare::clear> reals;
    vector<typename inputShare::clear> cs_debug;
    (void) cs_debug;
    (void) binary_mac_key;
    (void) shift_in_share;

    SubProcessor<BT> bit_proc(set_input.binary.thread.MC->get_part_MC(), set_input.arithmetic.processor.bit_prep, P);

    if (debug) {
        set_input.output.init_open(P, input_size);
        for (auto iterator = input_shares_begin; iterator != input_shares_end; iterator++) {
            inputShare c = *iterator;
            set_input.output.prepare_open(c);
        }
        set_input.output.exchange(P);
        set_input.check();
        for (int i = 0; i < input_size; i++) {
            typename inputShare::clear c = set_input.output.finalize_open();
//                std::cout << "input_" << i << " = " << c << endl;
            if (bigint(c + (typename inputShare::clear(1) << (n_bits_per_input - 1))) >=
                bigint(typename inputShare::clear(1) << n_bits_per_input)) {
                std::cout << "input_" << i << " = " << c << " " << bigint(c) << endl;
                std::cout << "shifted " << bigint(c + (typename inputShare::clear(1) << (n_bits_per_input - 1)))
                          << " < " << bigint(typename inputShare::clear(1) << n_bits_per_input) << endl;
                std::cout << "Value is not in range of " << n_bits_per_input << " bits ["
                          << -bigint(typename inputShare::clear(1) << (n_bits_per_input - 1)) << ", "
                          << bigint(typename inputShare::clear(1) << (n_bits_per_input - 1)) << "]" << endl;
                assert(false);
            }// make sure our values are within range
            reals.push_back(c);
        }
        std::cout << "input_1" << " = " << reals[1] << endl;
    }

    {
        // shift up
        std::vector<inputShare> input_shares_shifted(
                input_size); // not sure why we need this oversized array, but has to with impl of split
        int loop_idx = 0;
        for (auto iterator = input_shares_begin; iterator != input_shares_end; iterator++) {
            inputShare c = *iterator + shift_in_share;
//            for (int j = 0; j < dl; j++) {
//                input_shares_shifted[(loop_idx * dl) + j] = c;
//            }
            input_shares_shifted[loop_idx] = c;
            loop_idx += 1;
        }
        inputShare *input_shares_raw_pointer = input_shares_shifted.data();

//        buffer_size = input_size * dl;
        vector<int> regs(P.num_players() * n_bits_per_input);
        for (size_t i = 0; i < regs.size(); i++)
            regs[i] = i * buffer_size / dl;
//            regs[i] = i * n_bits_per_input;
//            regs[i] = i * P.num_players() * n_bits_per_input;
        StackedVector<bt> bits(n_bits_per_input * P.num_players() * input_size); // TODO: bits might be too large?
        inputShare::split(bits, regs, n_bits_per_input, input_shares_raw_pointer, input_size,
                          *GC::ShareThread<bt>::s().protocol);


        std::cout << "Done split" << endl;

        // debug output bits
        for (unsigned long i = 0; i < bits.size() / dl; i++) {
//            std::cout << bits[i] << " ";
        }


//        vector<vector<vector<bt>>> summands;
        for (int i = 0; i < n_bits_per_input; i++) {
            summands_one.push_back({});
            auto &x = summands_one.back();
            for (int j = 0; j < P.num_players(); j++) {
                x.push_back({});
                auto &y = x.back();
                for (int k = 0; k < buffer_size / dl; k++) {
//                    std::cout << "a" << k + buffer_size / dl * (j + P.num_players() * i) << " ";
                    y.push_back(bits.at(k + buffer_size / dl * (j + P.num_players() * i)));
                }
//                std::cout << std::endl;
            }
        }

        overall_stats = P.total_comm();

        bit_adder.multi_add(sums_one, summands_one, 0, buffer_size / dl, bit_proc, dl, 0);
//        for (int i = 0; i < input_size; i++) {
//            sums_one[i] = std::vector<BT>(n_bits_per_input);
//        }
    }

    // print overall stats until this point
    auto diff = (P.total_comm() - overall_stats);
    diff.print(true);
//    print_global("share_switch_split", P, diff);


//    if (debug) {
//        set_input.binary.output.init_open(P, (n_bits_per_input) * input_size);
//        for (int i = 0; i < n_bits_per_input; i++) {
//            for (int j = 0; j < buffer_size / dl; j++) {
//                set_input.binary.output.prepare_open(sums_one[j][i], dl);
//            }
//        }
//        set_input.binary.output.exchange(P);
//
//        vector<vector<typename bt::clear>> open_bits(n_bits_per_input, vector<typename bt::clear>(buffer_size / dl));
//        std::cout << "open bits type " << typeid(open_bits).name() << endl;
//        for (int i = 0; i < (int) n_bits_per_input; i++) {
//            for (int j = 0; j < (int) buffer_size / dl; j++) {
//                open_bits[i][j] = set_input.binary.output.finalize_open();
//            }
//        }
//        for (int i = 0; i < (int) input_size; i++) {
//            std::cout << i << " ";
//            std::cout << n_bits_per_input << " Number ";
//            std::cout << reals[i] << " has bits (these should be the original, unmasked value): ";
//            for (int j = 0; j < (int) n_bits_per_input; j++) {
//                // get the bits from open_bits[(n_bits_per_input) - j - 1] but from the right chunk of size dl
//                bool bit_result = open_bits[(n_bits_per_input) - j - 1][i / dl].get_bit(i % dl);
//                std::cout << bit_result;
//            }
//            std::cout << endl;
//        }
//    }

    vector<outputShare> result = compose_shares(sums_one, input_size, bit_proc, set_input, set_output, out_arithmetic_mac_key,
                   P, n_bits_per_input, shift_int_t, shift_out_t, debug, reals, cs_debug);

    (P.total_comm() - overall_stats).print(true);

    bit_proc.check();

    return result;
}

// TODO: Optimize these methods to share the compose function
template<class inputShare, class outputShare>
vector<outputShare> convert_shares_field(const typename vector<inputShare>::iterator input_shares_begin,
                                        const typename vector<inputShare>::iterator input_shares_end,
                                        MixedProtocolSet<inputShare>& set_input,
                                        ProtocolSet<outputShare>& set_output,
                                        typename inputShare::mac_key_type in_arithmetic_mac_key,
                                        typename inputShare::bit_type::mac_key_type binary_mac_key,
                                        typename outputShare::mac_key_type out_arithmetic_mac_key,
                                        Player &P, const int n_bits_per_input,
                                        const typename inputShare::clear shift_int_t,
                                        const typename outputShare::clear shift_out_t,
                                        const bool debug) {

    // for now we need to use all the bits;
    const int input_size = std::distance(input_shares_begin, input_shares_end);
//    int n_bits_per_input = prime_length;

    bool strict = true;

//    std::cout << "Singleton " << BaseMachine::singleton << endl;

    // read inputs
    // buffer edabits
    // decompose, add bits to r, open,
    // compose

    DataPositions usage;

    auto overall_stats = P.total_comm();

    std::cout << "shift_out_t initially " << shift_out_t << " " << n_bits_per_input << " " << outputShare::clear::n_bits() << " t" << omp_get_thread_num() << endl;
//    std::cout << "recomp " << (out_one << (n_bits_per_input - 1)) << " " << outputShare::clear::pr() << endl;

    if (shift_out_t == bigint("0")) {
        std::cout << "shift_out_t is zero " << endl;
        assert(false);
    }

    const inputShare shift_in_share = inputShare::constant(shift_int_t, P.my_num(), in_arithmetic_mac_key);

    BitAdder bit_adder;
    typedef typename inputShare::bit_type::part_type BT;
    int dl = BT::default_length;
    int buffer_size = DIV_CEIL(input_size, dl) * dl;
    vector <vector<BT>> sums_one(buffer_size / dl);
    vector<vector<vector<BT> > > summands_one(n_bits_per_input, vector<vector<BT> >(2, vector<BT>(buffer_size / dl)));

    const int kappa = 40;

    vector<typename inputShare::clear> reals;
    vector<typename inputShare::clear> cs_debug;
    (void)cs_debug;

    {
//        vector <edabit<inputShare>> edabits_in;
        vector <FixedVector<typename inputShare::bit_type::part_type::small_type, (inputShare::clear::MAX_EDABITS + 5)>> edabits_in;

        edabitvec <inputShare> buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
        edabitvec <inputShare> buffer_in_rprimeprime = set_input.preprocessing.get_edabitvec(strict, kappa);

        std::cout << buffer_in.size() << " " << buffer_in.get_b(0).size() << endl;
        // open for debug
        if (debug) {
            set_input.output.init_open(P, input_size);
            for (auto iterator = input_shares_begin; iterator != input_shares_end; iterator++) {
                inputShare c = *iterator;
                set_input.output.prepare_open(c);
            }
            set_input.output.exchange(P);
            set_input.check();
            for (int i = 0; i < input_size; i++) {
                typename inputShare::clear c = set_input.output.finalize_open();
//                std::cout << "input_" << i << " = " << c << endl;
                if (bigint(c + (typename inputShare::clear(1) << (n_bits_per_input - 1))) >= bigint(typename inputShare::clear(1) << n_bits_per_input)) {
                    std::cout << "input_" << i << " = " << c << " " << bigint(c) << endl;
                    std::cout << "shifted " << bigint(c + (typename inputShare::clear(1) << (n_bits_per_input - 1))) << " < " << bigint(typename inputShare::clear(1) << n_bits_per_input) << endl;
                    std::cout << "Value is not in range of " << n_bits_per_input << " bits [" << -bigint(typename inputShare::clear(1) << (n_bits_per_input - 1)) << ", " << bigint(typename inputShare::clear(1) << (n_bits_per_input - 1)) << "]" << endl;
                    assert(false);
                }// make sure our values are within range
                reals.push_back(c);
            }
            std::cout << "input_1" << " = " << reals[1] << endl;
        }
        // end debug

        const typename inputShare::clear power_two_n_bits = typename inputShare::clear(1) << n_bits_per_input;
        const typename inputShare::clear power_two_full = typename inputShare::clear(1) << (n_bits_per_input + kappa);
        inputShare power_two_n_bits_share = inputShare::constant(power_two_n_bits, P.my_num(), in_arithmetic_mac_key);
        inputShare power_two_full_share = inputShare::constant(power_two_full, P.my_num(), in_arithmetic_mac_key);
        (void)power_two_n_bits_share;
        (void)power_two_full_share;

        set_input.output.init_open(P, input_size);
        for (auto iterator = input_shares_begin; iterator != input_shares_end; iterator++) {
            if (buffer_in.empty()) {
                buffer_in = set_input.preprocessing.get_edabitvec(strict, n_bits_per_input);
                buffer_in_rprimeprime = set_input.preprocessing.get_edabitvec(strict, kappa);
            }
            auto edabit_in = buffer_in.next();
            auto edabit_in_rprimeprime = buffer_in_rprimeprime.next();
            edabits_in.push_back(edabit_in.second);

            // we don't need power_two_n_bits_share and (power_two_n_bits * edabit_in_rprimeprime.first) terms for correctness,
            // but maybe for security so that c' doesnt reveal anything?
            inputShare c = power_two_n_bits_share + power_two_full_share + *iterator + shift_in_share - edabit_in.first - (edabit_in_rprimeprime.first * power_two_n_bits);
//            inputShare c = power_two_n_bits_share + power_two_full_share + *iterator + shift_in_share - edabit_in.first - (power_two_n_bits * edabit_in_rprimeprime.first);
//            inputShare c = *iterator + shift_in_share; // X

            set_input.output.prepare_open(c);
        }


//        Timer timer_open_c;
//        timer_open_c.start();
        auto stats = P.total_comm();

        set_input.output.exchange(P);
        set_input.check();

//        cout << "Opening " << input_size << " masked input values " << timer_open_c.elapsed() * 1e3 << " ms" << endl;
        (P.total_comm() - stats).print(true);
        vector<typename inputShare::clear> cs;
        for (int i = 0; i < input_size; i++) {
            typename inputShare::clear c = set_input.output.finalize_open();
            cs.push_back(c);
            if (debug) {
                cs_debug.push_back(c);
            }
        }

//        // dim 0: n_bits, dim 1: (x,y), dim 2; element?
//        for (int i = 0; i < n_bits_per_input; i++) {
//            for (int j = 0; j < input_size; j++) {
//                summands_one[i][0][j] = BT::constant(Integer(bigint(cs[j])).get_bit(i), P.my_num(), binary_mac_key);
//                summands_one[i][1][j] = edabits_in[j][i];
////                summands_one[i][1][j] = 0; // X
//            }
//        }
        for (int j = 0; j < input_size; j++) {
            for (int i = 0; i < n_bits_per_input; i++) {
                summands_one[i][0][j / dl].xor_bit(j % dl, BT::constant(Integer(bigint(cs[j])).get_bit(i), P.my_num(), binary_mac_key));
                summands_one[i][1][j / dl].xor_bit(j % dl, edabits_in[j][i]);
            }
        }
    }

    auto stats = P.total_comm();

    SubProcessor<BT> bit_proc(set_input.binary.thread.MC->get_part_MC(), set_input.arithmetic.processor.bit_prep, P);

    int begin = 0;
    int end = buffer_size / dl;
    bit_adder.add(sums_one, summands_one, begin, end, bit_proc,
                  dl, 0);

    vector<outputShare> result = compose_shares(sums_one, input_size, bit_proc, set_input, set_output, out_arithmetic_mac_key,
                                                P, n_bits_per_input, shift_int_t, shift_out_t, debug, reals, cs_debug);

    (P.total_comm() - overall_stats).print(true);

    bit_proc.check();

    return result;
}

//11111111111111111111111111111111111111111111111100000000000000000
//                                              -100000000000000000


template<class inputShare>
vector<inputShare> exchangeVector(Player &P, MixedProtocolSet<inputShare> &set, const int n_bits_per_input,
                                  const input_format_type &inputs_format, const vector<typename inputShare::clear> &inputs) {
    typename inputShare::Input& input = set.input;

    const typename inputShare::clear shift_up = typename inputShare::clear(1) << (n_bits_per_input - 1);
    const bigint allowed_range_bound = bigint(typename inputShare::clear(1) << n_bits_per_input);

    // input from all parties
    input.reset_all(P);
    for (unsigned long i = 0; i < inputs_format.size(); i++) {
        if ((int)i == P.my_num()) {
            int input_counter = 0;
            for (unsigned long j = 0; j < inputs_format[i].size(); j++) {
                for (int k = 0; k < inputs_format[i][j].length; k++) {
                    assert(bigint(inputs[input_counter] + shift_up) < allowed_range_bound); // check that input is in valid bound
                    input.add_mine(inputs[input_counter]);
                    input_counter++;
                }
            }
        } else {
            for (unsigned long j = 0; j < inputs_format[i].size(); j++) {
                for (int k = 0; k < inputs_format[i][j].length; k++) {
                    input.add_other(i);
                }
            }
        }
    }
    input.exchange();

    vector<inputShare> result;
    // put shares in order of players
    for (unsigned long i = 0; i < inputs_format.size(); i++) {
        for (unsigned long j = 0; j < inputs_format[i].size(); j++) {
            for (int k = 0; k < inputs_format[i][j].length; k++) {
                result.push_back(input.finalize(i));
            }
        }
    }

    set.check();

    return result;
}

template<class inputShare>
std::vector<inputShare> distribute_inputs(Player &P, MixedProtocolSet<inputShare>& set, std::vector<std::vector<std::string> >& inputs_format_str, const int n_bits_per_input) {
    // this method loads inputs, distributes them, and returns the shares
    input_format_type inputs_format = process_format(inputs_format_str);

    std::vector<typename inputShare::clear> inputs;
    if (inputs_format[P.my_num()].size() > 0) {
        inputs = read_private_input<typename inputShare::clear>(P, inputs_format[P.my_num()]);
    }

    long long total_length_inputs = 0;
    for (unsigned long i = 0; i < inputs_format.size(); i++) {
        for (unsigned long j = 0; j < inputs_format[i].size(); j++) {
            total_length_inputs += inputs_format[i][j].length;
        }
    }
    std::cout << "Total length of inputs " << total_length_inputs << endl;

    // if bigger than int32_max
    if (13 * total_length_inputs > pow(2l, 32l)) {
        // Split in two chunks as input size is "likely" too big.
        // Future implementations should be able to handle this better by actually checking whether the number of elements is too big.
        // split vec into two
        std::cout << "Splitting input reading into two chunks" << endl;
        input_format_type inputs_format_1;
        input_format_type inputs_format_2;
        for (unsigned long i = 0; i < inputs_format.size(); i++) {
            if (i < inputs_format.size() / 2) {
                inputs_format_1.push_back(inputs_format[i]);
            } else {
                inputs_format_2.push_back(inputs_format[i]);
            }
        }
        std::vector<inputShare> shares_1 = exchangeVector(P, set, n_bits_per_input, inputs_format_1, inputs);
        std::vector<inputShare> shares_2 = exchangeVector(P, set, n_bits_per_input, inputs_format_2, inputs);
        shares_1.insert(shares_1.end(), shares_2.begin(), shares_2.end());

        return shares_1;
    }

    return exchangeVector(P, set, n_bits_per_input, inputs_format, inputs);

}

template<class inputShare, class outputShare>
void run(int argc, const char** argv, bigint output_field_prime, int bit_length = -1, int n_players = 3, bool input_is_field = false)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    SwitchOptions opts(opt, argc, argv);
    assert(opts.inputs_format.size() == 0 or opts.n_shares == 0); // can only specify one

    // Set outputShare

//    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;

//    int n_players = 3;
//    if (opt.isSet("-N")) {
//        opt.get("-N")->getInt(n_players);
//        std::cout << "N " << n_players << endl;
//    }
    Names N(opt, argc, argv, n_players);

    CryptoPlayer P(N, "pc");

    string prefix_input = get_prep_sub_dir<inputShare>("Player-Data", n_players, bit_length);
    std::cout << "Loading input mac from " << prefix_input << endl;

//    typename inputShare::mac_key_type mac_key;
//    inputShare::read_or_generate_mac_key(prefix, P, mac_key);

    // protocol setup (domain, MAC key if needed etc)

    if (bit_length == -1) {
        bit_length = inputShare::clear::n_bits();
    }

    std::cout << "inputs format" << endl;
    for(unsigned long i = 0; i < opts.inputs_format.size(); i++) {
        for(unsigned long j = 0; j < opts.inputs_format[i].size(); j++) {
            std::cout << opts.inputs_format[i][j] << " ";
        }
        std::cout << std::endl;
    }

//    OnlineOptions::singleton.batch_size = opts.n_shares;
//    OnlineOptions::singleton.verbose = true;

    // only only_distribute_inputs can be enabled if we are not reading shares
    assert(not (opts.n_shares > 0 and opts.only_distribute_inputs));

    // we either read shares or re-share input
    std::string log_name;

    vector <inputShare> input_shares;
    std::cout << "Test " << opts.test << endl;
    if (opts.test) {
        inputShare::clear::init_default(bit_length);
        inputShare::clear::next::init_default(bit_length, false);
        outputShare::clear::init_field(output_field_prime);
        outputShare::clear::next::init_field(output_field_prime, false);

        input_shares = {
                inputShare::constant(typename inputShare::clear(bigint("0")), P.my_num(), typename inputShare::mac_key_type()),
                inputShare::constant(typename inputShare::clear(bigint("1")), P.my_num(), typename inputShare::mac_key_type()),
                inputShare::constant(typename inputShare::clear(bigint("-5")), P.my_num(), typename inputShare::mac_key_type()),
                inputShare::constant(typename inputShare::clear(bigint("229539328")), P.my_num(), typename inputShare::mac_key_type()),
                inputShare::constant(typename inputShare::clear(bigint("1073741823")), P.my_num(), typename inputShare::mac_key_type()),
                inputShare::constant(typename inputShare::clear(bigint("-1073741823")), P.my_num(), typename inputShare::mac_key_type()),
        };
        log_name = "test";
    } else if (opts.n_shares > 0) {
        std::cout << "Initializing with bit length " << bit_length << std::endl;
        inputShare::clear::init_default(bit_length);
        inputShare::clear::next::init_default(bit_length, false);
        outputShare::clear::init_field(output_field_prime);
        outputShare::clear::next::init_field(output_field_prime, false);

        input_shares = read_inputs<inputShare>(P, opts.n_shares, opts.start);
        log_name = "share_switch_output";
    } else if (opts.inputs_format.size() > 0) {

        MixedProtocolSetup<inputShare> setup_input(P, bit_length, prefix_input);
        MixedProtocolSet<inputShare> set_input(P, setup_input);

//        ProtocolSetup<outputShare> setup_output(t_big, P);
//        ProtocolSet<outputShare> set_output(P, setup_output);
        outputShare::clear::init_field(output_field_prime);
        outputShare::clear::next::init_field(output_field_prime, false);

        input_shares = distribute_inputs(P, set_input, opts.inputs_format, opts.n_bits_per_input);
        std::cout << "Done reading inputs" << endl;
        log_name = "share_switch_input";

        set_input.check();

        if (opts.only_distribute_inputs) {
            // save those to file
            std::cout << "Saving unconverted shares " << endl;
            bool overwrite = opts.output_start == 0;
            write_shares<inputShare>(P, input_shares, "", overwrite, opts.output_start);
            return;
        }
    } else {
        std::cerr << "Must specify either n_shares or inputs_format," << std::endl;
        exit(1);
    }

    string prefix_output = get_prep_sub_dir<outputShare>("Player-Data", n_players, outputShare::clear::length());
    std::cout << "Loading output mac from " << prefix_output << " " << outputShare::clear::length() << endl;

    if (outputShare::has_mac) {
        typename outputShare::mac_key_type temp_mac = read_generate_write_mac_key<outputShare>(P, prefix_output);
        (void)temp_mac;
    }

    int n_bits_per_input = bit_length;
    if (opts.n_bits_per_input != -1) {
        n_bits_per_input = opts.n_bits_per_input;
    }

//    const int mem_cutoff = 8;

    Timer timer;
    timer.start();
    auto stats = P.total_comm();

    vector<outputShare> result(input_shares.size());

//    vector<CryptoPlayer> players;
//    for (int i = 0; i < n_chunks; i++) {
//        players.push_back(CryptoPlayer(N, i * 3));
//    }

    const bool has_large_edabit_batch_size = inputShare::malicious;
    // It seems that the large batch size is dynamic...  for now just assume its ~10k
    unsigned long min_batch_size_per_thread = 1;
    if (has_large_edabit_batch_size) {
        min_batch_size_per_thread = 10000;
    }

    int n_threads = opts.n_threads;
    if (n_threads > 1) {
        if (input_shares.size() < 10000 && n_threads > 18) {
            n_threads = 18;
            std::cout << "Using 18 threads because only " << input_shares.size() << " shares" << endl;
        }
        if (input_shares.size() < 1000) {
            n_threads = 1;
            std::cout << "Using single thread because only " << input_shares.size() << " shares" << endl;
        }
        const unsigned long n_samples_per_thread = DIV_CEIL(input_shares.size(), n_threads);
        if (n_samples_per_thread < min_batch_size_per_thread) {
            n_threads = DIV_CEIL(input_shares.size(), min_batch_size_per_thread);
            std::cout << "Using " << n_threads << " threads because only " << input_shares.size() << " shares" << endl;
        }
    }

    const unsigned long n_samples_per_thread = DIV_CEIL(input_shares.size(), n_threads);
    const unsigned long mem_cutoff = opts.chunk_size;

//    if ((opts.n_threads - 1) * n_chunks_per_thread > input_shares.size()) {
//        std::cout << "Warning: not enough shares to distribute to all threads" << endl;
//        std::cout << "Setting number of threads to "
//    }

    std::cout << "Edabit batch size " << OnlineOptions::singleton.batch_size << ". Would have needed " << min(n_samples_per_thread, mem_cutoff) << endl;
    OnlineOptions::singleton.batch_size = min((unsigned long)150000, min(n_samples_per_thread, mem_cutoff));
    OnlineOptions::singleton.verbose = true;

    const bigint shift_in = bigint(1) << (n_bits_per_input - 1);
    typename inputShare::clear shift_int_t = typename inputShare::clear(shift_in);
    typename outputShare::clear shift_out_t = typename outputShare::clear(bigint("1") << (n_bits_per_input - 1));

    std::cout << "shift_in " << shift_in << " " << n_bits_per_input << " " << inputShare::clear::n_bits() << endl;

    const typename inputShare::clear shift_in_prime = typename inputShare::clear(bigint(1)) << (n_bits_per_input - 1);
    std::cout << "shift in prime " << shift_in_prime << endl;

    //    std::cout << "shift_out_t initially " << shift_out_t << " " << n_bits_per_input << " " << outputShare::clear::n_bits() << endl;

    std::cout << "Running in " << n_threads << " threads" << endl;

    std::vector<NamedCommStats> thread_local_diffs(n_threads);

    // If we reach until here, we cannot have the same input as output because of networking,
    // but in any case it doesnt make sense to do this.
    auto has_same_types = is_same<inputShare, outputShare>::value;
    assert(not has_same_types);

#pragma omp parallel for num_threads(n_threads)
    for (int j = 0; j < n_threads; j++) {
        bigint::init_thread();

        const unsigned long begin_thread = j * n_samples_per_thread;
        const unsigned long end_thread = min(((unsigned long) (j + 1) * n_samples_per_thread), input_shares.size());
        if (begin_thread >= end_thread) {
            stringstream stream;
            stream << "Thread " << j << "(" << omp_get_thread_num() << ") will skip processing because not enough shares" << std::endl;
            cout << stream.str();
            continue;
        }

        const int n_chunks = DIV_CEIL(end_thread - begin_thread, mem_cutoff);

        stringstream stream;
        stream << "Thread " << j << "(" << omp_get_thread_num() << ") processing items (" << begin_thread << "-" << end_thread << ") in " << n_chunks << " chunks" << std::endl;
        cout << stream.str();

        CryptoPlayer P_j(N, j * n_threads + 202);

        MixedProtocolSetup<inputShare> setup_input_i(P_j, bit_length, prefix_input);
        MixedProtocolSet<inputShare> set_input_i(P_j, setup_input_i);

        ProtocolSetup<outputShare> setup_output_i(output_field_prime, P_j);
        ProtocolSet<outputShare> set_output_i(P_j, setup_output_i);

        auto thread_local_stats = P_j.total_comm();

        for (int i = 0; i < n_chunks; i++) {
            const unsigned long begin_chunk = begin_thread + i * mem_cutoff;
            const unsigned long end_chunk = min(begin_chunk + mem_cutoff, end_thread);
            // each thread in parallel

            vector<outputShare> res;
            if (input_is_field) {
                res = convert_shares_field(input_shares.begin() + begin_chunk,
                                           input_shares.begin() + end_chunk,
                                           set_input_i, set_output_i, setup_input_i.get_mac_key(),
                                           setup_input_i.binary.get_mac_key(),
                                           setup_output_i.get_mac_key(), P_j, n_bits_per_input,
                                           shift_int_t, shift_out_t,
                                           opts.debug);
            } else if (inputShare::has_split && opts.use_share_split) {
                std::cout << "Using share splitting";
                res = convert_shares_ring_split(input_shares.begin() + begin_chunk,
                                          input_shares.begin() + end_chunk,
                                          set_input_i, set_output_i, setup_input_i.get_mac_key(),
                                          setup_input_i.binary.get_mac_key(),
                                          setup_output_i.get_mac_key(), P_j, n_bits_per_input,
                                          shift_int_t, shift_out_t,
                                          opts.debug);
            } else {
                res = convert_shares_ring(input_shares.begin() + begin_chunk,
                                                               input_shares.begin() + end_chunk,
                                                               set_input_i, set_output_i, setup_input_i.get_mac_key(),
                                                               setup_input_i.binary.get_mac_key(),
                                                               setup_output_i.get_mac_key(), P_j, n_bits_per_input,
                                                               shift_int_t, shift_out_t,
                                                               opts.debug);
            }

//            result.insert(result.begin() + begin_chunk, res.begin(), res.end());
            for (unsigned long k = 0; k < res.size(); k++) {
                result[begin_chunk + k] = res[k];
            }

            stringstream stream2;
            stream2 << "Thread " << j << " done with chunk " << i << std::endl;
            cout << stream2.str();
        }

        set_input_i.check();
//        set_input_i.binary.thread.MC->get_part_MC().Check(P);
        set_output_i.check();

        auto thread_local_diff = P_j.total_comm() - thread_local_stats;
        thread_local_diffs[j] = thread_local_diff;
    }
//    set_input.check();
//    set_output.check();


    std::cout << "Share 0 " << result[0] << std::endl;

    bool overwrite = opts.output_start == 0;
    write_shares<outputShare>(P, result, KZG_SUFFIX, overwrite, opts.output_start);

    auto diff = P.total_comm() - stats;

    for (int j = 0; j < (int)thread_local_diffs.size(); j++) {
        diff = diff + thread_local_diffs[j];
    }

    print_timer(log_name, timer.elapsed());
    print_stat(log_name, diff);
    print_global(log_name, P, diff);

//    vector<outputShare> check_shares = read_inputs<outputShare>(P, 2, KZG_SUFFIX);
//
//    std::cout << "Share 0 after reading " << check_shares[0] << std::endl;
//    std::cout << "Prime " << P377Element::Scalar::pr() << std::endl;

//    P377Element::finish();
}

template<class inputShare, template<class T> class outputShare>
void run(int argc, const char** argv, int bit_length = -1, int n_players = 3, bool input_is_field = false) {
    ez::ezOptionParser opt;
    SwitchOptions opts(opt, argc, argv);

    if (opts.curve == "bls12377") {
        libff::bls12_377_pp::init_public_params();
        mpz_t t;
        mpz_init(t);
        P377Element::G1::order().to_mpz(t);
        bigint t_big(t);

        run<inputShare, outputShare<P377Element::Scalar>>(argc, argv, t_big, bit_length, n_players, input_is_field);

        P377Element::finish();
    } else if (opts.curve == "sec256k1") {

        P256Element::init(false);

        bigint order = P256Element::get_order();
        run<inputShare, outputShare<P256Element::Scalar>>(argc, argv, order, bit_length, n_players, input_is_field);

        P256Element::finish();
    } else {
        std::cerr << "Unknown curve " << opts.curve << endl;
        exit(1);
    }
}


template< template<class T> class inputShare, template<class T> class outputShare>
void run(int argc, const char** argv) {
    ez::ezOptionParser opt;
    SwitchOptions opts(opt, argc, argv);

    // assume we are in a prime field
    assert(opts.input_prime_length > 0);
    const int n_limbs = DIV_CEIL(opts.input_prime_length, 64);

    // TODO: down here, dont hardcode num players to 2

    switch (n_limbs)
    {
#undef X
#define X(L) \
    case L: \
        run<inputShare<gfp_<0, L>>, outputShare>(argc, argv, opts.input_prime_length, 2, true); \
        break;
#ifndef FEWER_PRIMES
        X(1) X(2) X(3) X(4)
//        X(2)
#endif
#undef X
        default:
            cerr << "Not compiled for " << opts.input_prime_length << "-bit primes" << endl;
            cerr << "Compile with -DGFP_MOD_SZ=" << n_limbs << endl;
            exit(1);
    }

}
