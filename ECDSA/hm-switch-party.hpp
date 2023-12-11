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
vector<outputShare> convert_shares(const typename vector<inputShare>::iterator input_shares_begin,
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


//    Timer timer_all;
//    timer_all.start();
    auto overall_stats = P.total_comm();

//    const bigint shift_in = bigint(1) << (n_bits_per_input - 1);
//    const typename inputShare::clear shift_int_t = typename inputShare::clear(shift_in);
//    const typename outputShare::clear shift_out_t = typename outputShare::clear(bigint(1)) << (n_bits_per_input - 1);

//    typename outputShare::clear out_one;
//    out_one.assign_one();

    std::cout << "shift_out_t initially " << shift_out_t << " " << n_bits_per_input << " " << outputShare::clear::n_bits() << " t" << omp_get_thread_num() << endl;
//    std::cout << "recomp " << (out_one << (n_bits_per_input - 1)) << " " << outputShare::clear::pr() << endl;

    if (shift_out_t == bigint("0")) {
        std::cout << "shift_out_t is zero " << endl;
        assert(false);
    }

    const inputShare shift_in_share = inputShare::constant(shift_int_t, P.my_num(), in_arithmetic_mac_key);
    const outputShare shift_out_share = outputShare::constant(shift_out_t, P.my_num(), out_arithmetic_mac_key);

    const int bit_overflow_one = 0; // there should not be any overflow here
    const int bit_overflow_two = bit_overflow_one + 1;

    BitAdder bit_adder;
    typedef typename inputShare::bit_type bt;
    int dl = inputShare::clear::MAX_EDABITS;
    vector <vector<bt>> sums_one(input_size);
    vector<vector<vector<bt> > > summands_one(n_bits_per_input, vector<vector<bt> >(2, vector<bt>(input_size)));

    vector<typename inputShare::clear> reals;

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
//            inputShare c = *iterator + shift_in_share;

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
        }

        // dim 0: n_bits, dim 1: (x,y), dim 2; element?
        for (int i = 0; i < n_bits_per_input; i++) {
            for (int j = 0; j < input_size; j++) {
                summands_one[i][0][j] = bt::constant(Integer(bigint(cs[j])).get_bit(i), P.my_num(), binary_mac_key);
                summands_one[i][1][j] = edabits_in[j][i];
//                summands_one[i][1][j] = 0;
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

    typename bt::LivePrep bit_prep(usage);
    SubProcessor<bt> bit_proc(set_input.binary.thread.MC->get_part_MC(), bit_prep, P);

    int begin = 0;
    int end = input_size;
    bit_adder.add(sums_one, summands_one, begin, end, bit_proc,
                  dl, 0);

    // rewrite the above loop
    vector <outputShare> edabits_out_a;
    edabitvec <outputShare> buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
    vector<vector<vector<bt> > > summands_two(n_bits_per_input, vector<vector<bt> >(2, vector<bt>(input_size)));

    for (int j = 0; j < input_size; j++) {
        if (buffer_out.empty()) {
            buffer_out = set_output.preprocessing.get_edabitvec(strict, n_bits_per_input);
//            std::cout << "Buffering more " << buffer_out.size() << std::endl;
        }
        auto edabit_out = buffer_out.next();
        edabits_out_a.push_back(edabit_out.first);
        for (int i = 0; i < n_bits_per_input; i++) {
            summands_two[i][0][j] = sums_one[j][i];
            summands_two[i][1][j] = edabit_out.second[i];

//            summands_two[i][1][j] = edabit_out.second[i];
//            summands_two[i][1][j] = 0;
        }
    }

    vector<vector<bt>> sums_two(input_size);
    bit_adder.add(sums_two, summands_two, begin, end, bit_proc,
                  bt::default_length, 0);

//    cout << "Adding " << input_size * n_bits_per_input << " bits: " << timer_adders.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

//    // now we open each bit
//    if (debug) {
//        set_input.binary.output.init_open(P, (n_bits_per_input + bit_overflow_two) * input_size);
//        for (int i = 0; i < n_bits_per_input + bit_overflow_two; i++) {
//            for (int j = 0; j < input_size; j++) {
//                set_input.binary.output.prepare_open(sums_one[j][i]);
//            }
//        }
//        set_input.binary.output.exchange(P);
//
//        vector <vector<typename bt::clear>> open_bits(n_bits_per_input + bit_overflow_two, vector<typename bt::clear>(input_size));
//        std::cout << "open bits type " << typeid(open_bits).name() << endl;
//        for (int i = 0; i < (int) n_bits_per_input + bit_overflow_two; i++) {
//            for (int j = 0; j < (int) input_size; j++) {
//                open_bits[i][j] = set_input.binary.output.finalize_open();
//            }
//        }
//        for (int i = 0; i < (int) input_size; i++) {
//            std::cout << open_bits[0][i].get_bit(0) << " ";
//            std::cout << n_bits_per_input << " Number "
//                      << " has bits (these should be the original, unmasked value): ";
//            for (int j = 0; j < (int) n_bits_per_input + bit_overflow_two; j++) {
////            std::cout << " j" << j << " " << open_bits[n_bits_per_input - j - 1][i].get_bit(0);
//                std::cout << open_bits[(n_bits_per_input + bit_overflow_two) - j - 1][i].get_bit(0);
//            }
//            std::cout << endl;
//        }
//    }

//    Timer timer_bits;
//    timer_bits.start();
    stats = P.total_comm();


    set_input.binary.output.init_open(P, (n_bits_per_input + bit_overflow_two) * input_size);
    for (int i = 0; i < (int)n_bits_per_input + bit_overflow_two; i++) {
        for (int j = 0; j < (int)input_size; j++) {
            set_input.binary.output.prepare_open(sums_two[j][i]);
        }
    }
    set_input.binary.output.exchange(P);
    set_input.binary.check();

    vector< typename outputShare::clear > open_mask(input_size);

//    std::cout << open_bits[0][0].get_bit(0) << " open " << open_bits[1][0].get_bit(0) << endl;
//    std::cout << open_bits[0][2].get_bit(0) << " open " << open_bits[1][2].get_bit(0) << endl;

    vector<vector<bool> > open_bits_bool(n_bits_per_input + bit_overflow_two, vector<bool>(input_size));

    // now we compose the bits into a c_prime of type output_type
    for (int i = 0; i < (int)n_bits_per_input + bit_overflow_two; i++) {
        for (int j = 0; j < (int)input_size; j++) {
            auto bv = set_input.binary.output.finalize_open();
            open_mask[j] = open_mask[j] | typename outputShare::clear(bv.get_bit(0)) << i;
//            open_bits[i][j].xor_bit(bv.get_bit(0));
            open_bits_bool[i][j] = bv.get_bit(0);
        }
    }

//    cout << "Opening " << input_size * n_bits_per_input << " masked bits: " << timer_bits.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    // now everyone subtracts c_prime from the mask

    vector<outputShare > result;
    for (int i = 0; i < (int)input_size; i++) {
        result.push_back(outputShare::constant(open_mask[i], P.my_num(), out_arithmetic_mac_key) - shift_out_share - edabits_out_a[i]);

    }

//    std::cout << "custom calc " << bigint(-(typename outputShare::clear((1 << (inputShare::clear::n_bits() - 1))))).get_str(2) << " (" << -(typename outputShare::clear((1 << (inputShare::clear::n_bits() - 1)))) << ")" << endl;
//    std::cout << "custom cal3 " << bigint(-(typename outputShare::clear(1) << (inputShare::clear::n_bits() - 1))).get_str(2) << " (" << -(typename outputShare::clear(1) << (inputShare::clear::n_bits() - 1)) << ")" << endl;

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
                if (bigint(typename outputShare::clear(c - reals[i])) != 0) {
                    //                    std::cout << reals[i] << " " << c << reals[i] - c << std::endl;
//                    std::cout << bigint(c).get_str(2) << " != "
//                              << bigint(typename inputShare::clear(reals[i])).get_str(2)
//                              << std::endl; //base 2 representation
//
//                    std::cout << "Error: " << i << " " << bigint(c) << " != " << bigint(reals[i]) << endl;

//                    std::cout << "What I want: " << bigint(typename outputShare::clear(reals[i])).get_str(2) << " ("
//                              << bigint(typename outputShare::clear(reals[i])) << ")" << endl;
//                    std::cout << "What I have: " << bigint(c).get_str(2) << endl;
                    std::cout << c << " !=  "<< reals[i] << " Need shift   " << bigint(typename outputShare::clear(c - reals[i])).get_str(2) << "(" << typename outputShare::clear(c - reals[i]) << ")" << endl;
                    std::cout << bigint(c) << " !=bg " << bigint(reals[i]) << endl;
                    std::cout << "Bits were " << open_mask[i] << endl;
                    std::cout << "Masking was " << edabits_out_a[i] << endl;
                    std::cout << "Shift out was " << shift_out_t << endl;
                    std::cout << "n bits were " << n_bits_per_input << endl;
                    std::cout << "input size was " << input_size << endl;
                    std::cout << "thread number was " << omp_get_thread_num() << endl;
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
    (P.total_comm() - overall_stats).print(true);


    return result;
}

//11111111111111111111111111111111111111111111111100000000000000000
//                                              -100000000000000000

template<class inputShare>
std::vector<inputShare> distribute_inputs(Player &P, MixedProtocolSet<inputShare>& set, std::vector<std::vector<std::string> >& inputs_format_str, const int n_bits_per_input) {
    // this method loads inputs, distributes them, and returns the shares
    input_format_type inputs_format = process_format(inputs_format_str);

    std::vector<typename inputShare::clear> inputs;
    if (inputs_format[P.my_num()].size() > 0) {
        inputs = read_private_input<typename inputShare::clear>(P, inputs_format[P.my_num()]);
    }

//    for (unsigned long i = 0; i < inputs.size(); i++) {
//        std::cout << "Input " << i << " " << inputs[i] << std::endl;
//    }

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

    std::vector<inputShare> result;
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

    //    input.reset_all(P);
//    for (size_t i = begin; i < end; i++)
//    {
//        typename T::open_type x[2];
//        for (int j = 0; j < 2; j++)
//            this->get_input(triples[i][j], x[j], input_player);
//        if (P.my_num() == input_player)
//            input.add_mine(x[0] * x[1], T::default_length);
//        else
//            input.add_other(input_player);
//    }
//    input.exchange();
//    for (size_t i = begin; i < end; i++)
//        triples[i][2] = input.finalize(input_player, T::default_length);
//

}

template<class inputShare, class outputShare>
void run(int argc, const char** argv)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    SwitchOptions opts(opt, argc, argv);
    assert(opts.inputs_format.size() == 0 or opts.n_shares == 0); // can only specify one

//    opts.R_after_msg |= is_same<T<P256Element>, AtlasShare<P256Element>>::value;
    Names N(opt, argc, argv, 3);

    CryptoPlayer P(N, "pc");

    // protocol setup (domain, MAC key if needed etc)
    libff::bls12_377_pp::init_public_params();
    mpz_t t;
    mpz_init(t);
    P377Element::G1::order().to_mpz(t);
    bigint t_big(t);

    int bit_length = inputShare::clear::n_bits();

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
        outputShare::clear::init_field(t_big);
        outputShare::clear::next::init_field(t_big, false);

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
        outputShare::clear::init_field(t_big);
        outputShare::clear::next::init_field(t_big, false);

        input_shares = read_inputs<inputShare>(P, opts.n_shares, opts.start);
        log_name = "share_switch_output";
    } else if (opts.inputs_format.size() > 0) {

        MixedProtocolSetup<inputShare> setup_input(P, bit_length);
        MixedProtocolSet<inputShare> set_input(P, setup_input);

        ProtocolSetup<outputShare> setup_output(t_big, P);
        ProtocolSet<outputShare> set_output(P, setup_output);

        input_shares = distribute_inputs(P, set_input, opts.inputs_format, opts.n_bits_per_input);
        std::cout << "Done reading inputs" << endl;
        log_name = "share_switch_input";

        set_input.check();
        set_output.check();
    } else {
        std::cerr << "Must specify either n_shares or inputs_format," << std::endl;
        exit(1);
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
    const unsigned long n_chunks_per_thread = DIV_CEIL(input_shares.size(), opts.n_threads);
    const unsigned long mem_cutoff = opts.chunk_size;

    OnlineOptions::singleton.batch_size = min((unsigned long)50000, min(n_chunks_per_thread, mem_cutoff));
    OnlineOptions::singleton.verbose = true;
    std::cout << "Edabit batch size " << OnlineOptions::singleton.batch_size << ". Would have needed " << min(n_chunks_per_thread, mem_cutoff) << endl;

    const bigint shift_in = bigint(1) << (n_bits_per_input - 1);
    typename inputShare::clear shift_int_t = typename inputShare::clear(shift_in);
    typename outputShare::clear shift_out_t = typename outputShare::clear(bigint("1") << (n_bits_per_input - 1));

//    std::cout << "shift_in " << shift_in << " " << n_bits_per_input << " " << inputShare::clear::n_bits() << endl;
//    std::cout << "shift_out_t initially " << shift_out_t << " " << n_bits_per_input << " " << outputShare::clear::n_bits() << endl;

    std::cout << "Running in " << opts.n_threads << " threads" << endl;

#pragma omp parallel for num_threads(opts.n_threads)
    for (int j = 0; j < opts.n_threads; j++) {
        bigint::init_thread();

        const unsigned long begin_thread = j * n_chunks_per_thread;
        const unsigned long end_thread = min(((unsigned long) (j + 1) * n_chunks_per_thread), input_shares.size());
        assert(begin_thread < end_thread);

        const int n_chunks = DIV_CEIL(end_thread - begin_thread, mem_cutoff);

        stringstream stream;
        stream << "Thread " << j << "(" << omp_get_thread_num() << ") processing items (" << begin_thread << "-" << end_thread << ") in " << n_chunks << " chunks" << std::endl;
        cout << stream.str();

        CryptoPlayer P_j(N, j * opts.n_threads);

        MixedProtocolSetup<inputShare> setup_input_i(P_j, bit_length);
        MixedProtocolSet<inputShare> set_input_i(P_j, setup_input_i);

        ProtocolSetup<outputShare> setup_output_i(bigint(t), P_j);
        ProtocolSet<outputShare> set_output_i(P_j, setup_output_i);

        auto thread_local_stats = P.total_comm();

        for (int i = 0; i < n_chunks; i++) {
            const unsigned long begin_chunk = begin_thread + i * mem_cutoff;
            const unsigned long end_chunk = min(begin_chunk + mem_cutoff, end_thread);
            // each thread in parallel

            vector<outputShare> res = convert_shares(input_shares.begin() + begin_chunk, input_shares.begin() + end_chunk,
                                                     set_input_i, set_output_i, setup_input_i.get_mac_key(), setup_input_i.binary.get_mac_key(),
                                                     setup_output_i.get_mac_key(), P_j, n_bits_per_input,
                                                     shift_int_t, shift_out_t,
                                                     opts.debug);

//            result.insert(result.begin() + begin_chunk, res.begin(), res.end());
            for (unsigned long k = 0; k < res.size(); k++) {
                result[begin_chunk + k] = res[k];
            }

            stringstream stream2;
            stream2 << "Thread " << j << " done with chunk " << i << std::endl;
            cout << stream2.str();

            set_input_i.check();
            set_output_i.check();

        }

        set_input_i.check();
//        set_input_i.binary.thread.MC->get_part_MC().Check(P);
        set_output_i.check();

        auto thread_local_diff = P.total_comm() - thread_local_stats;
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

    P377Element::finish();
}
