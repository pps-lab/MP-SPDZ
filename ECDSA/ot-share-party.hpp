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

template<class inputShare>
std::vector<inputShare> distribute_inputs(Player &P, MixedProtocolSet<inputShare>& set, std::vector<std::vector<std::string> >& inputs_format_str, const int n_bits_per_input) {
    // this method loads inputs, distributes them, and returns the shares
    input_format_type inputs_format = process_format(inputs_format_str);

    std::vector<typename inputShare::clear> inputs;
    if (inputs_format[P.my_num()].size() > 0) {
        inputs = read_private_input<typename inputShare::clear>(P, inputs_format[P.my_num()]);
    }

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
}

template<class inputShare>
void run(int argc, const char** argv, int bit_length = -1, int n_players = 3)
{
    bigint::init_thread();
    ez::ezOptionParser opt;
    SwitchOptions opts(opt, argc, argv);
    assert(opts.inputs_format.size() == 0 or opts.n_shares == 0); // can only specify one

    Names N(opt, argc, argv, n_players);

    CryptoPlayer P(N, "convert");

    // protocol setup (domain, MAC key if needed etc)
    libff::bls12_377_pp::init_public_params();
    mpz_t t;
    mpz_init(t);
    P377Element::G1::order().to_mpz(t);
    bigint t_big(t);

    // TODO: Hardcoded
    string prefix = get_prep_sub_dir<inputShare>("Player-Data", n_players, 253);
//    string prefix = "2-p-253";
    std::cout << "Loading mac from " << prefix << endl;

    if (bit_length == -1) {
//        bit_length = inputShare::clear::n_bits();
        bit_length = 253;
    }

    std::cout << "inputs format" << endl;
    for(unsigned long i = 0; i < opts.inputs_format.size(); i++) {
        for(unsigned long j = 0; j < opts.inputs_format[i].size(); j++) {
            std::cout << opts.inputs_format[i][j] << " ";
        }
        std::cout << std::endl;
    }

    Timer timer;
    timer.start();
    auto stats = P.total_comm();

    MixedProtocolSetup<inputShare> setup_input(t_big, P, prefix);
    MixedProtocolSet<inputShare> set_input(P, setup_input);

    auto input_shares = distribute_inputs(P, set_input, opts.inputs_format, opts.n_bits_per_input);
    std::cout << "Done reading inputs" << endl;
    string log_name = "share_switch_input";

    set_input.check();

    // save those to file
    std::cout << "Saving unconverted shares " << endl;
    bool overwrite = opts.output_start == 0;
    write_shares<inputShare>(P, input_shares, KZG_SUFFIX, overwrite, opts.output_start);

    auto diff = P.total_comm() - stats;
    print_timer(log_name, timer.elapsed());
    print_stat(log_name, diff);
    print_global(log_name, P, diff);

//
//    std::cout << "Share 0 after reading " << check_shares[0] << std::endl;
//    std::cout << "Prime " << P377Element::Scalar::pr() << std::endl;

    P377Element::finish();
}
