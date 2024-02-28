/*
 * sign.hpp
 *
 */

#ifndef POLY_EVAL_HPP_
#define POLY_EVAL_HPP_

//#include "CurveElement.h"
#include "P377Element.h"
#include "Tools/Bundle.h"

#include "poly_commit.hpp"
#include "Math/gfp.hpp"
#include "Processor/Binary_File_IO.h"
#include "PEOptions.h"
#include "ECDSA/share_utils.hpp"

//#include "sign.hpp"

template<class Curve>
Curve random_elem(PRNG& G) {
    typename Curve::Scalar r_scalar;
    r_scalar.randomize(G);
    return Curve(r_scalar);
}

template<class Curve>
inline ECPublicParameters<Curve> get_public_parameters(int n_parameters, PRNG& G) {
    // TODO: Is this consistent across parties?
    // It seems if we call GlobalPRNG is becomes consistent globally across parties, but it is not always called
    // so we call it again in the auditable inference function

    ECPublicParameters<Curve> params;
    for (int i = 0; i < n_parameters; i++) {
        params.powers_of_g.push_back(random_elem<Curve>(G));
    }

    params.g2 = random_elem<Curve>(G);
    return params;
}


template<class share>
void eval_point(
        typename share::clear beta,
        ProtocolSet< share> &set,
        Player& P,
        PEOptions& opts) {
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    SeededPRNG G;
//    G.SeedGlobally(P);

//    test_arith();
    std::vector<share > inputs = read_inputs<share >(P, opts.n_shares, opts.start, KZG_SUFFIX);

    std::cout << "Share 0 " << inputs[0] << std::endl;

//    // debug reconstruct
//    vector< vector< string > > inputs_format_str;
//    vector<string> str_zero = { "i167090", "f41330048" };
//    inputs_format_str.push_back(str_zero);
//
//    input_format_type inputs_format = process_format(inputs_format_str);
//    std::vector<clr> private_inputs;
//    int pid_to_check = 0;
//    if (P.my_num() == pid_to_check and inputs_format[P.my_num()].size() > 0) {
//        private_inputs = read_private_input<clr>(P, inputs_format[P.my_num()]);
//    }
//    set.output.init_open(P, inputs.size());
//    for (unsigned long i = 0; i < inputs.size(); i++) {
//        set.output.prepare_open(inputs[i]);
//    }
//    set.output.exchange(P);
//    set.check();
//    std::cout << "Starting opening" << std::endl;
//    for (unsigned long i = 0; i < inputs.size(); i++) {
//        clr input = set.output.finalize_open();
//        if (P.my_num() == pid_to_check) {
//            if (input != private_inputs[i]) {
//                std::cout << "Input " << i << " does not match" << std::endl;
//                std::cout << "Expected " << private_inputs[i] << " but got " << input << std::endl;
//            }
//        }
//    }

    typename share::clear r;
    r.randomize(G);
    set.input.reset_all(P);
    if (opts.input_party_i == P.my_num()) {
        set.input.add_mine(r);
        std::cout << "input_consistency_random_value_" << opts.input_party_i << "=" << to_string(bigint(r)) << endl;
    } else {
        set.input.add_other(opts.input_party_i);
    }
    set.input.exchange();
//    set.check();
    share r_share = set.input.finalize(opts.input_party_i);

    // Evaluate polynomial defined by inputs at beta
    share result;
    result += r_share;
//    (void)r_share;

    typename share::clear current_beta = beta;
    for (int i = 0; i < opts.n_shares; i++) { // can we parallelize this?
        result += inputs[i] * current_beta;
        current_beta = current_beta * beta;
    }

    set.output.init_open(P);
    set.output.prepare_open(result);
    set.output.exchange(P);
    set.check();

    typename share::clear rho = set.output.finalize_open();

    set.check();

    auto diff = (P.total_comm() - stats);
    cout << "Polynomial evaluation took " << timer.elapsed() * 1e3 << " ms and sending "
         << diff.sent << " bytes" << endl;
    diff.print(true);

    print_timer("poly_eval", timer.elapsed());
    print_stat("poly_eval", diff);
    print_global("poly_eval", P, diff);

    std::cout << "input_consistency_player_" << opts.input_party_i << "_eval=(" << beta << "," << rho << ")" << endl;

}

#endif /* POLY_EVAL_HPP_ */
