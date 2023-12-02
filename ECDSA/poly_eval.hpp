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

P377Element random_elem(PRNG& G) {
    P377Element::Scalar r_scalar;
    r_scalar.randomize(G);
    return P377Element(r_scalar);
}

inline KZGPublicParameters get_public_parameters(int n_parameters, PRNG& G) {
    // TODO: Is this consistent across parties?
    // It seems if we call GlobalPRNG is becomes consistent globally across parties, but it is not always called
    // so we call it again in the auditable inference function

    KZGPublicParameters params;
    for (int i = 0; i < n_parameters; i++) {
        params.powers_of_g.push_back(random_elem(G));
    }

    params.g2 = random_elem(G);
    return params;
}


template<template<class U> class T>
void eval_point(
        ProtocolSet< T<P377Element::Scalar>> &set,
        Player& P,
        PEOptions& opts) {
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    SeededPRNG G;
//    G.SeedGlobally(P);

//    test_arith();
    std::vector<T<P377Element::Scalar> > inputs = read_inputs<T<P377Element::Scalar> >(P, opts.n_shares, opts.start, KZG_SUFFIX);

//    std::cout << "Share 0" << inputs[0] << std::endl;
//
//    // debug reconstruct
//    set.output.init_open(P, inputs.size());
//    for (unsigned long i = 0; i < inputs.size(); i++) {
//        set.output.prepare_open(inputs[i]);
//    }
//    set.output.exchange(P);
//    set.check();
//    for (unsigned long i = 0; i < inputs.size(); i++) {
//        P377Element::Scalar input = set.output.finalize_open();
//        cout << "input_" << i << " = " << input << endl;
//    }

    // generate random point
    T<P377Element::Scalar> beta_share = set.protocol.get_random();
    set.output.init_open(P);
    set.output.prepare_open(beta_share);
    set.output.exchange(P);
    set.check();
    P377Element::Scalar beta = set.output.finalize_open();
//    beta = P377Element::Scalar(1);

    P377Element::Scalar current_beta = 1;

    // Evaluate polynomial defined by inputs at beta
    T<P377Element::Scalar> result;
    for (int i = 0; i < opts.n_shares; i++) { // can we parallelize this?
        result += inputs[i] * current_beta;
        current_beta = current_beta * beta;
    }

    set.output.init_open(P);
    set.output.prepare_open(result);
    set.output.exchange(P);
    set.check();

    P377Element::Scalar rho = set.output.finalize_open();

    set.check();

    auto diff = (P.total_comm() - stats);
    cout << "Auditable inference took " << timer.elapsed() * 1e3 << " ms and sending "
         << diff.sent << " bytes" << endl;
    diff.print(true);

    print_timer("poly_eval", timer.elapsed());
    print_stat("poly_eval", diff);
    print_global("poly_eval", P, diff);

    std::cout << "input_consistency_player_" << opts.input_party_i << "_eval=(" << beta << "," << rho << ")" << endl;

}

#endif /* POLY_EVAL_HPP_ */
