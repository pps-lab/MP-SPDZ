/*
 * sign.hpp
 *
 */

#ifndef AUDITABLE_HPP_
#define AUDITABLE_HPP_

//#include "CurveElement.h"
#include "P256Element.h"
#include "Tools/Bundle.h"

#include "poly_commit.hpp"
#include "Math/gfp.hpp"
#include "PCOptions.h"


P256Element random_elem(PRNG& G) {
    P256Element::Scalar r_scalar;
    r_scalar.randomize(G);
    return P256Element(r_scalar);
}

inline KZGPublicParameters get_public_parameters(int n_parameters, PRNG& G) {
    // TODO: Is this consistent across parties?

    KZGPublicParameters params;
    for (int i = 0; i < n_parameters; i++) {
        params.powers_of_g.push_back(random_elem(G));
    }

    params.g2 = random_elem(G);
    return params;
}


template<template<class U> class T>
void auditable_inference(
        typename T<P256Element>::MAC_Check& MCc,
        Player& P,
        PCOptions& opts,
        typename T<P256Element::Scalar>::TriplePrep& prep)
{

    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    SeededPRNG G;

    cout << "Prediction for " << opts.poly_dims.size() << " polynomials" << endl;

    // TODO: Load additional commitments to the 'datasets'!
    std::vector<KZGCommitment> datasets;
    KZGCommitment model = KZGCommitment { random_elem(G) };
    for (int i = 0; i < opts.n_datasets; i++) {
        datasets.push_back(KZGCommitment { random_elem(G) });
    }

    int n_parameters = max_element(opts.poly_dims.begin(), opts.poly_dims.end()).operator*();
    KZGPublicParameters publicParameters = get_public_parameters(n_parameters, G);

    std::vector<KZGCommitment> commitments;

    for (int size : opts.poly_dims) {
        // Proof for each size poly commitment
        std::cout << "Committing to polynomial of size " << size << endl;
        Polynomial<T> polynomial;

        // Fill poly up to size
        for (int i = 0; i < n_parameters; i++)
        {
            // inefficient, uses a triple for each input!
            T<P256Element::Scalar> k[3];
            prep.get_three_no_count(DATA_TRIPLE, k[0], k[1], k[2]); // this takes data
//            prep.get_three(DATA_TRIPLE, k[0], k[1], k[2]);

            polynomial.coeffs.push_back(k[0]);
        }

        assert(polynomial.coeffs.size() <= publicParameters.powers_of_g.size());

        commitments.push_back(commit_and_open(polynomial, publicParameters, MCc, P));
    }

    // Now we compute the hash of the concatenation!
    // Length of P256 is 33 bits + 8 bits for the length!

    const int commitment_size = 41;
    int expected_size = (commitment_size * datasets.size()) + (commitment_size * opts.poly_dims.size()) + commitment_size;

    octetStream os;
    model.c.pack(os);
    for (auto& dataset : datasets) {
        dataset.c.pack(os);
    }
    for (auto& commitment : commitments) {
        commitment.c.pack(os);
    }
    assert((int)os.get_length() == expected_size);

    auto diff = (P.total_comm() - stats);
    cout << "Auditable inference took " << timer.elapsed() * 1e3 << " ms and sending "
         << diff.sent << " bytes" << endl;
    diff.print(true);

}

//template<template<class U> class T>
//void sign_benchmark(vector<Polynomial<T>>& polys, T<P256Element::Scalar> sk,
//        typename T<P256Element::Scalar>::MAC_Check& MCp, Player& P,
//        EcdsaOptions& opts,
//        SubProcessor<T<P256Element::Scalar>>* proc = 0)
//{
//    unsigned char message[1024];
//    GlobalPRNG(P).get_octets(message, 1024);
//    typename T<P256Element>::Direct_MC MCc(MCp.get_alphai());
//
//    // synchronize
//    Bundle<octetStream> bundle(P);
//    P.unchecked_broadcast(bundle);
//    Timer timer;
//    timer.start();
//    auto stats = P.total_comm();
//    P256Element pk = MCc.open(sk, P);
//    MCc.Check(P);
//    cout << "Public key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
//    (P.total_comm() - stats).print(true);
//
//    for (size_t i = 0; i < min(10lu, tuples.size()); i++)
//    {
//        check(sign(message, 1 << i, tuples[i], MCp, MCc, P, opts, pk, sk, proc), message,
//                1 << i, pk);
//        if (not opts.check_open)
//            continue;
//        Timer timer;
//        timer.start();
//        auto& check_player = MCp.get_check_player(P);
//        auto stats = check_player.total_comm();
//        MCp.Check(P);
//        MCc.Check(P);
//        auto diff = (check_player.total_comm() - stats);
//        cout << "Online checking took " << timer.elapsed() * 1e3 << " ms and sending "
//            << diff.sent << " bytes" << endl;
//        diff.print();
//    }
//}

#endif /* AUDITABLE_HPP_ */
