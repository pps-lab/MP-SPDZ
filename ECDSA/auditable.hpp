/*
 * sign.hpp
 *
 */

#ifndef AUDITABLE_HPP_
#define AUDITABLE_HPP_

//#include "CurveElement.h"
#include "P377Element.h"
#include "Tools/Bundle.h"

#include "poly_commit.hpp"
#include "Math/gfp.hpp"
#include "Processor/Binary_File_IO.h"
#include "PCOptions.h"
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
std::string auditable_inference(
        typename T<P377Element>::MAC_Check& MCc,
        Player& P,
        PCOptions& opts)
{
    SeededPRNG G;
    G.SeedGlobally(P);

//    test_arith();
    std::vector<KZGCommitment> commitments;

    int commitment_sizes_arr[] = { opts.n_model, opts.n_x, opts.n_y };
    std::vector<int> commitment_sizes(commitment_sizes_arr, commitment_sizes_arr + 3);
    int n_parameters = max_element(commitment_sizes.begin(), commitment_sizes.end()).operator*();
    KZGPublicParameters publicParameters = get_public_parameters(n_parameters, G);

    Timer timer;
    timer.start();
    auto stats = P.total_comm();

    std::vector<T<P377Element>> commitment_shares;
    int start = opts.start;
    for (int size : commitment_sizes) {
        // Proof for each size poly commitment
        if (size == 0) {
            continue;
        }
        std::cout << "Committing to polynomial of size " << size << endl;
        std::vector< T<P377Element::Scalar> > input = read_inputs<T<P377Element::Scalar> >(P, size, start, KZG_SUFFIX);

        InputPolynomial<T> polynomial;
        for (int i = 0; i < size; i++)
        {
            polynomial.coeffs.push_back(input[i]);
        }

        assert(polynomial.coeffs.size() <= publicParameters.powers_of_g.size());

        commitment_shares.push_back(commit_and_open(polynomial, publicParameters));
        start = start + size;
    }

    vector<P377Element> commitment_elements;
    MCc.POpen_Begin(commitment_elements, commitment_shares, P);
    MCc.POpen_End(commitment_elements, commitment_shares, P);

    // We do this once for all the commitments, because of the protocol
    MCc.Check(P);

    for (int i = 0; i < (int)commitment_elements.size(); i++) {
        commitments.push_back(KZGCommitment { commitment_elements[i] });
    }

    auto diff = (P.total_comm() - stats);
    cout << "Auditable inference took " << timer.elapsed() * 1e3 << " ms and sending "
         << diff.sent << " bytes" << endl;
    diff.print(true);

    print_timer("commit", timer.elapsed());
    print_stat("commit", diff);
    print_global("commit", P, diff);

    // Now we compute the hash of the concatenation!
    octetStream os;
    for (auto& commitment : commitments) {
        commitment.c.pack(os);
    }
    std::cout << "Generated " << commitments.size() << " commitments of total size " << os.get_length() << endl;
//    std::cout << "SIZE " << os.get_length() << endl;

//    P256Element::Scalar sk;
//    sk.randomize(G);

    string message = os.str();
    return message;

//    auto sig = sign((const unsigned char *) message.c_str(), message.length(), sk);
//    std::cout << "Signature: " << sig.R << " " << sig.s << endl;

//    const int commitment_size = 41;
//    int expected_size = (commitment_size * datasets.size()) + (commitment_size * opts.poly_dims.size()) + commitment_size;

//    octetStream os;
//    model.c.pack(os);
//    for (auto& dataset : datasets) {
//        dataset.c.pack(os);
//    }
//    for (auto& commitment : commitments) {
//        commitment.c.pack(os);
//    }
//    cout << "SIZE " << os.get_length() << endl;
//    assert((int)os.get_length() == expected_size);


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
