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


template<template<class U> class T, class Curve, template<class> class Commitment>
std::string generate_vector_commitments(
        typename T<Curve>::MAC_Check& MCc,
        Player& P,
        PCOptions& opts)
{
    SeededPRNG G;
    G.SeedGlobally(P);

//    test_arith();
    std::vector<Commitment<Curve>> commitments;

    int commitment_sizes_arr[] = { opts.n_model, opts.n_x, opts.n_y };
    std::vector<int> commitment_sizes(commitment_sizes_arr, commitment_sizes_arr + 3);
    int n_parameters = max_element(commitment_sizes.begin(), commitment_sizes.end()).operator*();
    ECPublicParameters publicParameters = get_public_parameters<Curve>(n_parameters, G);

    Timer timer;
    timer.start();
    auto stats = P.total_comm();

    std::vector<T<Curve>> commitment_shares;
    int start = opts.start;
    typedef T<typename Curve::Scalar> inputShare;
    for (int size : commitment_sizes) {
        // Proof for each size poly commitment
        if (size == 0) {
            continue;
        }
        std::cout << "Committing to polynomial of size " << size << endl;
        std::vector< inputShare > input = read_inputs<inputShare >(P, size, start, KZG_SUFFIX);

        InputPolynomial<inputShare> polynomial;
        for (int i = 0; i < size; i++)
        {
            polynomial.coeffs.push_back(input[i]);
        }

        assert(polynomial.coeffs.size() <= publicParameters.powers_of_g.size());

        commitment_shares.push_back(commit_and_open<T, Curve>(polynomial, publicParameters));
        start = start + size;
    }

    vector<Curve> commitment_elements;
    MCc.POpen_Begin(commitment_elements, commitment_shares, P);
    MCc.POpen_End(commitment_elements, commitment_shares, P);

    // We do this once for all the commitments, because of the protocol
    MCc.Check(P);

    for (int i = 0; i < (int)commitment_elements.size(); i++) {
        commitments.push_back(Commitment<Curve> { commitment_elements[i] });
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

    string message = os.str();
    return message;
}


template<template<class U> class T, class Curve>
std::string generate_individual_commitments(
        typename T<Curve>::MAC_Check& MCc,
        ProtocolSet< T<typename Curve::Scalar> > set,
        Player& P,
        PCOptions& opts)
{
    SeededPRNG G;
    G.SeedGlobally(P);

//    test_arith();
    int commitment_sizes_arr[] = { opts.n_model, opts.n_x, opts.n_y };
    std::vector<int> commitment_sizes(commitment_sizes_arr, commitment_sizes_arr + 3);
    int n_parameters = max_element(commitment_sizes.begin(), commitment_sizes.end()).operator*();
    ECPublicParameters publicParameters = get_public_parameters<Curve>(n_parameters, G);

    Timer timer;
    timer.start();
    auto stats = P.total_comm();

    std::vector<std::vector<T<Curve>>> commitment_shares;
    int start = opts.start;
    typedef T<typename Curve::Scalar> inputShare;
    for (int size : commitment_sizes) {
        // Proof for each size poly commitment
        if (size == 0) {
            continue;
        }
        std::cout << "Committing to polynomial of size " << size << " with individual commitments" << endl;
        std::vector< inputShare > input = read_inputs<inputShare >(P, size, start, KZG_SUFFIX);

        InputPolynomial<inputShare> polynomial;
        vector<inputShare> randomness;
        for (int i = 0; i < size; i++)
        {
            polynomial.coeffs.push_back(input[i]);

            inputShare random_share = set.protocol.get_random();
            randomness.push_back(random_share);
        }

        assert(polynomial.coeffs.size() <= publicParameters.powers_of_g.size());

        commitment_shares.push_back(commit_individual(polynomial, randomness, publicParameters));

        start = start + size;
    }

    vector<vector<Curve>> commitment_elements;
    for (int i = 0; i < (int)commitment_shares.size(); i++) {
        vector<Curve> commitment_elements_i;
        MCc.POpen_Begin(commitment_elements_i, commitment_shares[i], P);
        MCc.POpen_End(commitment_elements_i, commitment_shares[i], P);
        commitment_elements.push_back(commitment_elements_i);
    }

    // We do this once for all the commitments, because of the protocol
    MCc.Check(P);

    auto diff = (P.total_comm() - stats);
    cout << "Auditable inference took " << timer.elapsed() * 1e3 << " ms and sending "
         << diff.sent << " bytes" << endl;
    diff.print(true);

    print_timer("commit", timer.elapsed());
    print_stat("commit", diff);
    print_global("commit", P, diff);

    // Now we compute the hash of the concatenation!
    octetStream os;
    for (auto& commitment_vec : commitment_elements) {
        for (auto& commitment : commitment_vec) {
            commitment.pack(os);
        }
    }
    std::cout << "Generated " << commitment_elements.size() << " commitments vectors of total size " << os.get_length() << endl;

    string message = os.str();
    return message;
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
