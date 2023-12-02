/*
 * sign.hpp
 *
 */

#ifndef POLY_COMMIT_HPP_
#define POLY_COMMIT_HPP_

//#include "CurveElement.h"
#include "P377Element.h"
#include "Tools/Bundle.h"

#include "preprocessing.hpp"
#include "Math/gfp.hpp"

#include "PCOptions.h"

#include <libff/algebra/scalar_multiplication/multiexp.hpp>

class KZGPublicParameters {
public:
    vector<P377Element> powers_of_g;
    P377Element g2;

};

template<template<class U> class T>
class InputPolynomial {
public:
    vector<T<typename P377Element::Scalar> > coeffs;
};

class KZGCommitment {
public:
    P377Element c;
};


class KZGProof
{
public:
    P377Element w;
    P377Element::Scalar rho;
};

template<template<class U> class T>
void ecscalarmulshare(T<P377Element> pointshare, P377Element::Scalar multiplier, T<P377Element>& result){
//    result.set_share(pointshare.get_share() * multiplier);
//    result.set_mac(pointshare.get_mac() * multiplier);
    result = pointshare * multiplier;
}

// Function for Scalar multiplication of a clear p256 and a shared gfp
template<template<class U> class T>
void ecscalarmulshare(P377Element point, T<P377Element::Scalar> multiplierShare, T<P377Element>& result){
    result.set_share(point * multiplierShare.get_share());
    result.set_mac(point * multiplierShare.get_mac());
}

//template<template<class U> class T>
//void ecscalarmulshare(T<P377Element> pointshare, P377Element::Scalar multiplier, T<P377Element>& result) {
//    // General implementation
//    cout << "ERROR NOT IMPLEMENTED" << endl;
//    (void) pointshare;
//    (void) multiplier;
//    (void) result;
//    exit(1);
//}
//template<template<class U> class T>
//void ecscalarmulshare(P377Element point, T<P377Element::Scalar> multiplierShare, T<P377Element>& result) {
//    // General implementation
//    cout << "ERROR NOT IMPLEMENTED" << endl;
//    (void) point;
//    (void) multiplierShare;
//    (void) result;
//    exit(1);
//}
//
//template<>
//void ecscalarmulshare(Share<P377Element> pointshare, P377Element::Scalar multiplier, Share<P377Element>& result){
//    result.set_share(pointshare.get_share() * multiplier);
//    result.set_mac(pointshare.get_mac() * multiplier);
//}
//
//// Function for Scalar multiplication of a clear p256 and a shared gfp
//template<>
//void ecscalarmulshare(P377Element point, Share<P377Element::Scalar> multiplierShare, Share<P377Element>& result){
//    result.set_share(point * multiplierShare.get_share());
//    result.set_mac(point * multiplierShare.get_mac());
//}
//
//template<>
//void ecscalarmulshare(Rep3Share<P377Element> pointshare, P377Element::Scalar multiplier, Rep3Share<P377Element>& result){
//    result = pointshare * multiplier;
//}


//// Function for Scalar multiplication of a clear p256 and a shared gfp
template<>
void ecscalarmulshare(P377Element point, Rep3Share<P377Element::Scalar> multiplierShare, Rep3Share<P377Element>& result){

    // This is ugly and specific for Rep3Share!!
    // We need: for each share in multiplierShare, get the value, multiply with point
    const array<P377Element::Scalar, 2>& shares = multiplierShare.get();
    array<P377Element, 2> result_shares;
    for (int i = 0; i < 2; i++) {
        P377Element::Scalar share = shares[i];
        P377Element result_share = point * share;
        result_shares[i] = result_share;
    }

    result = Rep3Share<P377Element>(result_shares);
}

// this is a specific, optimized functino for this set of shares (although the num conversino could be better)
template <template<class U> class T>
T<P377Element> msm(std::vector<P377Element>& bases, std::vector<T<P377Element::Scalar>> & multipliers){

    // loop through multipliers and put into separate vector
    std::vector<libff::bls12_377_Fr> share1;
    std::vector<libff::bls12_377_Fr> share2;
    for (unsigned long i = 0; i < multipliers.size(); i++) {
        // probably this conversion can be faster
        auto ps1 = libff::bls12_377_Fr(bigint(multipliers[i].get()[0]).get_str().c_str());
        auto ps2 = libff::bls12_377_Fr(bigint(multipliers[i].get()[1]).get_str().c_str());

        share1.push_back(ps1);
        share2.push_back(ps2);
    }

    std::vector<P377Element::G1> bases_format(bases.size());
    for (unsigned long i = 0; i < bases.size(); i++) {
        bases_format[i] = bases[i].get_point();
    }

    const size_t parts = 36; // TODO: Make this configurable

    P377Element::G1 sum1 = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
                                                                                                     share1.begin(), share1.end(), parts);
    P377Element::G1 sum2 = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
                                                                                                      share2.begin(), share2.end(), parts);
    array<P377Element, 2> result_shares = { P377Element(sum1), P377Element(sum2) };

    return T<P377Element>(result_shares);
}


//Share<P377Element> msm(std::vector<P377Element>& bases, std::vector<Share<P377Element::Scalar>> & multipliers){
//
//    std::vector<P377Element::Fr> multiplier_shares(multipliers.size());
//    std::vector<P377Element::Fr> multiplier_macs(multipliers.size());
//    for (unsigned long i = 0; i < multipliers.size(); i++) {
//        multiplier_shares[i] = libff::bls12_377_Fr(bigint(multipliers[i].get_share()).get_str().c_str());
//        multiplier_macs[i] = libff::bls12_377_Fr(bigint(multipliers[i].get_mac()).get_str().c_str());
//    }
//
//    std::vector<P377Element::G1> bases_format(bases.size());
//    for (unsigned long i = 0; i < bases.size(); i++) {
//        bases_format[i] = bases[i].get_point();
//    }
//
//    const size_t parts = 36; // TODO: Make this configurable
//
//    P377Element::G1 result_share = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
//                                                                                                              multiplier_shares.begin(), multiplier_shares.end(), parts);
//    P377Element::G1 result_mac = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
//                                                                                                              multiplier_macs.begin(), multiplier_macs.end(), parts);
//
//    return Share(P377Element(result_share), P377Element(result_mac));
//}



template<template<class U> class T>
KZGCommitment commit_and_open(
        InputPolynomial<T> tuple,
        KZGPublicParameters kzgPublicParameters,
        typename T<P377Element>::MAC_Check& MCc,
        Player& P)
{
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    KZGCommitment signature;

    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());

    // Opening tuple coeffs is working
//    typename T<P377Element::Scalar>::Direct_MC MCp(MCc.get_alphai());
//    vector<P377Element::Scalar> test_element;
//    tuple.coeffs[0] = tuple.coeffs[0] * 2;
//    MCp.POpen_Begin(test_element, tuple.coeffs, P);
//    MCp.POpen_End(test_element, tuple.coeffs, P);
//    std::cout << "OPEN TEST ELEM " << test_element[0] << endl;

    Timer msm_timer;
    msm_timer.start();

    T<P377Element> sum = msm(kzgPublicParameters.powers_of_g, tuple.coeffs);

//    T<P377Element> sum;
//    for (unsigned long i = 0; i < tuple.coeffs.size(); ++i) {
//        // This is technically a share!!
//        T<P377Element> result;
////        std::cout << "Before " << result.get()[0] << " " << result.get()[1] << std::endl;
////        std::cout << "KZG " << i << ": " << kzgPublicParameters.powers_of_g[i];
//        ecscalarmulshare(kzgPublicParameters.powers_of_g[i], tuple.coeffs[i], result);
////        std::cout << "After " << result.get()[0] << " " << result.get()[1] << std::endl; // these should be diff due to coeffs diff
////        std::cout << "Before " << result.get_share() << std::endl;
//
//
//        sum = sum + result;
//    }

    auto diff_msm = msm_timer.elapsed();
    cout << "MSM took " << diff_msm * 1e3 << " ms" << endl;
    // optimize with MSM


    vector<T<P377Element> > commitment_share = { sum };

    vector<P377Element> commitment_element;
    MCc.POpen_Begin(commitment_element, commitment_share, P);
    MCc.POpen_End(commitment_element, commitment_share, P);

    MCc.Check(P);


//    std::cout << "After open " << commitment_element[0] << endl;

    auto diff = (P.total_comm() - stats);
    cout << "Commitment took " << timer.elapsed() * 1e3 << " ms and sending "
         << diff.sent << " bytes" << endl;
    diff.print(true);

    return KZGCommitment { commitment_element[0] };
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

#endif /* POLY_COMMIT_HPP_ */
