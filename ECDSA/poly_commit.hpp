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

template<class Curve>
class ECPublicParameters {
public:
    vector<Curve> powers_of_g;
    Curve g2;
};

template<class T>
class InputPolynomial {
public:
    vector<T> coeffs;
};

template<class Curve>
class ECVectorCommitment {
public:
    Curve c;
};


class KZGProof
{
public:
    P377Element w;
    P377Element::Scalar rho;
};

template<template<class U> class T, class Curve>
void ecscalarmulshare(T<Curve> pointshare, typename Curve::Scalar multiplier, T<Curve>& result){
//    result.set_share(pointshare.get_share() * multiplier);
//    result.set_mac(pointshare.get_mac() * multiplier);
    result = pointshare * multiplier;
}

// Function for Scalar multiplication of a clear p256 and a shared gfp
template<template<class U> class T, class Curve>
void ecscalarmulshare(Curve point, T<typename Curve::Scalar> multiplierShare, T<Curve>& result){
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

//template <template<class U> class T>
//T<P377Element> msm(std::vector<P377Element>& bases, std::vector<T<P377Element::Scalar>> & multipliers){
//
//    // loop through multipliers and put into separate vector
//    std::vector<libff::bls12_377_Fr> share1;
//    std::vector<libff::bls12_377_Fr> share2;
//    for (unsigned long i = 0; i < multipliers.size(); i++) {
//        // probably this conversion can be faster
//        auto ps1 = libff::bls12_377_Fr(bigint(multipliers[i].get()[0]).get_str().c_str());
//        auto ps2 = libff::bls12_377_Fr(bigint(multipliers[i].get()[1]).get_str().c_str());
//
//        share1.push_back(ps1);
//        share2.push_back(ps2);
//    }
//
//    assert(bases.size() >= multipliers.size());
//    std::vector<P377Element::G1> bases_format(multipliers.size());
//    for (unsigned long i = 0; i < multipliers.size(); i++) {
//        bases_format[i] = bases[i].get_point();
//    }
//
//    std::cout << bases.size() << " and " << multipliers.size() << " and " << share1.size() << std::endl;
//
//    size_t parts = 1; // TODO: Make this configurable
//    if (multipliers.size() > 100000) {
//        parts = 8; // something like this?
//    }
//
//    P377Element::G1 sum1 = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
//                                                                                                              share1.begin(), share1.end(), parts);
//    P377Element::G1 sum2 = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
//                                                                                                              share2.begin(), share2.end(), parts);
//    array<P377Element, 2> result_shares = { P377Element(sum1), P377Element(sum2) };
//
//    return T<P377Element>(result_shares);
//}

// this is a specific, optimized function for this set of shares (although the num conversion could be better)
template <template<class U> class T, class Curve>
T<Curve> msm(std::vector<Curve>& bases, std::vector<T<typename Curve::Scalar>> & multipliers){

    // loop through multipliers and put into separate vector
    std::vector<typename Curve::Scalar> share1;
    std::vector<typename Curve::Scalar> share2;
    for (unsigned long i = 0; i < multipliers.size(); i++) {
        // probably this conversion can be faster
        auto ps1 = multipliers[i].get()[0];
        auto ps2 = multipliers[i].get()[1];

        share1.push_back(ps1);
        share2.push_back(ps2);
    }

    assert(bases.size() >= multipliers.size());

    // Make sure we only pass number of bases on the size of the multipliers
    // Make a copy of bases vec of max size multipliers.size
    std::vector<Curve> bases_short(bases.begin(), bases.begin() + multipliers.size());
//    std::vector<P377Element::G1> bases_format(multipliers.size());
//    for (unsigned long i = 0; i < multipliers.size(); i++) {
//        bases_format[i] = bases[i].get_point();
//    }

    std::cout << bases_short.size() << " and " << multipliers.size() << " and " << share1.size() << std::endl;

    size_t parts = 1; // TODO: Make this configurable
    if (multipliers.size() > 100000) {
        parts = 8; // something like this?
    }

    Curve sum1 = libff::multi_exp<Curve, typename Curve::Scalar, libff::multi_exp_method_BDLO12>(bases_short.begin(), bases_short.end(),
                                                                                      share1.begin(), share1.end(), parts);
    Curve sum2 = libff::multi_exp<Curve, typename Curve::Scalar, libff::multi_exp_method_BDLO12>(bases_short.begin(), bases_short.end(),
                                                                                                      share2.begin(), share2.end(), parts);
    array<Curve, 2> result_shares = { Curve(sum1), Curve(sum2) };

    return T<Curve>(result_shares);
}

Share<P377Element> msm(std::vector<P377Element>& bases, std::vector<Share<P377Element::Scalar>> & multipliers){

    std::vector<P377Element::Fr> multiplier_shares(multipliers.size());
    std::vector<P377Element::Fr> multiplier_macs(multipliers.size());
    for (unsigned long i = 0; i < multipliers.size(); i++) {
        P377Element::Scalar sh = multipliers[i].get_share();
        P377Element::Scalar m = multipliers[i].get_mac();
        multiplier_shares[i] = libff::bls12_377_Fr(bigint(sh).get_str().c_str());
        multiplier_macs[i] = libff::bls12_377_Fr(bigint(m).get_str().c_str());
    }

    std::vector<P377Element::G1> bases_format(bases.size());
    for (unsigned long i = 0; i < bases.size(); i++) {
        bases_format[i] = bases[i].get_point();
    }

    size_t parts = 1; // TODO: Make this configurable
    if (multipliers.size() > 100000) {
        parts = 8; // something like this?
    }
    P377Element::G1 result_share = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
                                                                                                              multiplier_shares.begin(), multiplier_shares.end(), parts);
    P377Element::G1 result_mac = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
                                                                                                              multiplier_macs.begin(), multiplier_macs.end(), parts);

    auto semi_sh = SemiShare<P377Element>(P377Element(result_share));
    auto semi_mac = SemiShare<P377Element>(P377Element(result_mac));

    return Share(semi_sh, semi_mac);
}

SemiShare<P377Element> msm(std::vector<P377Element>& bases, std::vector<SemiShare<P377Element::Scalar>> & multipliers){

    std::vector<P377Element::Fr> multiplier_shares(multipliers.size());
//    std::vector<P377Element::Fr> multiplier_macs(multipliers.size());
    for (unsigned long i = 0; i < multipliers.size(); i++) {
        P377Element::Scalar sh = multipliers[i];
        multiplier_shares[i] = libff::bls12_377_Fr(bigint(sh).get_str().c_str());
    }

    std::vector<P377Element::G1> bases_format(bases.size());
    for (unsigned long i = 0; i < bases.size(); i++) {
        bases_format[i] = bases[i].get_point();
    }

    size_t parts = 1; // TODO: Make this configurable
    if (multipliers.size() > 100000) {
        parts = 8; // something like this?
    }
    P377Element::G1 result_share = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
                                                                                                                      multiplier_shares.begin(), multiplier_shares.end(), parts);
//    P377Element::G1 result_mac = libff::multi_exp<P377Element::G1, P377Element::Fr, libff::multi_exp_method_BDLO12>(bases_format.begin(), bases_format.end(),
//                                                                                                                    multiplier_macs.begin(), multiplier_macs.end(), parts);

    auto semi_sh = SemiShare<P377Element>(P377Element(result_share));
//    auto semi_mac = SemiShare<P377Element>(P377Element(result_mac));

    return semi_sh;
}


template<template<class U> class T, class Curve>
T<Curve> commit_and_open(
        InputPolynomial<T<typename Curve::Scalar>> tuple,
        ECPublicParameters<Curve> kzgPublicParameters)
{
    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());

    Timer msm_timer;
    msm_timer.start();

    T<Curve> sum = msm(kzgPublicParameters.powers_of_g, tuple.coeffs);

    auto diff_msm = msm_timer.elapsed();
    cout << "MSM took " << diff_msm * 1e3 << " ms" << endl;
    // optimize with MSM

    return sum;
}

template<template<class U> class T, class Curve>
std::vector<T<Curve>> commit_individual(
        InputPolynomial<T<typename Curve::Scalar>> tuple,
        std::vector<T<typename Curve::Scalar>> randomness,
        ECPublicParameters<Curve> kzgPublicParameters)
{
    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());
    assert(tuple.coeffs.size() == randomness.size());

    Timer msm_timer;
    msm_timer.start();

    std::vector<T<Curve>> result;
    for (unsigned long i = 0; i < tuple.coeffs.size(); i++) {
        Curve sum1 = kzgPublicParameters.powers_of_g[0] * tuple.coeffs[i].get()[0];
        Curve sum2 = kzgPublicParameters.powers_of_g[0] * tuple.coeffs[i].get()[1];

        sum1 += kzgPublicParameters.powers_of_g[1] * randomness[i].get()[0];
        sum2 += kzgPublicParameters.powers_of_g[1] * randomness[i].get()[1];

        array<Curve, 2> result_shares = { Curve(sum1), Curve(sum2) };

        result.push_back(T<Curve>(result_shares));
    }

    auto diff_msm = msm_timer.elapsed();
    cout << "Exponentiation took " << diff_msm * 1e3 << " ms" << endl;
    // optimize with MSM

    return result;
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
