


#ifndef MAL_POLY_COMMIT_HPP_
#define MAL_POLY_COMMIT_HPP_

#include "P377Element.h"
#include "poly_commit.hpp"

// Ideally we get a better abstraction in the future

template<template<class U> class T, class Curve>
void ecscalarmulshare(Curve point, SpdzWiseShare<T<typename Curve::Scalar> > multiplierShare, SpdzWiseShare<T<Curve> >& result){

//    T<P377Element> result_share;
//    T<P377Element> result_mac;
    T<typename Curve::Scalar> multiplier_share = multiplierShare.get_share();
    T<typename Curve::Scalar> multiplier_mac = multiplierShare.get_mac();

    const array<typename Curve::Scalar, 2>& shares = multiplier_share.get();
    array<Curve, 2> result_shares;
    for (int i = 0; i < 2; i++) {
        typename Curve::Scalar share = shares[i];
        Curve result_share = point * share;
        result_shares[i] = result_share;
    }
    auto result_share = T<Curve>(result_shares);

    const array<typename Curve::Scalar, 2>& shares_mac = multiplier_mac.get();
    array<Curve, 2> result_shares_mac;
    for (int i = 0; i < 2; i++) {
        typename Curve::Scalar share = shares_mac[i];
        Curve result_share = point * share;
        result_shares_mac[i] = result_share;
    }
    auto result_mac = T<Curve>(result_shares_mac);

    result.set_share(result_share);
    result.set_mac(result_mac);
}

template<class Curve>
SpdzWiseShare<MaliciousRep3Share<Curve>> msm(std::vector<Curve>& bases, std::vector<SpdzWiseShare<MaliciousRep3Share<typename Curve::Scalar>>> & multipliers){

    std::vector<MaliciousRep3Share<typename Curve::Scalar> > multiplier_shares(multipliers.size());
    std::vector<MaliciousRep3Share<typename Curve::Scalar> > multiplier_macs(multipliers.size());
    for (unsigned long i = 0; i < multipliers.size(); i++) {
        multiplier_shares[i] = multipliers[i].get_share();
        multiplier_macs[i] = multipliers[i].get_mac();
    }

    MaliciousRep3Share<Curve> result_share = msm(bases, multiplier_shares);
    MaliciousRep3Share<Curve> result_mac = msm(bases, multiplier_macs);

    return SpdzWiseShare(result_share, result_mac);
}

template<class Curve>
std::vector<SpdzWiseRepFieldShare<Curve>> commit_individual(
        InputPolynomial<SpdzWiseRepFieldShare<typename Curve::Scalar>> tuple,
        std::vector<SpdzWiseRepFieldShare<typename Curve::Scalar>> randomness,
        ECPublicParameters<Curve> kzgPublicParameters)
{
    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());
    assert(tuple.coeffs.size() == randomness.size());

    Timer msm_timer;
    msm_timer.start();

    std::vector<SpdzWiseRepFieldShare<Curve>> result;
    for (unsigned long i = 0; i < tuple.coeffs.size(); i++) {
        SpdzWiseRepFieldShare<Curve> result_g;
        ecscalarmulshare(kzgPublicParameters.powers_of_g[0], tuple.coeffs[i], result_g);
        SpdzWiseRepFieldShare<Curve> result_h;
        ecscalarmulshare(kzgPublicParameters.powers_of_g[1], randomness[i], result_h);

        result.push_back(result_g + result_h);
    }

    auto diff_msm = msm_timer.elapsed();
    cout << "Exponentiation took " << diff_msm * 1e3 << " ms" << endl;
    // optimize with MSM

    return result;
}

#endif /* MAL_POLY_COMMIT_HPP_ */