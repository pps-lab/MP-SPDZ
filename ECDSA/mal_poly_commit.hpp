


#ifndef MAL_POLY_COMMIT_HPP_
#define MAL_POLY_COMMIT_HPP_

#include "P377Element.h"
#include "poly_commit.hpp"

// Ideally we get a better abstraction in the future

template<template<class U> class T>
void ecscalarmulshare(P377Element point, SpdzWiseShare<T<P377Element::Scalar> > multiplierShare, SpdzWiseShare<T<P377Element> >& result){

//    T<P377Element> result_share;
//    T<P377Element> result_mac;
    T<P377Element::Scalar> multiplier_share = multiplierShare.get_share();
    T<P377Element::Scalar> multiplier_mac = multiplierShare.get_mac();

    const array<P377Element::Scalar, 2>& shares = multiplier_share.get();
    array<P377Element, 2> result_shares;
    for (int i = 0; i < 2; i++) {
        P377Element::Scalar share = shares[i];
        P377Element result_share = point * share;
        result_shares[i] = result_share;
    }
    auto result_share = T<P377Element>(result_shares);

    const array<P377Element::Scalar, 2>& shares_mac = multiplier_mac.get();
    array<P377Element, 2> result_shares_mac;
    for (int i = 0; i < 2; i++) {
        P377Element::Scalar share = shares_mac[i];
        P377Element result_share = point * share;
        result_shares_mac[i] = result_share;
    }
    auto result_mac = T<P377Element>(result_shares_mac);

    result.set_share(result_share);
    result.set_mac(result_mac);
}

SpdzWiseShare<MaliciousRep3Share<P377Element>> msm(std::vector<P377Element>& bases, std::vector<SpdzWiseShare<MaliciousRep3Share<P377Element::Scalar>>> & multipliers){

    std::vector<MaliciousRep3Share<P377Element::Scalar> > multiplier_shares(multipliers.size());
    std::vector<MaliciousRep3Share<P377Element::Scalar> > multiplier_macs(multipliers.size());
    for (unsigned long i = 0; i < multipliers.size(); i++) {
        multiplier_shares[i] = multipliers[i].get_share();
        multiplier_macs[i] = multipliers[i].get_mac();
    }

    MaliciousRep3Share<P377Element> result_share = msm(bases, multiplier_shares);
    MaliciousRep3Share<P377Element> result_mac = msm(bases, multiplier_macs);

    return SpdzWiseShare(result_share, result_mac);
}

#endif /* MAL_POLY_COMMIT_HPP_ */