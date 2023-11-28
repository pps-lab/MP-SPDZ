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

class KZGPublicParameters {
public:
    vector<P377Element> powers_of_g;
    P377Element g2;

};

template<template<class U> class T>
class Polynomial {
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
    result.set_share(pointshare.get_share() * multiplier);
    result.set_mac(pointshare.get_mac() * multiplier);
}

// Function for Scalar multiplication of a clear p256 and a shared gfp
template<template<class U> class T>
void ecscalarmulshare(P377Element point, T<P377Element::Scalar> multiplierShare, T<P377Element>& result){
    result.set_share(point * multiplierShare.get_share());
    result.set_mac(point * multiplierShare.get_mac());
}

template<template<class U> class T>
KZGCommitment commit_and_open(
        Polynomial<T> tuple,
        KZGPublicParameters kzgPublicParameters,
        typename T<P377Element>::MAC_Check& MCc,
        Player& P)
{
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    KZGCommitment signature;

    assert(tuple.coeffs.size() <= kzgPublicParameters.powers_of_g.size());

    T<P377Element> result;
    for (unsigned long i = 0; i < tuple.coeffs.size(); ++i) {
        // This is technically a share!!
        ecscalarmulshare(kzgPublicParameters.powers_of_g[i], tuple.coeffs[i], result);
    }
    vector<T<P377Element> > commitment_share = { result };

    vector<P377Element> commitment_element;
    MCc.POpen_Begin(commitment_element, commitment_share, P);
    MCc.POpen_End(commitment_element, commitment_share, P);

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
