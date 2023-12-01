/*
 * sign.hpp
 *
 */

#ifndef ECDSA_SIGN_PC_HPP_
#define ECDSA_SIGN_PC_HPP_

//#include "CurveElement.h"
#include "P256Element.h"
#include "Tools/Bundle.h"

#include "preprocessing.hpp"
#include "Math/gfp.hpp"



EcSignature sign(const unsigned char* message, size_t length,
                                        EcTuple<SpdzWiseRepFieldShare> tuple,
                                        typename SpdzWiseRepFieldShare<P256Element::Scalar>::MAC_Check& MC,
                                        typename SpdzWiseRepFieldShare<P256Element>::MAC_Check& MCc,
                                        Player& P,
                                        EcdsaOptions opts,
                                        P256Element pk,
                                        SpdzWiseRepFieldShare<P256Element::Scalar> sk,
                                        SubProcessor<SpdzWiseRepFieldShare<P256Element::Scalar>>* proc)
{
    (void) pk;
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    EcSignature signature;
    vector<P256Element> opened_R;
    if (opts.R_after_msg)
        MCc.POpen_Begin(opened_R, {tuple.secret_R}, P);
    SpdzWiseRepFieldShare<P256Element::Scalar> prod = tuple.b;
    auto& protocol = proc->protocol;
    if (proc)
    {
        protocol.init_mul();
        protocol.prepare_mul(sk, tuple.a);
        protocol.start_exchange();
    }
    if (opts.R_after_msg)
    {
        MCc.POpen_End(opened_R, {tuple.secret_R}, P);
        tuple.R = opened_R[0];
        if (opts.fewer_rounds)
            tuple.R /= tuple.c;
    }
    if (proc)
    {
        protocol.stop_exchange();
        prod = protocol.finalize_mul();
    }
    signature.R = tuple.R;
    auto rx = tuple.R.x();
    signature.s = MC.open(
            tuple.a * hash_to_scalar(message, length) + prod * rx, P);
    auto diff = (P.total_comm() - stats);
    cout << "Minimal signing took " << timer.elapsed() * 1e3 << " ms and sending "
            << diff.sent << " bytes" << endl;
    diff.print(true);
    return signature;
}

#endif /* ECDSA_SIGN_PC_HPP_ */
