/*
 * DealerShare.h
 *
 */

#ifndef PROTOCOLS_DEALERMALICIOUSSHARE_H_
#define PROTOCOLS_DEALERMALICIOUSSHARE_H_

#include "Math/Z2k.h"
#include "SemiShare.h"
#include "Share.h"

template<class T, class ShareType, class BitShareType> class DealerPrep; // Made compatible
template<class T> class DealerMaliciousInput;
template<class T> class DealerMaliciousMC;
template<class T> class DirectDealerMaliciousMC;
template<class T> class DealerMatrixPrep; // Should be directly compatible
template<class T> class SPDZ;

template<class T> class Share;

template<class T> class Dealer; // Should be compat

//class gf2n_mac_key;

namespace GC
{
//    template<class T> class TinierSecret;
    class DealerSecret;
}

template<class T>
class DealerMaliciousShare : public Share<T>
{
    typedef DealerMaliciousShare This;
    typedef Share<T> super;

public:
    typedef GC::DealerSecret bit_type;

    typedef DealerMaliciousMC<This> MAC_Check;
    typedef DirectDealerMaliciousMC<This> Direct_MC;
    typedef SPDZ<This> Protocol;
    typedef DealerMaliciousInput<This> Input;
    typedef DealerPrep<This, Share<typename This::clear>, GC::SemiSecret > LivePrep;
    typedef ::PrivateOutput<This> PrivateOutput;

    typedef DealerMatrixPrep<This> MatrixPrep; // directly compatible
    typedef Dealer<This> BasicProtocol;

    static true_type dishonest_majority; // NOT SURE?
    const static bool needs_ot = false;
    const static bool symmetric = false;

    static string type_short()
    {
        return "DDM" + string(1, T::type_char());
    }

    static bool real_shares(const Player& P)
    {
        return P.my_num() != P.num_players() - 1;
    }

    static This constant(const T& other, int my_num,
            const typename super::mac_key_type& mac_key, int = -1)
    {
        // TODO: Not sure whats going on here
        if (my_num == 1)
            return super::constant(other, my_num, mac_key);
//            return DealerMaliciousShare(other, my_num);
        else
            return {};
    }

    DealerMaliciousShare()
    {
    }

    template<class U>
    DealerMaliciousShare(const U& other) : super(other)
    {
    }
};

//template<int K>
//using DealerMaliciousRingShare = DealerMaliciousShare<SignedZ2<K>>;

template<class T>
true_type DealerMaliciousShare<T>::dishonest_majority;

#endif /* PROTOCOLS_DEALERMALICIOUSSHARE_H_ */
