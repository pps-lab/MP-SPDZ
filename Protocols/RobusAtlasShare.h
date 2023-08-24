/*
 * AtlasShare.h
 *
 */

#ifndef PROTOCOLS_ROBUSTATLASSHARE_H_
#define PROTOCOLS_ROBUSTATLASSHARE_H_

#include "AtlasShare.h"
#include "MaliciousAtlas.h"

template<class T> class Atlas;
template<class T> class AtlasPrep;

namespace GC
{
    class AtlasSecret;
}

template<class T>
class RobustAtlasShare : public AtlasShare<T>
{
    typedef RobustAtlasShare This;
    typedef AtlasShare<T> super;

public:
    typedef RobustAtlas<This> Protocol;
    typedef ::Input<This> Input;

    // something something Input

//    typedef IndirectShamirMC<This> MAC_Check;
//    typedef ShamirMC<This> Direct_MC;

    typedef MAC_Check_<This> MAC_Check;
    typedef Direct_MAC_Check<This> Direct_MC;

    typedef ::PrivateOutput<This> PrivateOutput;
    typedef RobustAtlasPrep<This> LivePrep;

    typedef GC::AtlasSecret bit_type;
    // In SPDZ, this is a share of alpha_i.
    // In our setting, it is the type of authentication tag,
    // so I think it might be a tuple of (v, sigma) \in (vec<T (q)>, T)
    typedef T mac_key_type;

    RobustAtlasShare()
    {
    }

    template<class U>
    RobustAtlasShare(const U& other) :
            super(other)
    {
    }
};

#endif /* PROTOCOLS_ROBUSTATLASSHARE_H_ */
