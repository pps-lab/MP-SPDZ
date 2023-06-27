/*
 * AtlasShare.h
 *
 */

#ifndef PROTOCOLS_MALICIOUSATLASSHARE_H_
#define PROTOCOLS_MALICIOUSATLASSHARE_H_

#include "AtlasShare.h"
#include "MaliciousAtlas.h"

template<class T> class Atlas;
template<class T> class AtlasPrep;

namespace GC
{
    class AtlasSecret;
}

template<class T>
class MaliciousAtlasShare : public AtlasShare<T>
{
    typedef MaliciousAtlasShare This;
    typedef AtlasShare<T> super;

public:
    typedef MaliciousAtlas<This> Protocol;
    typedef ::Input<This> Input;
    typedef IndirectShamirMC<This> MAC_Check;
    typedef ShamirMC<This> Direct_MC;
    typedef ::PrivateOutput<This> PrivateOutput;
    typedef MaliciousAtlasPrep<This> LivePrep;

    typedef GC::AtlasSecret bit_type;

    MaliciousAtlasShare()
    {
    }

    template<class U>
    MaliciousAtlasShare(const U& other) :
            super(other)
    {
    }
};

#endif /* PROTOCOLS_ATLASSHARE_H_ */
