/*
 * DealerMaliciousMC.h
 *
 */

#ifndef PROTOCOLS_DEALERMALICIOUSMC_H_
#define PROTOCOLS_DEALERMALICIOUSMC_H_

#include "MAC_Check_Base.h"
#include "MAC_Check.h"
#include "Networking/AllButLastPlayer.h"

template<class T>
class DealerMaliciousMC : public MAC_Check_Base<T>
{
    typedef MAC_Check_<Share<typename T::clear> > internal_type;
    internal_type& internal;
    AllButLastPlayer* sub_player;

public:
    DealerMaliciousMC(typename T::mac_key_type::Scalar &mac_key);
    DealerMaliciousMC(typename T::mac_key_type::Scalar &mac_key, int = 0, int = 0);
    DealerMaliciousMC(internal_type& internal);
    ~DealerMaliciousMC();

    void init_open(const Player& P, int n = 0);
    void prepare_open(const T& secret, int n_bits = -1);
    void exchange(const Player& P);
    typename T::open_type finalize_raw();
    array<typename T::open_type*, 2> finalize_several(int n);

    DealerMaliciousMC& get_part_MC()
    {
        return *this;
    }
};

template<class T>
class DirectDealerMaliciousMC : public DealerMaliciousMC<T>
{
public:
    DirectDealerMaliciousMC(typename T::mac_key_type::Scalar &mac_key);
};

#endif /* PROTOCOLS_DEALERMALICIOUSMC_H_ */
