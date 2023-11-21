/*
 * DealerMaliciousMC.hpp
 *
 */

#ifndef PROTOCOLS_DEALERMALICIOUSMC_HPP_
#define PROTOCOLS_DEALERMALICIOUSMC_HPP_

#include "DealerMaliciousMC.h"

template<class T>
DealerMaliciousMC<T>::DealerMaliciousMC(typename T::mac_key_type::Scalar &mac_key, int, int) :
        DealerMaliciousMC(*(new internal_type(mac_key)))
{
}

template<class T>
DealerMaliciousMC<T>::DealerMaliciousMC(typename T::mac_key_type::Scalar &mac_key) :
        DealerMaliciousMC(*(new internal_type(mac_key)))
{
}

template<class T>
DirectDealerMaliciousMC<T>::DirectDealerMaliciousMC(typename T::mac_key_type::Scalar &mac_key) :
        DealerMaliciousMC<T>(*(new Direct_MAC_Check<Share<typename T::clear> >(mac_key)))
{
}

template<class T>
DealerMaliciousMC<T>::DealerMaliciousMC(internal_type& internal) :
        internal(internal), sub_player(0)
{
}

template<class T>
DealerMaliciousMC<T>::~DealerMaliciousMC()
{
    delete &internal;
    if (sub_player)
        delete sub_player;
}

template<class T>
void DealerMaliciousMC<T>::init_open(const Player& P, int n)
{
    if (P.my_num() != P.num_players() - 1)
    {
        if (not sub_player)
            sub_player = new AllButLastPlayer(P);
        internal.init_open(P, n);
    }
}

template<class T>
void DealerMaliciousMC<T>::prepare_open(const T& secret, int n_bits)
{
    if (sub_player)
        internal.prepare_open(secret, n_bits);
    else
    {
//        if (secret != T())
//            throw runtime_error("share for dealer should be 0");
//
        std::cout << "No check if secret empty!" << std::endl;
    }
}

template<class T>
void DealerMaliciousMC<T>::exchange(const Player&)
{
    if (sub_player)
        internal.exchange(*sub_player);
}

template<class T>
typename T::open_type DealerMaliciousMC<T>::finalize_raw()
{
    if (sub_player)
        return internal.finalize_raw();
    else
        return {};
}

template<class T>
array<typename T::open_type*, 2> DealerMaliciousMC<T>::finalize_several(int n)
{
    assert(sub_player);
    return internal.finalize_several(n);
}

#endif /* PROTOCOLS_DEALERMALICIOUSMC_HPP_ */
