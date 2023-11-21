/*
 * DealerMaliciousInput.hpp
 *
 */

#ifndef PROTOCOLS_DEALERMALICIOUSINPUT_HPP_
#define PROTOCOLS_DEALERMALICIOUSINPUT_HPP_

#include "DealerMaliciousInput.h"

template<class T>
DealerMaliciousInput<T>::DealerMaliciousInput(SubProcessor<T>& proc, typename T::MAC_Check&) :
        DealerMaliciousInput(&proc, proc.P)
{
}

template<class T>
DealerMaliciousInput<T>::DealerMaliciousInput(typename T::MAC_Check&, Preprocessing<T>&,
        Player& P) :
        DealerMaliciousInput(P)
{
}

template<class T>
DealerMaliciousInput<T>::DealerMaliciousInput(Player& P) :
        DealerMaliciousInput(0, P)
{
}

template<class T>
DealerMaliciousInput<T>::DealerMaliciousInput(SubProcessor<T>* proc, Player& P) :
        InputBase<T>(proc),
        P(P), to_send(P), shares(P.num_players()), from_dealer(false),
        sub_player(P)
{
    if (is_dealer())
        internal = 0;
    else
        internal = new Input<Share<typename T::clear> >(0, sub_player);
}

template<class T>
DealerMaliciousInput<T>::~DealerMaliciousInput()
{
    if (internal)
        delete internal;
}

template<class T>
bool DealerMaliciousInput<T>::is_dealer(int player)
{
    int dealer_player = P.num_players() - 1;
    if (player == -1)
        return P.my_num() == dealer_player;
    else
        return player == dealer_player;
}

template<class T>
void DealerMaliciousInput<T>::reset(int player)
{
    if (player == 0)
    {
        to_send.reset(P);
        from_dealer = false;
    }
    else if (not is_dealer())
        internal->reset(player - 1);
}

template<class T>
void DealerMaliciousInput<T>::add_mine(const typename T::open_type& input,
        int)
{
    if (is_dealer())
    {
        make_share(shares.data(), input, P.num_players() - 1, 0, G);
        for (int i = 0; i < P.num_players() - 1; i++)
            shares.at(i).pack(to_send[i]);
        from_dealer = true;
    }
    else
        internal->add_mine(input);
}

template<class T>
void DealerMaliciousInput<T>::add_other(int player, int)
{
    if (is_dealer(player))
        from_dealer = true;
    else if (not is_dealer())
        internal->add_other(player);
}

template<class T>
void DealerMaliciousInput<T>::exchange()
{
    if (from_dealer)
    {
        vector<bool> senders(P.num_players());
        senders.back() = true;
        P.send_receive_all(senders, to_send, to_receive);
    }
    else if (not is_dealer())
        internal->exchange();
}

template<class T>
T DealerMaliciousInput<T>::finalize(int player, int)
{
    if (is_dealer())
        return {};
    else
    {
        if (is_dealer(player))
            return to_receive.back().template get<T>();
        else
            return internal->finalize(player);
    }
}

#endif /* PROTOCOLS_DEALERMALICIOUSINPUT_HPP_ */
