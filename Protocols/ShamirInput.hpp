/*
 * ShamirInput.cpp
 *
 */

#ifndef PROTOCOLS_SHAMIRINPUT_HPP_
#define PROTOCOLS_SHAMIRINPUT_HPP_

#include "ShamirInput.h"
#include "ShamirOptions.h"
#include "Protocols/ReplicatedInput.hpp"
#include "Protocols/SemiInput.hpp"

template<class U>
void IndividualInput<U>::reset(int player)
{
    if (player == P.my_num())
    {
        this->shares.clear();
        os.reset(P);
    }

    senders[player] = false;
}

template<class T>
vector<vector<typename T::open_type>> ShamirInput<T>::get_vandermonde(
        size_t t, size_t n)
{
    vector<vector<typename T::open_type>> vandermonde(n);

    for (int i = 0; i < int(n); i++)
        if (vandermonde[i].size() < t)
        {
            vandermonde[i].resize(t);
            typename T::open_type x = 1;
            for (size_t j = 0; j < t; j++)
            {
                x *= (i + 1);
                vandermonde[i][j] = x;
            }
        }

    return vandermonde;
}

template<class T>
void ShamirInput<T>::init()
{
    reconstruction.resize(this->P.num_players() - threshold);
    for (size_t i = 0; i < reconstruction.size(); i++)
    {
        auto& x = reconstruction[i];
        vector<int> points(threshold + 1);
        points[0] = -1;
        for (int i = 0; i < threshold; i++)
            points[1 + i] = this->P.get_player(1 + i);
        x = Shamir<T>::get_rec_factors(points,
                this->P.get_player(1 + i + threshold));
    }
}

template<class T>
void ShamirInput<T>::add_mine(const typename T::open_type& input, int n_bits)
{
    this->maybe_init(this->P);

    (void) n_bits;
    auto& P = this->P;
    int n = P.num_players();
    int t = threshold;

    randomness.resize(t);
    for (int offset = 0; offset < t; offset++)
    {
        int i = P.get_player(1 + offset);
        assert(i != P.my_num());
        randomness[offset].randomize(this->send_prngs[i]);
    }

    for (int i = threshold; i < n; i++)
    {
        int player = P.get_player(1 + i);
        typename T::open_type x = input
                * reconstruction.at(i - threshold).at(0);
        for (int j = 0; j < t; j++)
            x += randomness[j] * reconstruction.at(i - threshold).at(j + 1);
        if (player == P.my_num())
            this->shares.push_back(x);
        else
            x.pack(this->os[player]);
    }

    this->senders[P.my_num()] = true;
}

template<class T>
void ShamirInput<T>::finalize_other(int player, T& target,
        octetStream& o, int n_bits)
{
    if (this->P.get_offset(player) >= this->P.num_players() - threshold)
        target.randomize(this->recv_prngs.at(player));
    else
        IndividualInput<T>::finalize_other(player, target, o, n_bits);
}

template<class U>
void IndividualInput<U>::add_sender(int player)
{
    this->maybe_init(this->P);
    senders[player] = true;
}

template<class U>
void IndividualInput<U>::add_other(int player, int)
{
    add_sender(player);
}

template<class U>
void IndividualInput<U>::send_mine()
{
    for (int i = 0; i < P.num_players(); i++)
        if (i != P.my_num())
            P.send_to(i, os[i]);
}

template<class T>
void IndividualInput<T>::exchange()
{
    CODE_LOCATION
    P.send_receive_all(senders, os, InputBase<T>::os);
    this->shares.reset();
}

template<class T>
void IndividualInput<T>::start_exchange()
{
    if (senders[P.my_num()])
        for (int offset = 1; offset < P.num_players(); offset++)
            P.send_relative(offset, os[P.get_player(offset)]);
}

template<class T>
void IndividualInput<T>::stop_exchange()
{
    for (int offset = 1; offset < P.num_players(); offset++)
    {
        int receive_from = P.get_player(-offset);
        if (senders[receive_from])
            P.receive_player(receive_from, InputBase<T>::os[receive_from]);
    }
    this->shares.reset();
}

template<class T>
void IndividualInput<T>::finalize_other(int player, T& target, octetStream& o,
        int n_bits)
{
    (void) player;
    target.unpack(o, n_bits);
}

#endif
