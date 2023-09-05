/*
 * SpdzWiseInput.cpp
 *
 */

#include "AuthenticationTagInput.h"

template<class T>
AuthenticationTagInput<T>::AuthenticationTagInput(SubProcessor<T>* proc, Player& P) :
        InputBase<T>(proc), P(P), part_input(0, P), honest_mult(P), checker(P), proc(
                proc), counters(P.num_players()), shares(P.num_players())
{
    assert(proc != 0);
    mac_key = proc->MC.get_alphai();
    checker.init(proc->DataF, proc->MC);
}

template<class T>
AuthenticationTagInput<T>::AuthenticationTagInput(SubProcessor<T>& proc, Player& P) :
        AuthenticationTagInput<T>(&proc, P)
{
}

template<class T>
AuthenticationTagInput<T>::AuthenticationTagInput(SubProcessor<T>& proc, typename T::MAC_Check&) :
        AuthenticationTagInput<T>(&proc, proc.P)
{
}

template<class T>
AuthenticationTagInput<T>::~AuthenticationTagInput()
{
    checker.check();
}

template<class T>
void AuthenticationTagInput<T>::reset(int player)
{
    part_input.reset(player);
    counters[player] = 0;
}

template<class T>
void AuthenticationTagInput<T>::add_mine(const typename T::open_type& input, int n_bits)
{
    // TODO: This is something like input called on the type, gf2n Input type ??
    part_input.add_mine(input, n_bits);
    counters[P.my_num()]++;
}

template<class T>
void AuthenticationTagInput<T>::add_other(int player, int n_bits)
{
    part_input.add_other(player, n_bits);
    counters[player]++;
}

template<class T>
void AuthenticationTagInput<T>::exchange()
{
    part_input.exchange();
    honest_mult.init_mul();
    for (int i = 0; i < P.num_players(); i++)
    {
        shares[i].clear();
        for (int j = 0; j < counters[i]; j++)
        {
            auto s = part_input.finalize(i);
            shares[i].push_back({});
            shares[i].back().set_share(s);
            honest_mult.prepare_mul(s, mac_key);
        }
    }
    honest_mult.exchange();
    for (int i = 0; i < P.num_players(); i++)
        for (int j = 0; j < counters[i]; j++)
        {
            shares[i][j].set_mac(honest_mult.finalize_mul());
            checker.results.push_back(shares[i][j]);
        }
    checker.maybe_check();
}

template<class T>
T AuthenticationTagInput<T>::finalize(int player, int)
{
    return shares[player].next();
}
