/*
 * DealerMaliciousInput.h
 *
 */

#ifndef PROTOCOLS_DEALERMALICIOUSINPUT_H_
#define PROTOCOLS_DEALERMALICIOUSINPUT_H_

#include "../Networking/AllButLastPlayer.h"
#include "Processor/Input.h"

template<class T>
class DealerMaliciousInput : public InputBase<T>
{
    Player& P;
    octetStreams to_send, to_receive;
    SeededPRNG G;
    vector<Share<typename T::clear>> shares;
    bool from_dealer;
    AllButLastPlayer sub_player;
    Input<Share<typename T::clear>>* internal;

public:
    DealerMaliciousInput(SubProcessor<T>& proc, typename T::MAC_Check&);
    DealerMaliciousInput(typename T::MAC_Check&, Preprocessing<T>&, Player& P);
    DealerMaliciousInput(Player& P);
    DealerMaliciousInput(SubProcessor<T>*, Player& P);
    ~DealerMaliciousInput();

    bool is_dealer(int player = -1);

    void reset(int player);
    void add_mine(const typename T::open_type& input, int n_bits = -1);
    void add_other(int player, int n_bits = -1);
    void exchange();
    T finalize(int player, int n_bits = -1);
};

#endif /* PROTOCOLS_DEALERMALICIOUSINPUT_H_ */
