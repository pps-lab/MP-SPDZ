/*
 * DealerPrep.hpp
 *
 */

#ifndef PROTOCOLS_DEALERPREP_HPP_
#define PROTOCOLS_DEALERPREP_HPP_

#include "DealerPrep.h"
#include "GC/SemiSecret.h"

template<class T>
void DealerPrep<T>::buffer_triples()
{
    CODE_LOCATION
    assert(this->proc);
    auto& P = this->proc->P;
    vector<bool> senders(P.num_players());
    senders.back() = true;
    octetStreams os(P), to_receive(P);
    int buffer_size = BaseMachine::batch_size<T>(DATA_TRIPLE,
            this->buffer_size);
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<SemiShare<typename T::clear>> shares(P.num_players() - 1);
        for (int i = 0; i < buffer_size; i++)
        {
            T triples[3];
            for (int i = 0; i < 2; i++)
                triples[i] = G.get<T>();
            triples[2] = triples[0] * triples[1];
            for (auto& value : triples)
            {
                make_share(shares.data(), typename T::clear(value),
                        P.num_players() - 1, 0, G);
                for (int i = 1; i < P.num_players(); i++)
                    shares.at(i - 1).pack(os[i - 1]);
            }
            this->triples.push_back({});
        }
        P.send_receive_all(senders, os, to_receive);
    }
    else
    {
        P.send_receive_all(senders, os, to_receive);
        for (int i = 0; i < buffer_size; i++)
            this->triples.push_back(to_receive.back().get<FixedVec<T, 3>>().get());
    }
}

template<class T>
void DealerPrep<T>::buffer_inverses()
{
    buffer_inverses(T::invertible);
}

template<class T>
template<int>
void DealerPrep<T>::buffer_inverses(false_type)
{
    throw not_implemented();
}

template<class T>
template<int>
void DealerPrep<T>::buffer_inverses(true_type)
{
    CODE_LOCATION
    assert(this->proc);
    auto& P = this->proc->P;
    vector<bool> senders(P.num_players());
    senders.back() = true;
    octetStreams os(P), to_receive(P);
    int buffer_size = BaseMachine::batch_size<T>(DATA_INVERSE);
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<SemiShare<typename T::clear>> shares(P.num_players() - 1);
        for (int i = 0; i < buffer_size; i++)
        {
            T tuple[2];
            while (tuple[0] == 0)
                tuple[0] = G.get<T>();
            tuple[1] = tuple[0].invert();
            for (auto& value : tuple)
            {
                make_share(shares.data(), typename T::clear(value),
                        P.num_players() - 1, 0, G);
                for (int i = 1; i < P.num_players(); i++)
                    shares.at(i - 1).pack(os[i - 1]);
            }
            this->inverses.push_back({});
        }
        P.send_receive_all(senders, os, to_receive);
    }
    else
    {
        P.send_receive_all(senders, os, to_receive);
        for (int i = 0; i < buffer_size; i++)
            this->inverses.push_back(to_receive.back().get<FixedVec<T, 2>>().get());
    }
}

template<class T>
void DealerPrep<T>::buffer_bits()
{
    CODE_LOCATION
    assert(this->proc);
    auto& P = this->proc->P;
    vector<bool> senders(P.num_players());
    senders.back() = true;
    octetStreams os(P), to_receive(P);
    int buffer_size = BaseMachine::batch_size<T>(DATA_BIT);
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<SemiShare<typename T::clear>> shares(P.num_players() - 1);
        for (int i = 0; i < buffer_size; i++)
        {
            T bit = G.get_bit();
            make_share(shares.data(), typename T::clear(bit),
                    P.num_players() - 1, 0, G);
            for (int i = 1; i < P.num_players(); i++)
                shares.at(i - 1).pack(os[i - 1]);
            this->bits.push_back({});
        }
        P.send_receive_all(senders, os, to_receive);
    }
    else
    {
        P.send_receive_all(senders, os, to_receive);
        for (int i = 0; i < buffer_size; i++)
            this->bits.push_back(to_receive.back().get<T>());
    }
}

template<class T>
void DealerPrep<T>::buffer_dabits(ThreadQueues*)
{
    CODE_LOCATION
    assert(this->proc);
    auto& P = this->proc->P;
    vector<bool> senders(P.num_players());
    senders.back() = true;
    octetStreams os(P), to_receive(P);
    int buffer_size = BaseMachine::batch_size<T>(DATA_DABIT);
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<SemiShare<typename T::clear>> shares(P.num_players() - 1);
        vector<GC::SemiSecret> bit_shares(P.num_players() - 1);
        for (int i = 0; i < buffer_size; i++)
        {
            auto bit = G.get_bit();
            make_share(shares.data(), typename T::clear(bit),
                    P.num_players() - 1, 0, G);
            make_share(bit_shares.data(), typename T::bit_type::clear(bit),
                    P.num_players() - 1, 0, G);
            for (int i = 1; i < P.num_players(); i++)
            {
                shares.at(i - 1).pack(os[i - 1]);
                bit_shares.at(i - 1).pack(os[i - 1]);
            }
            this->dabits.push_back({});
        }
        P.send_receive_all(senders, os, to_receive);
    }
    else
    {
        P.send_receive_all(senders, os, to_receive);
        for (int i = 0; i < buffer_size; i++)
        {
            this->dabits.push_back({to_receive.back().get<T>(),
                to_receive.back().get<typename T::bit_type>()});
        }
    }
}

template<class T>
void DealerPrep<T>::buffer_sedabits(int length, ThreadQueues*)
{
    auto& buffer = this->edabits[{false, length}];
    if (buffer.empty())
        buffer_edabits(length, 0);
    this->edabits[{true, length}].push_back(buffer.back());
    buffer.pop_back();
}

template<class T>
void DealerPrep<T>::buffer_edabits(int length, ThreadQueues*)
{
    buffer_edabits(length, T::clear::characteristic_two);
}

template<class T>
template<int>
void DealerPrep<T>::buffer_edabits(int, true_type)
{
    throw not_implemented();
}

template<class T>
template<int>
void DealerPrep<T>::buffer_edabits(int length, false_type)
{
    CODE_LOCATION
    assert(this->proc);
    auto& P = this->proc->P;
    vector<bool> senders(P.num_players());
    senders.back() = true;
    octetStreams os(P), to_receive(P);
    int n_vecs = DIV_CEIL(BaseMachine::edabit_batch_size<T>(length),
            edabitvec<T>::MAX_SIZE);
    auto& buffer = this->edabits[{false, length}];
    if (this->proc->input.is_dealer())
    {
        SeededPRNG G;
        vector<SemiShare<typename T::clear>> shares(P.num_players() - 1);
        vector<GC::SemiSecret> bit_shares(P.num_players() - 1);
        for (int i = 0; i < n_vecs; i++)
        {
            vector<typename T::clear> as;
            vector<typename T::bit_type::part_type::clear> bs;
            plain_edabits(as, bs, length, G, edabitvec<T>::MAX_SIZE);
            for (auto& a : as)
            {
                make_share(shares.data(), a, P.num_players() - 1, 0, G);
                for (int i = 1; i < P.num_players(); i++)
                    shares.at(i - 1).pack(os[i - 1]);
            }
            for (auto& b : bs)
            {
                make_share(bit_shares.data(), b, P.num_players() - 1, 0, G);
                for (int i = 1; i < P.num_players(); i++)
                    bit_shares.at(i - 1).pack(os[i - 1]);
            }
            buffer.push_back({});
            buffer.back().a.resize(edabitvec<T>::MAX_SIZE);
            buffer.back().b.resize(length);
        }
        P.send_receive_all(senders, os, to_receive);
    }
    else
    {
        P.send_receive_all(senders, os, to_receive);
        for (int i = 0; i < n_vecs; i++)
        {
            buffer.push_back({});
            for (int j = 0; j < edabitvec<T>::MAX_SIZE; j++)
                buffer.back().a.push_back(to_receive.back().get<typename T::clear>());
            for (int j = 0; j < length; j++)
                buffer.back().b.push_back(
                        to_receive.back().get<typename T::bit_type::part_type::clear>());
        }
    }
}

#endif /* PROTOCOLS_DEALERPREP_HPP_ */
