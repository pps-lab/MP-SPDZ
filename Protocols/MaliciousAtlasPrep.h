/*
 * AtlasPrep.h
 *
 */

#ifndef PROTOCOLS_MALICIOUSATLASPREP_H_
#define PROTOCOLS_MALICIOUSATLASPREP_H_

#include "ReplicatedPrep.h"

/**
 * ATLAS preprocessing.
 */
template<class T>
class MaliciousAtlasPrep : public MaliciousRingPrep<T>
{
public:
    MaliciousAtlasPrep(SubProcessor<T>* proc, DataPositions& usage) :
        BufferPrep<T>(usage), BitPrep<T>(proc, usage),
        RingPrep<T>(proc, usage),
        MaliciousDabitOnlyPrep<T>(proc, usage),
        MaliciousRingPrep<T>(proc, usage)
    {
    }

    /// Input tuples from random sharings
    void buffer_inputs(int player)
    {
        assert(this->protocol and this->proc);
        int batch_size = OnlineOptions::singleton.batch_size;
        typename T::MAC_Check MC;
        vector<T> shares;
        for (int i = 0; i < batch_size; i++)
            shares.push_back(this->protocol->get_random());
        vector<typename T::open_type> opened;
        this->proc->MC.POpen(opened, shares, this->proc->P);
        for (int i = 0; i < batch_size; i++)
            this->inputs.at(player).push_back({shares[i], opened[i]});
    }
};

#endif /* PROTOCOLS_MALICIOUSATLASPREP_H_ */
