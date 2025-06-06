/*
 * ThreadQueues.cpp
 *
 */

#include "ThreadQueues.h"

#include <assert.h>
#include <math.h>

int ThreadQueues::distribute(ThreadJob job, int n_items, int base,
        int granularity)
{
    if (find_available() > 0)
        return distribute_no_setup(job, n_items, base, granularity);
    else
        return base;
}

int ThreadQueues::find_available()
{
#ifdef VERBOSE_QUEUES
    cerr << available.size() << " threads in use" << endl;
#endif
    if (not available.empty())
        return 0;
    for (size_t i = 1; i < size(); i++)
        if (at(i)->available())
            available.push_back(i);
#ifdef VERBOSE_QUEUES
    cerr << "Using " << available.size() << " threads" << endl;
#endif
    return available.size();
}

int ThreadQueues::get_n_per_thread(int n_items, int granularity)
{
    int n_per_thread = int(ceil(n_items / (available.size() + 1.0)) / granularity)
            * granularity;
    return n_per_thread;
}

int ThreadQueues::distribute_no_setup(ThreadJob job, int n_items, int base,
        int granularity, const vector<void*>* supplies)
{
#ifdef VERBOSE_QUEUES
    cerr << "Distribute " << job.type << " among " << available.size() << endl;
#endif

    int n_per_thread = get_n_per_thread(n_items, granularity);

    if (n_items and (n_per_thread == 0 or base + n_per_thread > n_items))
    {
        available.clear();
        return base;
    }

    for (size_t i = 0; i < available.size(); i++)
    {
        if (base + (i + 1) * n_per_thread > size_t(n_items))
        {
            assert(i);
            available.resize(i);
            return base + i * n_per_thread;
        }
        if (supplies)
            job.supply = supplies->at(i);
        job.begin = base + i * n_per_thread;
        job.end = base + (i + 1) * n_per_thread;
        at(available[i])->schedule(job);
    }
    return base + available.size() * n_per_thread;
}

void ThreadQueues::wrap_up(ThreadJob job)
{
#ifdef VERBOSE_QUEUES
    cerr << "Wrap up " << available.size() << " threads" << endl;
#endif
    for (int i : available)
    {
        auto result = at(i)->result();
        assert(result.output == job.output);
        assert(result.type == job.type);
    }
    available.clear();
}

TimerWithComm ThreadQueues::sum(const string& phase)
{
    TimerWithComm res;
    for (auto& x : *this)
        res += x->timers[phase];
    return res;
}

void ThreadQueues::print_breakdown()
{
    if (size() > 0)
    {
        if (size() == 1)
        {
            cerr << "Spent " << (*this)[0]->timers["online"].full()
                    << " on the online phase and "
                    << (*this)[0]->timers["prep"].full()
                    << " on the preprocessing/offline phase." << endl;
        }
        else
        {
            cerr << size() << " threads spent a total of " << sum("online").full()
                    << " on the online phase, " << sum("prep").full()
                    << " on the preprocessing/offline phase, and "
                    << sum("wait").full() << " idling." << endl;
        }

        if (sum("random").elapsed())
            cerr << "Spent " << sum("random").full()
                    << " on correlated randomness generation." << endl;
    }
}

NamedCommStats ThreadQueues::total_comm()
{
    NamedCommStats res;
    for (auto& queue : *this)
      res += queue->get_comm_stats();
    return res;
}

NamedCommStats ThreadQueues::max_comm()
{
    NamedCommStats max;
    if (size() > 2)
        for (auto& queue : *this)
            max.imax(queue->get_comm_stats());
    return max;
}
