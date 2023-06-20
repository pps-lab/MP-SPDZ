/*
 * Atlas.h
 *
 */

#ifndef PROTOCOLS_MALICIOUSATLAS_H_
#define PROTOCOLS_MALICIOUSATLAS_H_

#define VERBOSE_COMM 1

#include "Replicated.h"
#include "Atlas.h"
#include <tuple>


/**
 * ATLAS protocol (simple version).
 * Uses double sharings to reduce degree of Shamir secret sharing.
 */

// TODO: Dot product verification as well, but with/without the verification
template<class T>
class MaliciousAtlas : public Atlas<T>
{
    PointerVector<T> check_x, check_y, check_z;

public:
    MaliciousAtlas(Player& P) : Atlas<T>(P)
    {
    }

    ~MaliciousAtlas();

    void check();
    void exchange();

    void prepare_mul(const T& x, const T& y, int n = -1);
    T finalize_mul(int n = -1);

    void prepare_dotprod(const T& x, const T& y);
    T finalize_dotprod(int n = -1);
    T finalize_dotprod_q(bool queue_check);

    void prepare_mul(const T& x, const T& y, bool queue_check);
    T finalize_mul(bool queue_check);

    T mul_helper(const T& x, const T& y, int n = -1);

    T open(const T& val);
    typename T::open_type coin();


    void check_products();

    // Protocol 12
    tuple<std::vector<T>, std::vector<T>, T> ip_compress(std::vector<T> xs_l, std::vector<T> ys_l, T ip_l, std::vector<T> xs_r, std::vector<T> ys_r, T ip_r);

    // Protocol 13
    void hadamard_check();

    // Protocol 14, 15
    void ip_check(T rzs_sum);

    T ip_compute(std::vector<T> xs, std::vector<T> ys);
    void king_compute();

    MaliciousAtlas branch()
    {
        return this->P;
    }
};

#endif /* PROTOCOLS_ATLAS_H_ */
