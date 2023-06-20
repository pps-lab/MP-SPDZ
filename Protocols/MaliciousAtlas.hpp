/*
 * Atlas.hpp
 *
 */

#ifndef PROTOCOLS_MALICIOUSATLAS_HPP_
#define PROTOCOLS_MALICIOUSATLAS_HPP_

//#define ATLAS_DEBUG 0

#include "MaliciousAtlas.h"

template<class T>
MaliciousAtlas<T>::~MaliciousAtlas()
{
#ifdef VERBOSE
    if (not double_sharings.empty())
        cerr << double_sharings.size() << " double sharings left" << endl;
#endif
}


template<class T>
void MaliciousAtlas<T>::check()
{
    // We need to check the products, if any
    this->check_products();
}

template<class T>
void MaliciousAtlas<T>::check_products()
{
    if (!check_x.empty()) {
#ifdef ATLAS_DEBUG
        std::cout << "Checking " << check_x.size() << " multiplication triples!" << std::endl;
        std::cout << "check_z size: " << check_z.size() << std::endl;
#endif
        assert(check_x.size() == check_y.size());
        assert(check_y.size() == check_z.size());

        hadamard_check();
    }
}

template<class T>
void MaliciousAtlas<T>::hadamard_check()
{
#ifdef ATLAS_DEBUG
    std::cout << "Hadamard " << check_x.size() << std::endl;
#endif

    typename T::open_type r = coin();
//    std::cout << "Hadamard Random" << element << std::endl;

    // Iterate over check_z and sum its elements
    T z_sum = T(); // zero

    T r_i = T() + 1; // one
    // Combine the two above loops into one loop that iterates over both at the same time using i
    for (size_t i = 0; i < check_z.size(); i++) {
        check_x[i] = check_x[i] * r_i;
        check_z[i] = check_z[i] * r_i;
        z_sum += check_z[i];
        r_i = r_i * r;
    }

#ifdef ATLAS_DEBUG
    std::cout << "Finish " << z_sum << ", r " << r << ", x*r " << check_x[0] << " " << std::endl;
#endif
    ip_check(z_sum);

}

template<class T>
void print_list(std::vector<T> path) {
    for (T i: path)
        std::cout << i << ' ';
    std::cout << std::endl;
}

// Check an IP, recursively shrinking it
template<class T>
void MaliciousAtlas<T>::ip_check(T rzs_sum)
{
    (void)rzs_sum;
#ifdef ATLAS_DEBUG
    std::cout << "ip_check for size " << check_x.size() << std::endl;
#endif

    assert(check_x.size() == check_y.size());

    std::vector<T> xs(check_x);
    std::vector<T> ys(check_y);

#ifdef ATLAS_DEBUG
    print_list(xs);
    print_list(ys);
#endif

    while (xs.size() > 1) {
        if (xs.size() % 2 == 1) {
            xs.push_back(T());
            ys.push_back(T());
        }
        size_t n = xs.size() / 2;
        // split check_x into first n elements and the rest
        auto xs_split = slice(xs, n);
        auto xs_l = xs_split[0];
        auto xs_r = xs_split[1];
        auto ys_split = slice(ys, n);
        auto ys_l = ys_split[0];
        auto ys_r = ys_split[1];
        T ip_l = ip_compute(xs_l, ys_l);
#ifdef ATLAS_DEBUG
        std::cout << "xs_l " << xs_l[0] << ", ys_l " << ys_l[0] << ", ip_l " << ip_l << std::endl;

        typename T::open_type resipl = open(ip_l);
        std::cout << "open ip_l " << resipl << std::endl;
#endif
        T ip_r = rzs_sum - ip_l;

        // Compress
        auto res = ip_compress(xs_l, ys_l, ip_l, xs_r, ys_r, ip_r);
        tie(xs, ys, rzs_sum) = res;
    }

    // some post-processing
    T xr = this->get_random();
    T yr = this->get_random();

    T x = xs[0];
    T y = ys[0];

#ifdef ATLAS_DEBUG
    std::cout << "x " << x << ", y " << y << ", rzs_sum " << rzs_sum << std::endl;
#endif

#ifdef ATLAS_DEBUG
    T x_out_unblind = open(x);
    T y_out_unblind = open(y);
    T ip_out_unblind = open(rzs_sum);

    std::cout << "x_out (not blind) " << x_out_unblind << std::endl;
    std::cout << "y_out (not blind) " << y_out_unblind << std::endl;
    std::cout << "ip_out (not blind) " << ip_out_unblind << std::endl;

    assert(x_out_unblind * y_out_unblind == ip_out_unblind);
#endif

    // Now multiply but without the check ??
    // 15.4
    T ip_rand = mul_helper(xr, yr);
    T x_blind = mul_helper(x, xr);
    T y_blind = mul_helper(y, yr);
    T ip_blind = mul_helper(rzs_sum, ip_rand);

//#ifdef ATLAS_DEBUG
//    std::cout << "xr " << xr << ", yr " << yr << ", ip_rand " << ip_rand << std::endl;
//    std::cout << "x " << x << ", xr " << xr << ", x_blind " << x_blind << std::endl;
//    std::cout << "y " << y << ", yr " << yr << ", y_blind " << y_blind << std::endl;
//    std::cout << "rzs_sum " << rzs_sum << ", ip_rand " << ip_rand << ", ip_blind " << ip_blind << std::endl;
//#endif

    // Now we need to open blinded values, ie everyone shares with each other
    T x_out = open(x_blind);
    T y_out = open(y_blind);
    T ip_out = open(ip_blind);

#ifdef ATLAS_DEBUG
    std::cout << "x_out " << x_out << std::endl;
    std::cout << "y_out " << y_out << std::endl;
    std::cout << "ip_out " << ip_out << std::endl;
#endif

    assert(x_out * y_out == ip_out);
}

//template <class T>
//void try_print(T x) {
//    bigint result = x;
//    std::cout << "print " << x << " " << result << std::endl;
//}

// Does a full multiplication (todo: turn off checks ?)
template <class T>
T MaliciousAtlas<T>::mul_helper(const T& x, const T& y, int) {
    this->init_mul();
    this->prepare_mul(x, y, false);
    this->exchange();
    return this->finalize_mul(false);
}

// Protocol 6
template<class T>
typename T::open_type MaliciousAtlas<T>::coin() {
    T r = this->shamir.get_random();
    return open(r);
}

// Open values
template<class T>
T MaliciousAtlas<T>::open(const T& val) {
    // Everyone sends its share of val to everyone else, everyone reconstructs the result.
    int t = ShamirMachine::s().threshold;
    typename T::Direct_MC mc = typename T::Direct_MC(t);
//    mc.init_open(this->P);
//    mc.prepare_open(val);
//    mc.exchange(this->P);
//
//    const vector<T> shares;
//    mc.finalize(&shares);
//    T reconstruction = mc.reconstruct(shares);

    std::vector<typename T::open_type> reconstruction(1);
    const std::vector<T> shares = {val};

    mc.POpen(reconstruction, shares, this->P);

    return reconstruction[0];

//    Bundle<octetStream> oss = Bundle(this->P);
//
//    oss.reset();
//    oss.mine = val;
//
//    this->P.unchecked_broadcast(oss);
//
//    // should we use some subprotocol for this? PrivateOutput ??
//
//    int t = ShamirMachine::s().threshold;
//    typename T::open_type e;
//    for (int i = 0; i < 2 * t + 1; i++)
//    {
//        auto tmp = oss[i].template get<T>();
//        e += tmp * reconstruction.at(i);
//    }
//    resharing.add_mine(e);
}

template<class T>
array<std::vector<T>, 2> slice(std::vector<T> vec, size_t n) {
    assert(n < vec.size());
    std::vector<T> lhs = std::vector<T>(vec.begin(), vec.begin() + n);
    std::vector<T> rhs = std::vector<T>(vec.begin() + n, vec.end());

    return {lhs, rhs};
}

// Roughly Extend-Mult (Protocol 10)
template<class T>
T MaliciousAtlas<T>::ip_compute(std::vector<T> xs, std::vector<T> ys) {
    assert(xs.size() == ys.size());
    size_t n = xs.size();

    this->init_dotprod();
    for (size_t i = 0; i < n; i++)
        this->prepare_dotprod(xs[i], ys[i]);
    this->next_dotprod();
    this->exchange();
    return this->finalize_dotprod_q(false);
//
//    T acc = T();
//    size_t n = xs.size();
////    size_t degree = 0;
//    for (size_t i = 0; i < n; i++) {
//        acc += xs[i] * ys[i];
////        degree = max(degree, xs[i].degree() + ys[i].degree());
//    }
//    // r[0] is degree 2t, r[1] is degree t
//    auto r = this->get_double_sharing();
//    // Protocol 10.3
//    acc += r[0];
//
//    // Protocol 10.4, reshare
//    this->init_dotprod();
//    for (size_t i = 0; i < n; i++)
//        this->prepare_dotprod(xs[i], ys[i]);
//    this->next_dotprod();
//    this->exchange();
//    T shifted_result = this->finalize_dotprod(n);
//
////    shifted_result = king_compute ...
//    return shifted_result - r[1];
}

// Compress two inner product checks into one, Extend-Compress
// Protocol 12
template<class T>
tuple<std::vector<T>, std::vector<T>, T> MaliciousAtlas<T>::ip_compress(std::vector<T> xs_l, std::vector<T> ys_l, T ip_l, std::vector<T> xs_r, std::vector<T> ys_r, T ip_r)
{
#ifdef ATLAS_DEBUG
    std::cout << "ip_compress" << std::endl;
#endif

    size_t n = xs_l.size();

    std::vector<T> xs_m = std::vector<T>(n);
    std::vector<T> xs_b = std::vector<T>(n);
    std::vector<T> xs_3 = std::vector<T>(n);
    for (size_t i = 0; i < n; i++) {
        xs_m[i] = xs_r[i] - xs_l[i];
        xs_b[i] = xs_l[i] - xs_m[i];
        xs_3[i] = xs_r[i] + xs_m[i];
    }

    std::vector<T> ys_m = std::vector<T>(n);
    std::vector<T> ys_b = std::vector<T>(n);
    std::vector<T> ys_3 = std::vector<T>(n);
    for (size_t i = 0; i < n; i++) {
        ys_m[i] = ys_r[i] - ys_l[i];
        ys_b[i] = ys_l[i] - ys_m[i];
        ys_3[i] = ys_r[i] + ys_m[i];
    }

    T ip_3 = ip_compute(xs_3, ys_3);

    typename T::open_type r = coin();

    std::vector<T> xs_rand = std::vector<T>(n);
    std::vector<T> ys_rand = std::vector<T>(n);
    for (size_t i = 0; i < n; i++) {
        xs_rand[i] = xs_m[i] * r + xs_b[i];
        ys_rand[i] = ys_m[i] * r + ys_b[i];
    }

    // Evaluate basis polynomials at 1, 2, 3
    // The ip-function is a parabola
    // We need the lagrange basis on 1, 2, 3. It is:
    // f_1(X) = (X-2)(X-3)/2
    // f_2(X) = (X-1)(X-3)/-1
    // f_3(X) = (X-1)(X-2)/2
    T t_one = T(1);
    T t_two = T(2);
    T t_three = T(3);

    T f_1 = ((r - t_two) * (r - t_three)) / t_two;
    T f_2 = ((r - t_one) * (r - t_three)) / -t_one;
    T f_3 = ((r - t_one) * (r - t_two)) / t_two;

    T ip_result = f_1 * ip_l + f_2 * ip_r + f_3 * ip_3;
    return make_tuple(xs_rand, ys_rand, ip_result);
}

template<class T>
void king_compute()
{
//    octetStreams to_send(this->P);
//    for (int i = 1; i < 4; i++)
//        for (int j = 0; j < 4; j++)
//            to_send[P.get_player(i)].concat(send_hashes[j][P.get_player(i)].final());
//
//    octetStreams to_receive;

    // Collect shares
    vector<typename T::open_type> reconstruction;

    // Generate degree sharing
    //


    // Redistribute shares
}

template<class T>
void MaliciousAtlas<T>::prepare_mul(const T &x, const T &y, bool queue_check) {
    Atlas<T>::prepare_mul(x, y, queue_check);

    if (queue_check) {
        check_x.push_back(x);
        check_y.push_back(y);
    }
}

template<class T>
void MaliciousAtlas<T>::prepare_mul(const T& x, const T& y, int)
{
    MaliciousAtlas<T>::prepare_mul(x, y, true);
}

template<class T>
void MaliciousAtlas<T>::exchange()
{
    // TODO: I think this is  the same as in the parent
    this->P.send_receive_all(this->oss2, this->oss);
    this->oss.mine = this->oss2.mine;

    // Create shares
    int t = ShamirMachine::s().threshold;
    if (this->reconstruction.empty())
        for (int i = 0; i < 2 * t + 1; i++)
            this->reconstruction.push_back(Shamir<T>::get_rec_factor(i, 2 * t + 1));
    this->resharing.reset_all(this->P);

#ifdef ATLAS_DEBUG
//    std::cout << "reconstructing as king ? " << this->P.get_player(-this->base_king) << std::endl;
#endif

    // King reconstructs value ?? and then adds to reshare
    for (size_t j = this->P.get_player(-this->base_king); j < this->masks.size();
         j += this->P.num_players())
    {
        typename T::open_type e;
        for (int i = 0; i < 2 * t + 1; i++)
        {
            auto tmp = this->oss[i].template get<T>();
            e += tmp * this->reconstruction.at(i);
        }
#ifdef ATLAS_DEBUG
//        std::cout << "e " << e << std::endl;
#endif
        this->resharing.add_mine(e);
    }

    // Share with other players
    for (size_t i = 0; i < min(this->masks.size(), size_t(this->P.num_players())); i++)
    {
        int j = (this->base_king + i) % this->P.num_players();
        this->resharing.add_sender(j);
    }

    // What do we need to add, a triple of x, y, z
    this->resharing.exchange();
}

template<class T>
void MaliciousAtlas<T>::prepare_dotprod(const T& x, const T& y)
{
    Atlas<T>::prepare_dotprod(x, y);

    // Add this in some smart way
    std::cout << "prepare_dotprod" << std::endl;
}

template<class T>
T MaliciousAtlas<T>::finalize_dotprod(int)
{
    return finalize_dotprod_q(true);
}

template<class T>
T MaliciousAtlas<T>::finalize_dotprod_q(bool queue_check)
{
    return finalize_mul(queue_check);
}


template<class T>
T MaliciousAtlas<T>::finalize_mul(int)
{
    return MaliciousAtlas<T>::finalize_mul(true);
}

template<class T>
T MaliciousAtlas<T>::finalize_mul(bool queue_check)
{
    // Maybe check later: Can we call superclass as standalone?
    // Subtract degree t r (Protocol 7.4), z
    T res = this->resharing.finalize(this->base_king) - this->masks.next();

    // Assuming it stays in order ?
    if (queue_check) {
        check_z.push_back(res);
    }

    this->base_king = (this->base_king + 1) % this->P.num_players();
    return res;
}

#endif /* PROTOCOLS_ATLAS_HPP_ */
