/*
 * Element.h
 *
 */

#ifndef ECDSA_P377ELEMENT_H_
#define ECDSA_P377ELEMENT_H_

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/curve_serialization.hpp>

#include "Math/gfp.h"

class P377Element : public ValueInterface
{
public:
    typedef gfp_<4, 4> Scalar;
    typedef libff::bls12_377_G1 G1;
    typedef libff::bls12_377_Fr Fr;

private:

    libff::bls12_377_G1 point;

public:
    typedef P377Element next;
    typedef void Square;

    static const true_type invertible;

    static int size() { return 0; }
    static int length() { return 256; }
    static string type_string() { return "P377"; }

    static void init();
    static void finish();

    P377Element();
    P377Element(const P377Element& other);
    P377Element(const Scalar& other);
    P377Element(word other);
    P377Element(G1 p);
    ~P377Element();

    P377Element& operator=(const P377Element& other);

    void check();

    Scalar x() const;
    void randomize(PRNG& G, int n = -1);
    void input(istream& s, bool human);
    static string type_short() { return "ec"; }
    static DataFieldType field_type() { return DATA_INT; }

    P377Element operator+(const P377Element& other) const;
    P377Element operator-(const P377Element& other) const;
    P377Element operator*(const Scalar& other) const;

    P377Element& operator+=(const P377Element& other);
    P377Element& operator/=(const Scalar& other);

    bool operator==(const P377Element& other) const;
    bool operator!=(const P377Element& other) const;

    void assign_zero() { *this = {}; }
    bool is_zero() { return *this == P377Element(); }
    void add(octetStream& os, int = -1) { *this += os.get<P377Element>(); }

    void pack(octetStream& os, int = -1) const;
    void unpack(octetStream& os, int = -1);

    G1 get_point();

    octetStream hash(size_t n_bytes) const;

    friend ostream& operator<<(ostream& s, const P377Element& x);

//    static P377Element Mul(const P377Element &a, P377Element::Scalar &b)
//    {
//        return a * b;
//    }

    // Custom functions for compatibility with libff
    static P377Element zero() {
        return P377Element();
    }
    static const int num_limbs = Scalar::N_LIMBS;
    P377Element dbl() {
        // this should be implemented in openssl?
        return *this + *this;
    }
    P377Element mixed_add(const P377Element &other) {
        return *this + other;
    }

    // End of custom functions

};

P377Element operator*(const P377Element::Scalar& x, const P377Element& y);

#endif /* ECDSA_P377ELEMENT_H_ */
