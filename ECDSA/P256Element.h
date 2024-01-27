/*
 * Element.h
 *
 */

#ifndef ECDSA_P256ELEMENT_H_
#define ECDSA_P256ELEMENT_H_

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include "Math/gfp.h"

class P256Element : public ValueInterface
{
public:
    typedef gfp_<2, 4> Scalar;

private:
    static EC_GROUP* curve;

    EC_POINT* point;

public:
    typedef P256Element next;
    typedef void Square;

    static const true_type invertible;

    static int size() { return 0; }
    static int length() { return 256; }
    static string type_string() { return "P256"; }

    static void init(bool init_field = false);
    static void finish();

    P256Element();
    P256Element(const P256Element& other);
    P256Element(const Scalar& other);
    P256Element(word other);
    ~P256Element();

    P256Element& operator=(const P256Element& other);

    void check();

    Scalar x() const;
    void randomize(PRNG& G, int n = -1);
    void input(istream& s, bool human);
    static string type_short() { return "ec"; }
    static DataFieldType field_type() { return DATA_INT; }

    P256Element operator+(const P256Element& other) const;
    P256Element operator-(const P256Element& other) const;
    P256Element operator*(const Scalar& other) const;

    P256Element& operator+=(const P256Element& other);
    P256Element& operator/=(const Scalar& other);

    bool operator==(const P256Element& other) const;
    bool operator!=(const P256Element& other) const;

    void pack(octetStream& os, int = -1) const;
    void unpack(octetStream& os, int = -1);

    friend ostream& operator<<(ostream& s, const P256Element& x);

    static bigint get_order() {
        assert(curve != 0);
        auto modulus = EC_GROUP_get0_order(curve);
        auto mod = BN_bn2dec(modulus);
        return mod;
    }


    // Custom functions for compatibility with libff
    static P256Element zero() {
        return P256Element();
    }
    static const int num_limbs = Scalar::N_LIMBS;
    P256Element dbl() {
        // this should be implemented in openssl?
        return *this + *this;
    }
    P256Element mixed_add(const P256Element &other) {
        return *this + other;
    }

    // End of custom functions
};

P256Element operator*(const P256Element::Scalar& x, const P256Element& y);

#endif /* ECDSA_P256ELEMENT_H_ */
