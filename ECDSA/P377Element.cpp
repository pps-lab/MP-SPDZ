/*
 * P377Element.cpp
 *
 */

#include "P377Element.h"

#include "Math/gfp.hpp"

//EC_GROUP* P377Element::curve;

void P377Element::init()
{
    libff::bls12_377_pp::init_public_params();

    mpz_t t;
    mpz_init(t);
    G1::order().to_mpz(t);

    Scalar::init_field(bigint(t), false);
}

void P377Element::finish()
{
//    EC_GROUP_free(curve);
    // unused?
}

P377Element::P377Element()
{
//    point = EC_POINT_new(curve);
//    assert(point != 0);
//    assert(EC_POINT_set_to_infinity(curve, point) != 0);

    point = G1();
}

P377Element::P377Element(const Scalar& other) :
        P377Element()
{
    // Convert other
    auto fr = libff::bls12_377_Fr(bigint(other).get_str().c_str());
    point = fr * G1::zero();
}

P377Element::P377Element(word other) :
        P377Element()
{
    auto fr = libff::bls12_377_Fr(to_string(other).c_str());
    point = fr * G1::zero();
}
P377Element::P377Element(P377Element::G1 p) {
    point = p;
}

P377Element::~P377Element()
{
//    EC_POINT_free(point);
}

P377Element& P377Element::operator =(const P377Element& other)
{
//    assert(EC_POINT_copy(point, other.point) != 0);
    point = other.point;
    return *this;
}

void P377Element::check()
{
    point.is_in_safe_subgroup();
//    assert(EC_POINT_is_on_curve(curve, point, 0) == 1);
}

P377Element::Scalar P377Element::x() const
{
//    BIGNUM* x = BN_new();
//#if OPENSSL_VERSION_MAJOR >= 3
//    assert(EC_POINT_get_affine_coordinates(curve, point, x, 0, 0) != 0);
//#else
//    assert(EC_POINT_get_affine_coordinates_GFp(curve, point, x, 0, 0) != 0);
//#endif
//    char* xx = BN_bn2dec(x);
//    Scalar res((bigint(xx)));
//    OPENSSL_free(xx);
//    BN_free(x);
//    return res;
    G1 copy(point);
    copy.to_affine_coordinates();
    mpz_t t;
    mpz_init(t);
    copy.X.as_bigint().to_mpz(t);
    Scalar res((bigint(t)));
    return res;
}

P377Element P377Element::operator +(const P377Element& other) const
{
    P377Element res;
//    assert(EC_POINT_add(curve, res.point, point, other.point, 0) != 0);
    res.point = point + other.point;
    return res;
}

P377Element P377Element::operator -(const P377Element& other) const
{
    P377Element tmp = other;
    tmp.point = -tmp.point;
    return *this + tmp;
}

P377Element P377Element::operator *(const Scalar& other) const
{
    P377Element res;
//    BIGNUM* exp = BN_new();
//    BN_dec2bn(&exp, bigint(other).get_str().c_str());
//    assert(EC_POINT_mul(curve, res.point, 0, point, exp, 0) != 0);
//    BN_free(exp);
    auto fr = libff::bls12_377_Fr(bigint(other).get_str().c_str());
    res.point = fr * point;
    return res;
}

bool P377Element::operator ==(const P377Element& other) const
{
    int cmp = (point == other.point);
    assert(cmp == 0 or cmp == 1);
    return cmp;
}

void P377Element::pack(octetStream& os, int) const
{
    G1 copy(point);
    copy.to_affine_coordinates();
//
    std::ostringstream ss;
    libff::group_write<libff::encoding_binary, libff::form_plain, libff::compression_on>(copy, ss);
//    (void)os;
//
    std::string buffer_str = ss.str();
    size_t length = buffer_str.length();
//    std::cout << "Length 377 " << length << std::endl;
    octet* buffer = (octet*) buffer_str.c_str();
    os.store_int(length, 8);
    os.append(buffer, length);

//    size_t length = EC_POINT_point2buf(curve, point,
//            POINT_CONVERSION_COMPRESSED, &buffer, 0);
//    std::cout << "Length " << length << std::endl;
//    assert(length != 0);
//    os.store_int(length, 8);
//    os.append(buffer, length);
//    free(buffer);
}

void P377Element::unpack(octetStream& os, int)
{
//    size_t length = os.get_int(8);
//    assert(
//            EC_POINT_oct2point(curve, point, os.consume(length), length, 0)
//                    != 0);

    size_t length = os.get_int(8);
    octet* buffer = os.consume(length);
    std::string buffer_str((char*) buffer, length);
    std::istringstream ss(buffer_str);
//
    libff::group_read<libff::encoding_binary, libff::form_plain, libff::compression_on>(point, ss);
//    free(buffer);
}

ostream& operator <<(ostream& s, const P377Element& x)
{
    s << x.point;
    return s;
//    char* hex = EC_POINT_point2hex(x.curve, x.point,
//            POINT_CONVERSION_COMPRESSED, 0);
//    s << point;
//    OPENSSL_free(hex);
//    return s;
}

P377Element::P377Element(const P377Element& other) :
        P377Element()
{
    *this = other;
}

P377Element operator*(const P377Element::Scalar& x, const P377Element& y)
{
    return y * x;
}

P377Element& P377Element::operator +=(const P377Element& other)
{
    *this = *this + other;
    return *this;
}

P377Element& P377Element::operator /=(const Scalar& other)
{
    *this = *this * other.invert();
    return *this;
}

bool P377Element::operator !=(const P377Element& other) const
{
    return not (*this == other);
}

octetStream P377Element::hash(size_t n_bytes) const
{
    octetStream os;
    pack(os);
    auto res = os.hash();
    assert(n_bytes >= res.get_length());
    res.resize_precise(n_bytes);
    return res;
}

void P377Element::randomize(PRNG& G, int n)
{
    (void) n;
    P377Element::Scalar newscalar;
    newscalar.randomize(G, n);
    point = P377Element(newscalar).point;
}

void P377Element::input(istream& s,bool human)
{
    P377Element::Scalar newscalar;
    newscalar.input(s,human);
    point = P377Element(newscalar).point;
}

P377Element::G1 P377Element::get_point() {
    return point;
}