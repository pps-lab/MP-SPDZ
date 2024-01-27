/*
 * mal-rep-ecdsa-party.cpp
 *
 */

#include "Protocols/Rep3Share2k.h"
#include "Protocols/Rep3Share.h"

#include "hm-switch-party.hpp"

int main(int argc, const char** argv)
{
    run<Rep3Share, Rep3Share>(argc, argv);
}
