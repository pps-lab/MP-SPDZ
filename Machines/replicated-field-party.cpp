/*
 * replicated-field-party.cpp
 *
 */

//#define VERBOSE 1 # TODO: Somehow setting this to 1 gives weird compilation errors

#include "Math/gfp.hpp"
#include "Processor/FieldMachine.hpp"
#include "Machines/Rep.hpp"

int main(int argc, const char** argv)
{
    HonestMajorityFieldMachine<Rep3Share>(argc, argv);
}
