/*
 * EcdsaOptions.h
 *
 */

#ifndef ECDSA_SWITCHOPTIONS_H_
#define ECDSA_SWITCHOPTIONS_H_

#include "Tools/ezOptionParser.h"

class SwitchOptions
{
public:
    int n_shares;
    int start;
    int n_bits_per_input;

    SwitchOptions(ez::ezOptionParser& opt, int argc, const char** argv)
    {
        opt.add(
                "92", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Number of shares to convert", // Help description.
                "-n", // Flag token.
                "--n_shares" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Start position of shares", // Help description.
                "-s", // Flag token.
                "--start" // Flag token.
        );
        opt.add(
                "-1", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Number of bits per input", // Help description.
                "-b", // Flag token.
                "--n_bits" // Flag token.
        );

        opt.parse(argc, argv);

        opt.get("-n")->getInt(n_shares);
        opt.get("-s")->getInt(start);
        opt.get("-b")->getInt(n_bits_per_input);
        opt.resetArgs();
    }
};

#endif /* ECDSA_SWITCHOPTIONS_H_ */
