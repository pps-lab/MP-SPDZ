/*
 * EcdsaOptions.h
 *
 */

#ifndef ECDSA_PEOPTIONS_H_
#define ECDSA_PEOPTIONS_H_

#include "Tools/ezOptionParser.h"

class PEOptions
{
public:
    int n_shares;
    int start;
    int input_party_i;
    string eval_point;
    string curve;

    PEOptions(ez::ezOptionParser& opt, int argc, const char** argv)
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
                "Input party ID", // Help description.
                "-i", // Flag token.
                "--input_party_i" // Flag token.
        );
        opt.add(
                "",
                0,
                1,
                0,
                "Evaluation point",
                "-e",
                "--eval_point"
                );
        opt.add(
                "bls12377",
                0,
                1,
                0,
                "Curve",
                "-cu",
                "--curve"
        );

        opt.parse(argc, argv);

        opt.get("-n")->getInt(n_shares);
        opt.get("-s")->getInt(start);
        opt.get("-i")->getInt(input_party_i);

        if (opt.isSet("-e")) {
            opt.get("-e")->getString(eval_point);
        }
        opt.get("-cu")->getString(curve);

        opt.resetArgs();

        if (input_party_i < 0) {
            std::cerr << "Input party ID must be specified." << std::endl;
            exit(1);
        }
    }
};

#endif /* ECDSA_PEOPTIONS_H_ */
