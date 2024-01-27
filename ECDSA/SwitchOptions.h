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
    std::vector<std::vector<std::string> > inputs_format;
    int output_start;
    int n_threads;
    int chunk_size;
    int input_prime_length;
    bool debug;
    bool test;
    bool only_distribute_inputs;
    bool use_share_split;
    std::string curve;

    SwitchOptions(ez::ezOptionParser& opt, int argc, const char** argv)
    {
        opt.add(
                "", // Default.
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
        opt.add(
                "",
                0,
                1,
                ',',
                "Input format",
                "-i",
                "--input"
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
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Output start position", // Help description.
                "-o", // Flag token.
                "--out_start" // Flag token.
        );
        opt.add(
                "1",
                0,
                1,
                0,
                "Number of parallel threads",
                "-t",
                "--n_threads"
                );
        opt.add(
                "250000",
                0,
                1,
                0,
                "Chunk size",
                "-c",
                "--chunk_size"
                );
        opt.add(
                "",
                0,
                0,
                0,
                "Debug mode",
                "-d",
                "--debug"
                );
        opt.add(
                "",
                0,
                0,
                0,
                "Test mode",
                "-te",
                "--test"
                );
        opt.add(
                "128",
                0,
                1,
                0,
                "Input prime length",
                "-pr",
                "--prime_length"
                );
        opt.add(
                "",
                0,
                0,
                0,
                "Only distribute inputs without converting shares",
                "-nc",
                "--no_conversion"
                );
        opt.add(
                "",
                0,
                0,
                0,
                "Use share split",
                "-sp",
                "--split"
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
        opt.get("-b")->getInt(n_bits_per_input);
        if (opt.isSet("-i")) {
            opt.get("-i")->getMultiStrings(inputs_format);
        }
        opt.get("-o")->getInt(output_start);
        opt.get("-t")->getInt(n_threads);
        opt.get("-c")->getInt(chunk_size);
        opt.get("-pr")->getInt(input_prime_length);
        opt.get("-cu")->getString(curve);
        debug = opt.isSet("-d");
        test = opt.isSet("-te");
        only_distribute_inputs = opt.isSet("-nc");
        use_share_split = opt.isSet("-sp");

        opt.resetArgs();
    }
};

#endif /* ECDSA_SWITCHOPTIONS_H_ */
