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
    bool debug;

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
        opt.parse(argc, argv);

        opt.get("-n")->getInt(n_shares);
        opt.get("-s")->getInt(start);
        opt.get("-b")->getInt(n_bits_per_input);
        opt.get("-i")->getMultiStrings(inputs_format);
        opt.get("-o")->getInt(output_start);
        opt.get("-t")->getInt(n_threads);
        opt.get("-c")->getInt(chunk_size);
        debug = opt.isSet("-d");

        opt.resetArgs();
    }
};

#endif /* ECDSA_SWITCHOPTIONS_H_ */
