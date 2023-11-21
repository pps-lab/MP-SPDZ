/*
 * EcdsaOptions.h
 *
 */

#ifndef ECDSA_PCOPTIONS_H_
#define ECDSA_PCOPTIONS_H_

#include "Tools/ezOptionParser.h"

class PCOptions
{
public:
    vector<int> poly_dims;
    bool check_open;
    bool check_beaver_open;
    int n_datasets;

    PCOptions(ez::ezOptionParser& opt, int argc, const char** argv)
    {
        opt.add(
                "", // Default.
                0, // Required?
                0, // Number of args expected.
                ',', // Delimiter if expecting multiple args.
                "Sizes of the commitments to commit to", // Help description.
                "-D", // Flag token.
                "--dimensions" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                0, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Number of dataset commitments", // Help description.
                "-N", // Flag token.
                "--n_datasets" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                0, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Skip checking final openings (but not necessarily openings for Beaver; only relevant with active protocols)", // Help description.
                "-C", // Flag token.
                "--no-open-check" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                0, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Skip checking Beaver openings (only relevant with active protocols)", // Help description.
                "-B", // Flag token.
                "--no-beaver-open-check" // Flag token.
        );
        opt.parse(argc, argv);

        if (opt.isSet("-D")) {
            opt.get("-D")->getInts(poly_dims);
            std::cout << "getting ints " << poly_dims.size() << std::endl;
        } else {
            poly_dims.push_back(16);
            std::cout << "pushing ints" << std::endl;
        }

        check_open = not opt.isSet("-C");
        check_beaver_open = not opt.isSet("-B");
        opt.get("-N")->getInt(n_datasets);
        std::cout << "Datasets " << n_datasets << std::endl;

        opt.resetArgs();
    }
};

#endif /* ECDSA_PCOPTIONS_H_ */
