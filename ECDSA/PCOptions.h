/*
 * EcdsaOptions.h
 *
 */

#ifndef ECDSA_PCOPTIONS_H_
#define ECDSA_PCOPTIONS_H_

#include "Tools/ezOptionParser.h"

class PCOptions: public EcdsaOptions
{
public:
    bool check_open;
    bool check_beaver_open;
    int n_model;
    int n_x;
    int n_y;
    int start;
    string prime;
    string curve;
    string commit_type;

    PCOptions(ez::ezOptionParser& opt, int argc, const char** argv): EcdsaOptions(opt, argc, argv)
    {
        opt.add(
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Size of the model to commit to", // Help description.
                "-m", // Flag token.
                "--n_model" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Size of the x prediction to commit to", // Help description.
                "-x", // Flag token.
                "--n_x" // Flag token.
        );
        opt.add(
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Size of the y prediction to commit to", // Help description.
                "-y", // Flag token.
                "--n_y" // Flag token.
        );
        opt.add(
                "0", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Start reading shares from", // Help description.
                "-s", // Flag token.
                "--start" // Flag token.
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
        opt.add(
                "", // Default.
                0, // Required?
                1, // Number of args expected.
                0, // Delimiter if expecting multiple args.
                "Prime for GF(p) field (default: read from file or "
                "generated from -lgp argument)", // Help description.
                "-P", // Flag token.
                "--prime" // Flag token.
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
        opt.add(
                "ec_vec",
                0,
                1,
                0,
                "Commitment type",
                "-ct",
                "--commit-type"
        );


        opt.parse(argc, argv);

//        if (opt.isSet("-D")) {
//            opt.get("-D")->getInts(poly_dims);
//            std::cout << "getting ints " << poly_dims.size() << std::endl;
//        } else {
//            poly_dims.push_back(16);
//            std::cout << "pushing ints" << std::endl;
//        }

        check_open = not opt.isSet("-C");
        check_beaver_open = not opt.isSet("-B");

        std::cout << opt.isSet("-x") << std::endl;
        opt.get("-m")->getInt(n_model);
        opt.get("-x")->getInt(n_x);
        opt.get("-y")->getInt(n_y);
        opt.get("-s")->getInt(start);
        opt.get("--prime")->getString(prime);
        opt.get("-cu")->getString(curve);
        opt.get("-ct")->getString(commit_type);

        std::cout << "n_model " << n_model << std::endl;
        std::cout << "n_x " << n_x << std::endl;
        std::cout << "n_y " << n_y << std::endl;

        opt.resetArgs();
    }
};

#endif /* ECDSA_PCOPTIONS_H_ */
