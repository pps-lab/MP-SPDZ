
#ifndef SHARE_UTILS_HPP
#define SHARE_UTILS_HPP

const string KZG_SUFFIX = "-P251";

std::string addSuffixBeforeExtension(const std::string& filename, const std::string& suffix) {
    size_t dotPos = filename.find_last_of(".");
    if (dotPos == std::string::npos) {
        // No extension found, return the filename as is or handle it as per your need.
        return filename;
    }
    return filename.substr(0, dotPos) + suffix + filename.substr(dotPos);
}

template<class T>
void checkSignature(string filename) {
    ifstream pers(filename);
    try
    {
        check_file_signature<T>(pers, filename);
    }
    catch (signature_mismatch&)
    {
        ofstream pers(filename, ios::binary);
        file_signature<T>().output(pers);
    }
}

//SOMETHING IS OFF WITH READ/WRITE SHARES

template<class T>
std::vector<T> read_inputs(Player& P, size_t size, int start, string suffix = "") {
    if (size == 0) {
        return std::vector<T>();
    }
    Binary_File_IO binary_file_io = Binary_File_IO();

    string filename;
    filename = binary_file_io.filename(P.my_num());
    const string filename_suffix = addSuffixBeforeExtension(filename, suffix);

    std::cout << "Reading shares with " << file_signature<T>() << " signature." << std::endl;

    std::vector< T > outbuf(size);

    int start_file_posn = start;
    int end_file_posn = start_file_posn;

    try {
        binary_file_io.read_from_file(filename_suffix, outbuf, start_file_posn, end_file_posn);
    } catch (file_missing& e) {
        cerr << "Got file missing error, will return -2. " << e.what() << endl;
        throw file_error(filename_suffix);
    }

    return outbuf;
}

template<class T>
void write_shares(Player& P, vector<T>& shares, string suffix = "", bool overwrite = false, int start_pos = 0) {
    Binary_File_IO binary_file_io = Binary_File_IO();

    string filename;
    filename = binary_file_io.filename(P.my_num());
    const string filename_suffix = addSuffixBeforeExtension(filename, suffix);

    assert(not (overwrite && start_pos > 0)); // cannot overwrite file and start at a non-zero position

    if (overwrite) {
        ofstream outf;
        outf.open(filename_suffix, ios::out | ios::binary | ios::trunc);
        outf.close();
        std::cout << "truncating output file to start from the beginning" << std::endl;
    }

    checkSignature<T>(filename_suffix);
    std::cout << "Writing " << shares.size() << " shares " << " with " << file_signature<T>() << " signature. (appending to the end of the file)" << std::endl;

    // should append at the end!
    (void)start_pos;
    binary_file_io.write_to_file(filename_suffix, shares, -1);

}

void print_timer(const string name, double elapsed_s) {
    std::cout << fixed << "TIMER (name=" << name << "_mus) (value=" << (long long)(elapsed_s * 1e6) << ")" << std::endl;
}
void print_stat(const string name, NamedCommStats& stats) {
    std::cout << fixed << "STATS (name=" << name << "_bytes) (value=" << stats.sent << ")" << std::endl;
}

void print_global(const string name, Player &P, NamedCommStats& stats) {
    Bundle<octetStream> bundle(P);
    bundle.mine.store(stats.sent);
    P.Broadcast_Receive_no_stats(bundle);
    size_t global = 0;
    for (auto& os : bundle)
        global += os.get_int(8);

    std::cout << fixed << "STATS (name=" << name << "_global_bytes) (value=" << global << ")" << std::endl;
//    cerr << "Global data sent = " << global / 1e6 << " MB (all parties)" << endl;
}



struct input_format_item
{
    char type;
    long length;
};
typedef std::vector<std::vector<input_format_item> > input_format_type;

input_format_type process_format(std::vector<std::vector<std::string> >& inputs_format) {
    std::vector<std::vector<input_format_item> > res;

    for (unsigned long i = 0; i < inputs_format.size(); i++) {

        std::vector<input_format_item> player_format;
        for (unsigned long j = 0; j < inputs_format[i].size(); j++) {
            if (inputs_format[i][j][0] == '0') {
                std::cout << "No inputs for player " << to_string(i) << std::endl;
                continue;
            } else if (inputs_format[i][j][0] == 'i') {
                player_format.push_back({'i', stoi(inputs_format[i][j].substr(1))});
            } else if (inputs_format[i][j][0] == 'f') {
                player_format.push_back({'f', stoi(inputs_format[i][j].substr(1))});
            } else {
                throw runtime_error("Unknown format");
            }
        }
        res.push_back(player_format);
    }
    return res;
}

template<class T>
std::vector<T> read_private_input(Player &P, std::vector<input_format_item> format) {
    string input_file = "Player-Data/Input-Binary-P" + to_string(P.my_num()) + "-0";
    ifstream binary_input;
    binary_input.open(input_file, ios::in | ios::binary);

    std::vector<T> inputs;
    for (unsigned long i = 0; i < format.size(); i++) {
        if (binary_input.peek() == EOF)
            throw IO_Error("not enough inputs in " + input_file);

        if (format[i].type == 'i') {
            // now parse the rest of format[i] into an int
            long cnt = format[i].length;
            std::cout << "Parsing " << cnt << " integers" << std::endl;
            for (int j = 0; j < cnt; j++) {
                int64_t x;
                binary_input.read((char*) &x, sizeof(x));
                // assert x is within range
                int64_t two_l_minus_one = (((int64_t)1) << (31 - 1));
                if (x < 0) {
                    std::cout << "Negative " << x << endl;
                }
                assert(x < two_l_minus_one and x > -two_l_minus_one);
                inputs.push_back(T(x));
            }
        } else if (format[i].type == 'f') {
            long cnt = format[i].length;
            std::cout << "Parsing " << cnt << " floats" << std::endl;
            for (int j = 0; j < cnt; j++) {
                float x;
                binary_input.read((char*) &x, sizeof(x));

                const double f = 16;
                long tmp = round(x * exp2(f));

//                std::cout << "Float " << j << " " << x << " " << tmp << endl;

                inputs.push_back(T(tmp));
            }
        } else {
            std::cerr << "Format is " << format[i].type << " " << to_string(format[i].length) << endl;
            throw runtime_error("Unknown format");
        }
    }
    std::cout << "Got " << inputs.size() << " inputs" << std::endl;
    return inputs;



//
//    for (int i = 0; i < instruction.get_size(); i++)
//    {
//        if (binary_input.peek() == EOF)
//            throw IO_Error("not enough inputs in " + binary_input_filename);
//        double buf;
//        if (instruction.get_r(2) == 0)
//        {
//            int64_t x;
//            binary_input.read((char*) &x, sizeof(x));
//            tmp = x;
//        }
//        else
//        {
//            if (use_double)
//                binary_input.read((char*) &buf, sizeof(double));
//            else
//            {
//                float x;
//                binary_input.read((char*) &x, sizeof(float));
//                buf = x;
//            }
//            tmp = bigint::tmp = round(buf * exp2(instruction.get_r(1)));
//        }
//        if (binary_input.fail())
//            throw IO_Error("failure reading from " + binary_input_filename);
//        write_Cp(instruction.get_r(0) + i, tmp);
//    }
}


#endif /* SHARE_UTILS_HPP */