
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
void write_shares(Player& P, vector<T>& shares, string suffix = "", bool overwrite = false) {
    Binary_File_IO binary_file_io = Binary_File_IO();

    string filename;
    filename = binary_file_io.filename(P.my_num());
    const string filename_suffix = addSuffixBeforeExtension(filename, suffix);

    int start_pos = 0;

    if (overwrite) {
        ofstream outf;
        outf.open(filename_suffix, ios::out | ios::binary | ios::trunc);
        outf.close();
        std::cout << "truncating value" << std::endl;
    }

    checkSignature<T>(filename_suffix);
    std::cout << "Writing shares with " << file_signature<T>() << " signature." << std::endl;

    binary_file_io.write_to_file(filename_suffix, shares, start_pos);

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


#endif /* SHARE_UTILS_HPP */