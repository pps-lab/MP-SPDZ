
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
std::vector<T> read_inputs(Player& P, size_t size, string suffix = "") {
    if (size == 0) {
        return std::vector<T>();
    }
    Binary_File_IO binary_file_io = Binary_File_IO();

    string filename;
    filename = binary_file_io.filename(P.my_num());
    filename = addSuffixBeforeExtension(filename, suffix);

    std::vector< T > outbuf(size);

    int start_file_posn = 0;
    int end_file_posn = start_file_posn;

    try {
        binary_file_io.read_from_file(filename, outbuf, start_file_posn, end_file_posn);
    } catch (file_missing& e) {
        cerr << "Got file missing error, will return -2. " << e.what() << endl;
    }

    return outbuf;
}

template<class T>
void write_shares(Player& P, vector<T>& shares, string suffix = "") {
    Binary_File_IO binary_file_io = Binary_File_IO();

    string filename;
    filename = binary_file_io.filename(P.my_num());
    const string filename_suffix = addSuffixBeforeExtension(filename, suffix);


    ofstream outf;
    outf.open(filename_suffix, ios::out | ios::binary);
    outf.close();
    if (outf.fail()) {
        cerr << "22 open failure as expected: " << strerror(errno) << '\n';
        throw file_error(filename_suffix);
    }

    int start_pos = 0;

    binary_file_io.write_to_file(filename_suffix, shares, start_pos);

}




#endif /* SHARE_UTILS_HPP */