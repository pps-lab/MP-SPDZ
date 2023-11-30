
#ifndef SHARE_UTILS_HPP
#define SHARE_UTILS_HPP


template<class T>
std::vector<T> read_inputs(Player& P, size_t size) {
    if (size == 0) {
        return std::vector<T>();
    }
    Binary_File_IO binary_file_io = Binary_File_IO();

    string filename;
    filename = binary_file_io.filename(P.my_num());

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



#endif /* SHARE_UTILS_HPP */