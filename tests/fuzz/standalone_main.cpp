// Standalone driver for the fuzz targets, used for corpus smoke runs on
// toolchains without libFuzzer (e.g. gcc in the local dev loop). Reads each
// file as one input and invokes LLVMFuzzerTestOneInput.
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size);

int main(int argc, char ** argv) {
    if (argc < 2) {
        std::cerr << "usage: fuzz_<target>_standalone <input-file>...\n";
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        std::ifstream in(argv[i], std::ios::binary);
        if (!in) {
            std::cerr << "cannot open " << argv[i] << "\n";
            return 1;
        }
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
        if (LLVMFuzzerTestOneInput(buf.data(), buf.size())) {
            std::cerr << "non-zero return on " << argv[i] << "\n";
            return 1;
        }
    }
    return 0;
}
