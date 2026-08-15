// Fuzz target for the shared base64 decoder (decode_base64_string in
// i2pbase64.cpp). libFuzzer defines FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION,
// which silences the per-parse error messages.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

int decode_base64_string(const std::string & input, std::vector<uint8_t> & out);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    std::string input(reinterpret_cast<const char *>(data), size);
    std::vector<uint8_t> out;
    (void)decode_base64_string(input, out);
    return 0;
}
