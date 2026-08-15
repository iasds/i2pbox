// Fuzz target for the private-key file parser (PrivateKeys::FromBuffer),
// which is the keyinfo / offlinekeys / vain / regaddr parsing path.
#include <cstddef>
#include <cstdint>

#include "Crypto.h"
#include "Identity.h"

static const bool kCryptoInit = [] {
    i2p::crypto::InitCrypto(false);
    return true;
}();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    (void)kCryptoInit;
    // mirror the keyinfo file-size cap (64 MiB)
    if (size > 64u * 1024u * 1024u)
        return 0;
    i2p::data::PrivateKeys keys;
    (void)keys.FromBuffer(data, size);
    return 0;
}
