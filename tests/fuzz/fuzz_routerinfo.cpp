// Fuzz target for the router.info parser (RouterInfo buffer constructor),
// which is the routerinfo / famtool parsing path.
#include <cstddef>
#include <cstdint>

#include "Crypto.h"
#include "RouterInfo.h"

static const bool kCryptoInit = [] {
    i2p::crypto::InitCrypto(false);
    return true;
}();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    (void)kCryptoInit;
    // a sane cap for router.info documents (published ones are a few KB)
    if (size > 4u * 1024u * 1024u)
        return 0;
    i2p::data::RouterInfo ri(data, size);
    (void)ri.IsUnreachable();
    (void)ri.GetIdentHashBase64();
    return 0;
}
