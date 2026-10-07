// Fuzz target for the private-key file parser (PrivateKeys::FromBuffer),
// which is the keyinfo / offlinekeys / vain / regaddr parsing path.
#include <cstddef>
#include <cstdint>

#include "Crypto.h"
#include "Identity.h"
#include "Log.h"

static const bool kCryptoInit = [] {
    i2p::crypto::InitCrypto(false);
    return true;
}();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    (void)kCryptoInit;
    // No fuzz target starts libi2pd's log worker (Log::Start is never called),
    // so every message LogPrint queues is retained for the process lifetime:
    // a 60 s b33address/verifyhost run grew to ~4 GB and tripped libFuzzer's
    // RSS limit (weekly CI, 2026-08..10). Nothing drains the queue, so nothing
    // was ever printed either. Set the level on the first call, not from a
    // static initializer: Log.o's `logger` is a namespace-scope object whose
    // constructor (m_MinLevel = eLogInfo) may still run afterwards and reset it.
    static const bool kLogSilenced = [] {
        i2p::log::Logger().SetLogLevel("none");
        return true;
    }();
    (void)kLogSilenced;
    // mirror the keyinfo file-size cap (64 MiB)
    if (size > 64u * 1024u * 1024u)
        return 0;
    i2p::data::PrivateKeys keys;
    (void)keys.FromBuffer(data, size);
    return 0;
}
