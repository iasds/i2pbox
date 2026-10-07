// Fuzz target for the b33 offline-keys batch tail parser
// (i2pbox::DescribeB33OfflineBatch), reached in production through
// `keyinfo -b` on a key file with an appended per-day batch. The input is
// treated as a whole key file: parse the online keys, then describe the
// trailing batch, if any.
#include <cstddef>
#include <cstdint>
#include <string>

#include "Crypto.h"
#include "Identity.h"
#include "Log.h"
#include "common/b33_offline.hpp"

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
    const std::size_t onlineLen = keys.FromBuffer(data, size);
    auto dest = keys.GetPublic();
    if (!onlineLen || !dest || onlineLen >= size)
        return 0;
    uint16_t numKeys = 0;
    std::string firstDate, lastDate;
    (void)i2pbox::DescribeB33OfflineBatch(data + onlineLen, size - onlineLen,
        dest->GetIdentHash(), numKeys, firstDate, lastDate);
    return 0;
}
