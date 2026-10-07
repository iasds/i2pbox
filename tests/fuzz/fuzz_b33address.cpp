// Fuzz target for the b33address parsing path: IdentityEx::FromBase64,
// Base64ToByteStream round-trip check, and BlindedPublicKey construction.
// Mirrors tool_b33address in b33address.cpp.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "Base.h"
#include "Crypto.h"
#include "Identity.h"
#include "LeaseSet.h"
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
    // real destinations are a single base64 line (~600 chars); cap far above
    // that so pathological fuzz inputs cannot exhaust memory
    if (size > 1024u * 1024u)
        return 0;
    std::string base64(reinterpret_cast<const char *>(data), size);
    auto ident = std::make_shared<i2p::data::IdentityEx>();
    std::vector<uint8_t> buf(base64.length()); // binary data can't exceed base64
    if (ident->FromBase64(base64) == 0 ||
        i2p::data::Base64ToByteStream(base64, buf.data(), buf.size()) != ident->GetFullLen())
        return 0;
    if (ident->GetSigningKeyType() == i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 ||
        ident->GetSigningKeyType() == i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519) {
        i2p::data::BlindedPublicKey blindedKey(ident);
        (void)blindedKey.ToB33();
        (void)blindedKey.GetStoreHash();
    }
    return 0;
}
