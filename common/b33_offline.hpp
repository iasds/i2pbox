#ifndef I2PBOX_COMMON_B33_OFFLINE_HPP
#define I2PBOX_COMMON_B33_OFFLINE_HPP
// b33 offline keys batch format (upstream PurpleI2P/i2pd-tools PR #124,
// freeacetone/i2pd b33-offline-keys branch; libi2pd side not yet merged
// upstream, so the constants and the reader live here instead of libi2pd):
//
//   version(1) || ident hash(32) || number of keys(2),
//   then per day: expires(4) || transient sig type(2) || transient pubkey ||
//   signature by that day's blinded key || transient privkey.
//
// The batch is appended to the keys file after the online (offline-signed)
// keys. libi2pd's PrivateKeys::FromBuffer stops at the end of the online
// keys and ignores trailing bytes, so old readers stay compatible.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "I2PEndian.h"
#include "Identity.h"
#include "Timestamp.h"

namespace i2pbox {

inline constexpr uint8_t kB33OfflineKeysVersion = 1;
inline constexpr std::size_t kB33OfflineKeysHeaderLength = 1 + 32 + 2;
inline constexpr std::size_t kOfflineSignatureHeaderLength = 4 + 2; // expires, transient sig type
inline constexpr uint64_t kSecondsPerDay = 24 * 60 * 60;
inline constexpr int kB33OfflineMaxDays = 0xFFFF; // key count field is two bytes

// Parse a batch at buf[0, len). On success fills numKeys/firstDate/lastDate
// (dates as YYYYMMDD) and returns true. Returns false (no output) for a
// missing, truncated, or otherwise malformed batch. Strictly bounds-checked:
// keyinfo feeds it arbitrary key files.
inline bool DescribeB33OfflineBatch(const uint8_t * buf, std::size_t len,
    const i2p::data::IdentHash& identHash,
    uint16_t& numKeys, std::string& firstDate, std::string& lastDate)
{
    if (len < kB33OfflineKeysHeaderLength)
        return false;
    if (buf[0] != kB33OfflineKeysVersion)
        return false;
    if (std::memcmp(buf + 1, identHash, 32) != 0)
        return false;
    const uint16_t n = bufbe16toh(buf + 33);
    if (n == 0)
        return false;
    // blinded keys are always RedDSA; the signature length is fixed per batch
    std::unique_ptr<i2p::crypto::Verifier> blindedVerifier(
        i2p::data::IdentityEx::CreateVerifier(
            i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519));
    if (!blindedVerifier)
        return false;
    const std::size_t blindedSignatureLen = blindedVerifier->GetSignatureLen();
    std::size_t offset = kB33OfflineKeysHeaderLength;
    std::string first, last;
    for (uint16_t i = 0; i < n; i++) {
        if (offset + kOfflineSignatureHeaderLength > len)
            return false;
        const uint32_t expires = bufbe32toh(buf + offset);
        const uint16_t sigType = bufbe16toh(buf + offset + 4);
        std::unique_ptr<i2p::crypto::Verifier> transientVerifier(
            i2p::data::IdentityEx::CreateVerifier(sigType));
        if (!transientVerifier)
            return false;
        const std::size_t entryLen = kOfflineSignatureHeaderLength +
            transientVerifier->GetPublicKeyLen() +
            blindedSignatureLen + transientVerifier->GetPrivateKeyLen();
        if (offset + entryLen > len)
            return false;
        if (expires < kSecondsPerDay)
            return false;
        char date[9];
        i2p::util::GetDateString(expires - kSecondsPerDay, date);
        if (i == 0) first = date;
        last = date;
        offset += entryLen;
    }
    numKeys = n;
    firstDate = first;
    lastDate = last;
    return true;
}

} // namespace i2pbox

#endif
