// b33offlinekeys: per-day keys that let a router publish an encrypted
// LeaseSet (a b33 address) without holding the destination's signing key.
// Port of upstream PurpleI2P/i2pd-tools b33offlinekeys.cpp (PR #124) to the
// i2pbox single-binary layout: tool entry point, hardened file handling,
// strict day validation, and 0600 output files per repo convention.
//
// The batch layout constants live in common/b33_offline.hpp because the
// libi2pd side (freeacetone/i2pd b33-offline-keys branch) is not merged
// upstream yet and our pinned libi2pd has no B33_OFFLINE_KEYS_* symbols.
// The batch is appended after the online keys; PrivateKeys::FromBuffer
// stops at the end of the online keys, so old readers ignore the tail.
#include <iostream>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "Blinding.h"
#include "Crypto.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "Timestamp.h"
#include "common/b33_offline.hpp"
#include "common/key.hpp"
#include "common/secure_file.hpp"
#include <openssl/crypto.h>

static std::vector<uint8_t> createB33OfflineKeys(const i2p::data::PrivateKeys& keys,
    i2p::data::SigningKeyType transientSigType, int days)
{
    std::vector<uint8_t> buf;
    if (days < 1 || days > i2pbox::kB33OfflineMaxDays) return buf;
    auto identity = keys.GetPublic();
    i2p::data::BlindedPublicKey blindedKey(identity);
    if (!blindedKey.IsValid()) return buf;
    std::unique_ptr<i2p::crypto::Verifier> transientVerifier(
        i2p::data::IdentityEx::CreateVerifier(transientSigType));
    std::unique_ptr<i2p::crypto::Verifier> blindedVerifier(
        i2p::data::IdentityEx::CreateVerifier(blindedKey.GetBlindedSigType()));
    if (!transientVerifier || !blindedVerifier) return buf;
    const std::size_t blindedSignatureLen = blindedVerifier->GetSignatureLen();
    const std::size_t transientPublicKeyLen = transientVerifier->GetPublicKeyLen();
    const std::size_t signedDataLen = i2pbox::kOfflineSignatureHeaderLength + transientPublicKeyLen;
    const std::size_t keyLen = signedDataLen + blindedSignatureLen + transientVerifier->GetPrivateKeyLen();

    buf.resize(i2pbox::kB33OfflineKeysHeaderLength + static_cast<std::size_t>(days) * keyLen);
    std::size_t offset = 0;
    buf[offset] = i2pbox::kB33OfflineKeysVersion; offset++;
    std::memcpy(buf.data() + offset, identity->GetIdentHash(), 32); offset += 32;
    htobe16buf(buf.data() + offset, static_cast<uint16_t>(days)); offset += 2;
    const uint64_t midnight = (i2p::util::GetSecondsSinceEpoch() / i2pbox::kSecondsPerDay) * i2pbox::kSecondsPerDay;
    for (int i = 0; i < days; i++) {
        char date[9];
        i2p::util::GetDateString(midnight + static_cast<uint64_t>(i) * i2pbox::kSecondsPerDay, date);
        uint8_t * signedData = buf.data() + offset;
        htobe32buf(signedData, static_cast<uint32_t>(midnight + static_cast<uint64_t>(i + 1) * i2pbox::kSecondsPerDay)); // expires at the end of that day
        htobe16buf(signedData + 4, transientSigType);
        uint8_t blindedPriv[32], blindedPub[32];
        if (!blindedKey.BlindPrivateKey(keys.GetSigningPrivateKey(), date, blindedPriv, blindedPub)) {
            OPENSSL_cleanse(buf.data(), buf.size());
            buf.clear();
            return buf;
        }
        std::unique_ptr<i2p::crypto::Signer> blindedSigner(
            i2p::data::PrivateKeys::CreateSigner(blindedKey.GetBlindedSigType(), blindedPriv));
        OPENSSL_cleanse(blindedPriv, sizeof(blindedPriv)); // it would give the destination's key away
        if (!blindedSigner) {
            OPENSSL_cleanse(buf.data(), buf.size());
            buf.clear();
            return buf;
        }
        i2p::data::PrivateKeys::GenerateSigningKeyPair(transientSigType,
            signedData + signedDataLen + blindedSignatureLen, signedData + i2pbox::kOfflineSignatureHeaderLength);
        blindedSigner->Sign(signedData, signedDataLen, signedData + signedDataLen);
        offset += keyLen;
    }
    return buf;
}

int tool_b33offlinekeys(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "Usage: b33offlinekeys <output file> <keys file> [days]" << std::endl;
        return 1;
    }
    std::string outName(argv[1]);
    std::string fname(argv[2]);
    if (outName == fname) {
        std::cerr << "output file must be different from the input keys file" << std::endl;
        return 1;
    }
    int days = 365; // 1 year by default
    if (argc > 3) {
        const std::string_view input(argv[3]);
        unsigned parsed = 0;
        const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), parsed);
        if (error != std::errc{} || end != input.data() + input.size() ||
            parsed < 1 || parsed > static_cast<unsigned>(i2pbox::kB33OfflineMaxDays)) {
            std::cerr << "days must be an integer between 1 and " << i2pbox::kB33OfflineMaxDays << std::endl;
            return 6;
        }
        days = static_cast<int>(parsed);
    }

    i2p::data::PrivateKeys keys;
    {
        std::vector<uint8_t> buff;
        std::ifstream inf;
        inf.open(fname);
        if (!inf.is_open()) {
            std::cerr << "cannot open keys file " << fname << std::endl;
            return 2;
        }
        inf.seekg(0, std::ios::end);
        const std::size_t len = static_cast<std::size_t>(inf.tellg());
        inf.seekg(0, std::ios::beg);
        if (len == static_cast<std::size_t>(-1) || len > 64 * 1024 * 1024) {
            std::cerr << "bad keys file size" << std::endl;
            return 3;
        }
        buff.resize(len);
        inf.read(reinterpret_cast<char *>(buff.data()), buff.size());
        if (!inf || static_cast<std::size_t>(inf.gcount()) != buff.size()) {
            std::cerr << "short read on keys file" << std::endl;
            OPENSSL_cleanse(buff.data(), buff.size());
            return 3;
        }
        const bool valid = keys.FromBuffer(buff.data(), buff.size()) != 0;
        OPENSSL_cleanse(buff.data(), buff.size());
        if (!valid) {
            std::cerr << "bad keys file format" << std::endl;
            return 3;
        }
    }
    if (keys.IsOfflineSignature()) {
        std::cerr << "the destination's own keys are required, " << fname << " holds offline keys" << std::endl;
        return 4;
    }
    // only a blindable destination has a b33 address at all. NB: gate on the
    // signature type first — constructing BlindedPublicKey on other types
    // aborts inside libi2pd instead of reporting invalid.
    const auto destSigType = keys.GetPublic()->GetSigningKeyType();
    if (destSigType != i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 &&
        destSigType != i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519) {
        std::cerr << fname << " is a " << SigTypeToName(destSigType)
            << " destination and has no b33 address; ED25519-SHA512 or RED25519-SHA512 is required" << std::endl;
        return 5;
    }

    // The outer layer of an encrypted LeaseSet is built on blinded keys, which are RedDSA
    const i2p::data::SigningKeyType type = i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519;
    auto b33Keys = createB33OfflineKeys(keys, type, days);
    if (b33Keys.empty()) {
        std::cerr << "Can't create b33 offline keys" << std::endl;
        return 7;
    }
    // the transient of the inner LeaseSet lasts exactly as long as the batch
    const uint32_t expires = static_cast<uint32_t>(
        (i2p::util::GetSecondsSinceEpoch() / i2pbox::kSecondsPerDay + static_cast<uint64_t>(days)) * i2pbox::kSecondsPerDay);
    auto onlineKeys = keys.CreateOfflineKeys(i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519, expires);
    std::vector<uint8_t> out(onlineKeys.GetFullLen() + b33Keys.size());
    const std::size_t l = onlineKeys.ToBuffer(out.data(), out.size());
    if (!l) {
        std::cerr << "Can't serialize online keys" << std::endl;
        return 8;
    }
    std::memcpy(out.data() + l, b33Keys.data(), b33Keys.size());
    out.resize(l + b33Keys.size());
    OPENSSL_cleanse(b33Keys.data(), b33Keys.size());
    if (!i2pbox::WritePrivateFile(outName, out.data(), out.size())) {
        std::cerr << "Can't create file " << outName << std::endl;
        OPENSSL_cleanse(out.data(), out.size());
        return 1;
    }
    OPENSSL_cleanse(out.data(), out.size());
    i2p::data::BlindedPublicKey blindedKey(keys.GetPublic());
    std::cout << "Address " << blindedKey.ToB33() << ".b32.i2p, " << days << " days" << std::endl
        << "Give the router this file and keep the destination keys offline:" << std::endl
        << "  keys = " << outName << std::endl
        << "  i2cp.leaseSetType = 5" << std::endl;
    return 0;
}
