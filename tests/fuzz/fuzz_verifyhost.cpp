// Fuzz target for the host-record parsing path used by verifyhost and
// regaddralias records: "#!" splitting, "name=base64" extraction,
// "#sig=" / "!sig=" / "#olddest=" / "#oldsig=" scanning, IdentityEx::FromBase64
// on attacker-controlled substrings, and Base64ToByteStream into a
// signature-length buffer. Mirrors tool_verifyhost in verifyhost.cpp.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "Base.h"
#include "Crypto.h"
#include "Identity.h"

static const bool kCryptoInit = [] {
    i2p::crypto::InitCrypto(false);
    return true;
}();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    (void)kCryptoInit;
    // real host records are one line of ~700 chars; cap far above that so
    // pathological fuzz inputs cannot exhaust memory
    if (size > 1024u * 1024u)
        return 0;
    std::string str(reinterpret_cast<const char *>(data), size);

    i2p::data::IdentityEx Identity, OldIdentity;

    // get record without command block after "#!"
    std::size_t pos = str.find("#!");
    std::string hostStr = str.substr(0, pos);

    // get host base64 (upstream semantics: npos -> substr(0) = whole string)
    pos = hostStr.find("=");
    std::string hostBase64 = hostStr.substr(pos + 1);

    if (!Identity.FromBase64(hostBase64))
        return 0; // upstream prints an error and exits here

    // find the signature marker
    pos = str.find("#sig=");
    if (pos == std::string::npos)
        pos = str.find("!sig=");
    if (pos == std::string::npos)
        return 0;

    std::string hostNoSig = str.substr(0, pos - (pos > 0 && str[pos - 1] == '#' ? 1 : 0));
    std::string sig = str.substr(pos + 5); // after "#sig=" till end

    auto signatureLen = Identity.GetSignatureLen();
    std::vector<uint8_t> signature(signatureLen);
    i2p::data::Base64ToByteStream(sig, signature.data(), signatureLen);
    (void)Identity.Verify((uint8_t *)hostNoSig.c_str(), hostNoSig.length(), signature.data());

    if (str.find("olddest=") != std::string::npos)
    {
        pos = str.find("#olddest=");
        if (pos == std::string::npos)
            return 0; // guard: upstream would wrap, keep the harness crash-free
        std::string oldDestCut = str.substr(pos + 9);
        pos = oldDestCut.find("#");
        std::string oldDestBase64 = oldDestCut.substr(0, pos);

        if (!OldIdentity.FromBase64(oldDestBase64))
            return 0;

        signatureLen = OldIdentity.GetSignatureLen();
        signature.assign(signatureLen, 0);

        pos = str.find("#oldsig=");
        if (pos == std::string::npos)
            return 0;
        std::string hostNoOldSig = str.substr(0, pos);

        std::string oldSigCut = str.substr(pos + 8);
        pos = oldSigCut.find("#");
        std::string oldSig = oldSigCut.substr(0, pos);

        i2p::data::Base64ToByteStream(oldSig, signature.data(), signatureLen);
        (void)OldIdentity.Verify((uint8_t *)hostNoOldSig.c_str(), hostNoOldSig.length(), signature.data());
    }
    return 0;
}
