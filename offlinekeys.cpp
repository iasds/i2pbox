#include <iostream>
#include <charconv>
#include <cstdint>
#include <fstream>
#include <stdlib.h>
#include <inttypes.h>
#include "Crypto.h"
#include "Identity.h"
#include "Timestamp.h"
#include "common/key.hpp"
#include <openssl/crypto.h>
#include "common/secure_file.hpp"

int tool_offlinekeys(int argc, char *argv[])
{
	if (argc < 3)
	{
		std::cout << "Usage: offlinekeys <output file> <keys file> <signature type> <days>" << std::endl;
		return 1;
	}
	std::string fname(argv[2]);
	if (std::string(argv[1]) == fname) {
		std::cerr << "output file must be different from the input keys file" << std::endl;
		return 1;
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
		if (len == (size_t)-1 || len > 64*1024*1024) {
			std::cerr << "bad keys file size" << std::endl;
			return 3;
		}
		buff.resize(len);
		inf.read((char*)buff.data(), buff.size());
		if (!inf || static_cast<std::size_t>(inf.gcount()) != buff.size()) {
			std::cerr << "short read on keys file" << std::endl;
			OPENSSL_cleanse(buff.data(), buff.size());
			return 3;
		}
		const bool valid = keys.FromBuffer(buff.data(), buff.size());
		OPENSSL_cleanse(buff.data(), buff.size());
		if (!valid) {
			std::cerr << "bad keys file format" << std::endl;
			return 3;
		}
	}
	if (keys.IsOfflineSignature ()) {
		std::cerr << "input keys file is already an offline keys file, provide the master keys file" << std::endl;
		return 1;
	}

	i2p::data::SigningKeyType type = i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519; // EdDSA by default
	if (argc > 3)
	{
		std::string str(argv[3]);
		type = NameToSigType(str);
		if (SigTypeToName(type).find("unknown") != std::string::npos) { std::cerr << "Incorrect signature type" << std::endl; return -2; }
		if (type == i2p::data::SIGNING_KEY_TYPE_RSA_SHA256_2048 ||
		    type == i2p::data::SIGNING_KEY_TYPE_RSA_SHA384_3072 ||
		    type == i2p::data::SIGNING_KEY_TYPE_RSA_SHA512_4096 ||
		    type == i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519ph) {
			std::cerr << "Signature type " << SigTypeToName(type) << " is not supported for offline keys" << std::endl;
			return 1;
		}
	}

	uint32_t days = 365; // 1 year by default
	if (argc > 4) {
		const std::string_view input(argv[4]);
		const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), days);
		const uint32_t days_max = static_cast<uint32_t>((UINT32_MAX - static_cast<uint64_t>(i2p::util::GetSecondsSinceEpoch ())) / (24 * 60 * 60));
		if (error != std::errc{} || end != input.data() + input.size() || days == 0 || days > days_max) {
			std::cerr << "Days must be an integer between 1 and " << days_max << std::endl;
			return 4;
		}
	}
	const uint64_t expires64 = static_cast<uint64_t>(i2p::util::GetSecondsSinceEpoch ()) + static_cast<uint64_t>(days) * 24 * 60 * 60;
	if (expires64 > UINT32_MAX) {
		std::cerr << "Requested expiration is outside the supported range" << std::endl;
		return 4;
	}
	const uint32_t expires = static_cast<uint32_t>(expires64);

	auto offlineKeys = keys.CreateOfflineKeys (type, expires);
	if (!offlineKeys.IsOfflineSignature ()) {
		std::cerr << "Failed to create offline keys for signature type " << SigTypeToName(type) << std::endl;
		return 1;
	}
	{
		const size_t fullLen = offlineKeys.GetFullLen ();
		uint8_t * buf = new uint8_t[fullLen];
		size_t len = offlineKeys.ToBuffer (buf, fullLen);
		if (len == 0) {
			OPENSSL_cleanse (buf, fullLen);
			delete[] buf;
			std::cerr << "Failed to serialize offline keys" << std::endl;
			return 1;
		}
		const bool written = i2pbox::WritePrivateFile(argv[1], buf, len);
		OPENSSL_cleanse(buf, len);
		delete[] buf;
		if (!written) {
			std::cerr << "Can't create file " << argv[1] << std::endl;
			return 1;
		}
		std::cout << "Offline keys for destination " << offlineKeys.GetPublic ()->GetIdentHash ().ToBase32 () << " created" << std::endl
			<< "Signature type: " << SigTypeToName(type) << " (" << type << ")" << std::endl
			<< "Days: " << days << std::endl;
	}
	return 0;
}
