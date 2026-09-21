#include "Identity.h"
#include "I2PEndian.h"
#include "LeaseSet.h"
#include "Base.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include "common/key.hpp"
#include "common/b33_offline.hpp"
#include <openssl/crypto.h>

static int printHelp(const char * exe, int exitcode)
{
	std::cout << "usage: " << exe << " [-v] [-d] [-p] [-b] privatekey.dat" << std::endl;
	return exitcode;
}

std::string ConvertTime (time_t t)
{
	struct tm *tm = localtime(&t);
	char date[128];
	snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
	return date;
}

int tool_keyinfo(int argc, char *argv[])
{
	if(argc == 1) {
		return printHelp(argv[0], 1);
	}

	int opt;
	bool print_dest = false;
	bool print_private = false;
	bool print_blinded = false;
	bool verbose = false;
	while((opt = getopt(argc, argv, "hvdpb")) != -1) {
		switch(opt){
		case 'h':
			return printHelp(argv[0], 0);
		case 'v':
			verbose = true;
			break;
		case 'd':
			print_dest = true;
			break;
		case 'p':
			print_private = true;
			break;
		case 'b':
			print_blinded = true;
			break;
		default:
			return printHelp(argv[0], 1);
		}
	}

	if (optind >= argc) return printHelp(argv[0], 1);
	std::string fname(argv[optind]);
	i2p::data::PrivateKeys keys;
	std::ifstream s(fname, std::ifstream::binary);

	if (!s.is_open()) {
		std::cerr << "cannot open private key file " << fname << std::endl;
		return 2;
	}

	s.seekg(0, std::ios::end);
	size_t len = static_cast<std::size_t>(s.tellg());
	s.seekg(0, std::ios::beg);
	if (len == (size_t)-1 || len > 64*1024*1024) {
		std::cerr << "bad key file size" << std::endl;
		return 3;
	}
	uint8_t * buf = new uint8_t[len];
	s.read((char*)buf, len);
	if (!s || static_cast<std::size_t>(s.gcount()) != len) {
		std::cerr << "short read on private key file " << fname << std::endl;
		OPENSSL_cleanse(buf, len);
		delete[] buf;
		return 3;
	}

	const std::size_t onlineLen = keys.FromBuffer(buf, len);
	if (!onlineLen) {
		std::cerr << "bad key file format" << std::endl;
		OPENSSL_cleanse(buf, len);
		delete[] buf;
		return 3;
	}

	auto dest = keys.GetPublic();
	if(!dest) {
		std::cerr << "failed to extract public key" << std::endl;
		OPENSSL_cleanse(buf, len);
		delete[] buf;
		return 3;
	}

	const auto & ident = dest->GetIdentHash();
	// b33offlinekeys appends a batch of per-day keys after the online keys,
	// which is where FromBuffer stopped. Parse it once for -p and -b.
	uint16_t batchDays = 0;
	std::string batchFirst, batchLast;
	const bool hasBatch = onlineLen < len && i2pbox::DescribeB33OfflineBatch(
	    buf + onlineLen, len - onlineLen, ident, batchDays, batchFirst, batchLast);
	if (verbose) {
		std::cout << "Destination: " << dest->ToBase64() << std::endl;
		std::cout << "Destination Hash: " << ident.ToBase64() << std::endl;
		std::cout << "B32 Address: " << ident.ToBase32() << ".b32.i2p" << std::endl;
		std::cout << "Signature Type: " << SigTypeToName(dest->GetSigningKeyType()) << std::endl;
		std::cout << "Encryption Type: " << (int) dest->GetCryptoKeyType() << std::endl;
		if (keys.IsOfflineSignature ())
		{
			std::cout << "Offline signature" << std::endl;
			const auto& offlineSignature = keys.GetOfflineSignature ();
			std::cout << "Expires: " << ConvertTime (bufbe32toh(offlineSignature.data ())) << std::endl;
			std::cout << "Transient Signature Type: " << SigTypeToName(bufbe16toh(offlineSignature.data () + 4)) << std::endl;
		}
	} else {
		if(print_private) {
			if (hasBatch)
			{
				// upstream's libi2pd parses the batch and re-emits it inside
				// ToBuffer, so its -p round trips the whole file. Serialize the
				// online keys and append the batch to match that byte for byte.
				std::vector<uint8_t> whole(len);
				const std::size_t online = keys.ToBuffer(whole.data(), onlineLen);
				if (online == onlineLen)
				{
					std::memcpy(whole.data() + onlineLen, buf + onlineLen, len - onlineLen);
					std::cout << i2p::data::ByteStreamToBase64(whole.data(), whole.size()) << std::endl;
				}
				else
					std::cout << keys.ToBase64() << std::endl;
			}
			else
				std::cout << keys.ToBase64() << std::endl;
		} else if(print_dest) {
			std::cout << dest->ToBase64() << std::endl;
		} else {
			std::cout << ident.ToBase32() << ".b32.i2p" << std::endl;
		}
	}

	if (print_blinded) {
		if (dest->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 ||
		    dest->GetSigningKeyType () == i2p::data::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 ) // 11 or 7
		{
			i2p::data::BlindedPublicKey blindedKey (dest);
			std::cout << "b33 address: " << blindedKey.ToB33 () << ".b32.i2p" << std::endl;
			std::cout << "Today's store hash: " << blindedKey.GetStoreHash ().ToBase64 () << std::endl;
			if (hasBatch)
				std::cout << "b33 offline keys: " << batchDays << " days, "
				    << batchFirst << " to " << batchLast << std::endl;
		}
		else {
			std::cerr << "Invalid signature type " << SigTypeToName (dest->GetSigningKeyType ()) << std::endl;
			OPENSSL_cleanse(buf, len);
			delete[] buf;
			return 1;
		}
	}

	OPENSSL_cleanse(buf, len);
	delete[] buf;
	return 0;
}
