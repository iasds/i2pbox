/**
 * famtool - a tool for creating and verifying router families
 */
#include <algorithm>
#include <cassert>
#include <cctype>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include "Crypto.h"
#include "RouterInfo.h"
#include "Base.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include "common/secure_file.hpp"

using namespace i2p::crypto;
using namespace i2p::data;

static void usage(const std::string & name)
{
	std::cout << "usage: " << name << " [-h] [-v] [-g -n family -c family.crt -k family.pem [-P password] [-e days]] [-s -n family -k family.pem [-P password] -i router.keys -f router.info] [-V -c family.crt -f router.info]" << std::endl;
}

static void printhelp(const std::string & name)
{
	usage(name);
	std::cout << std::endl;
	std::cout << "generate a new family signing key for family called ``i2pfam''" << std::endl;
	std::cout << name << " -g -n i2pfam -c myfam.crt -k myfam.pem" << std::endl;
	std::cout << name << " -g -n i2pfam -c myfam.crt -k myfam.pem -P secret -e 3650" << std::endl << std::endl;
	std::cout << "sign a router info with family signing key (add -P if the key is encrypted)" << std::endl;
	std::cout << name << " -s -n i2pfam -k myfam.pem -i router.keys -f router.info" << std::endl;
	std::cout << name << " -s -n i2pfam -k myfam.pem -P secret -i router.keys -f router.info" << std::endl << std::endl;
	std::cout << "verify signed router.info" << std::endl;
	std::cout << name << " -V -n i2pfam -c myfam.pem -f router.info" << std::endl << std::endl;
	std::cout << "options:" << std::endl;
	std::cout << "  -P password  encrypt/decrypt the family private key (AES-256-CBC)." << std::endl;
	std::cout << "               Without -P the key is written unencrypted (legacy format)." << std::endl;
	std::cout << "               Note: the password is visible in the process list." << std::endl;
	std::cout << "  -e days      certificate validity in days (default 3650 = 10 years)." << std::endl;
}

static std::shared_ptr<Verifier> LoadCertificate (const std::string& filename)
{
	BIO * bio = BIO_new_file(filename.c_str(), "r");
	if (!bio) return nullptr;
	X509 * cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!cert) return nullptr;
	std::shared_ptr<Verifier> verifier;
	EVP_PKEY * pkey = X509_get_pubkey(cert);
	if (pkey)
	{
		// Family certs are P-256 EC keys; extract raw x||y via modern EVP_PKEY BN params.
		BIGNUM * x = nullptr, * y = nullptr;
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) && EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y))
		{
			// Verify it's P-256 by checking the group name when available.
			char groupName[64] = {0};
			size_t glen = 0;
			bool isP256 = true;
			if (EVP_PKEY_get_group_name(pkey, groupName, sizeof(groupName), &glen) == 1)
				isP256 = (std::string(groupName) == "prime256v1" || std::string(groupName) == "P-256");
			if (isP256)
			{
				uint8_t signingKey[64];
				bn2buf(x, signingKey, 32);
				bn2buf(y, signingKey + 32, 32);
				verifier = std::make_shared<i2p::crypto::ECDSAP256Verifier>();
				verifier->SetPublicKey(signingKey);
			}
		}
		if (x) BN_free(x);
		if (y) BN_free(y);
		EVP_PKEY_free(pkey);
	}
	X509_free(cert);
	return verifier;
}

// Password callback for PEM_read_bio_ECPrivateKey. OpenSSL's default callback
// prompts on the terminal, which would hang non-interactive runs; supply the
// password programmatically or fail immediately.
static int PasswordCb (char * buf, int size, int /*rwflag*/, void * u)
{
	if (u) {
		const std::string * pw = static_cast<const std::string *>(u);
		if (pw->size () < static_cast<size_t>(size)) {
			memcpy (buf, pw->c_str (), pw->size ());
			return static_cast<int>(pw->size ());
		}
	}
	return 0;
}

static int NoPasswordCb (char * /*buf*/, int /*size*/, int /*rwflag*/, void * /*u*/)
{
	return 0; // never prompt; fail cleanly instead
}

static bool CreateFamilySignature (const std::string& family, const IdentHash& ident,
	const std::string & filename, const std::string & password, std::string & sig)
{
	BIO * bio = BIO_new_file (filename.c_str (), "r");
	if (!bio)
		return false;
	EC_KEY * ecKey;
	if (password.empty ()) {
		// Encrypted keys fail immediately instead of prompting on the tty.
		ecKey = PEM_read_bio_ECPrivateKey (bio, nullptr, NoPasswordCb, nullptr);
	} else {
		ecKey = PEM_read_bio_ECPrivateKey (bio, nullptr, PasswordCb, (void *)&password);
	}
	BIO_free (bio);
	bool ok = false;
	if (ecKey)
	{
		auto group = EC_KEY_get0_group (ecKey);
		if (group)
		{
			int curve = EC_GROUP_get_curve_name (group);
			if (curve == NID_X9_62_prime256v1)
			{
				uint8_t signingPrivateKey[32], buf[50], signature[64];
				bn2buf (EC_KEY_get0_private_key (ecKey), signingPrivateKey, 32);
				ECDSAP256Signer signer (signingPrivateKey);
				size_t len = family.length ();
				memcpy (buf, family.c_str (), len);
				memcpy (buf + len, (const uint8_t *)ident, 32);
				len += 32;
				signer.Sign (buf, len, signature);
				sig = ByteStreamToBase64 (signature, 64);
				ok = true;
				OPENSSL_cleanse (signingPrivateKey, 32);
			}
		}
		EC_KEY_free (ecKey);
	}
	return ok;
}

static bool ParseValidityDays (const char * s, long & days)
{
	if (!s || !*s)
		return false;
	for (const char * p = s; *p; ++p)
		if (!std::isdigit (static_cast<unsigned char>(*p)))
			return false;
	char * end = nullptr;
	long v = strtol (s, &end, 10);
	if (end && *end)
		return false;
	if (v <= 0 || v > 36500) // at most 100 years
		return false;
	days = v;
	return true;
}

int tool_famtool(int argc, char *argv[])
{
	if (argc == 1) {
		usage(argv[0]);
		return 1;
	}
	int opt;
	bool verbose = false;
	bool help = false;
	bool gen = false;
	bool sign = false;
	bool verify = false;
	std::string fam;
	std::string privkey;
	std::string certfile;
	std::string infile;
	std::string infofile;
	std::string outfile;
	std::string password;
	long days = 3650; // default: 10 years (legacy hardcoded value)
	while((opt = getopt(argc, argv, "vVhgsn:i:c:k:o:f:P:e:")) != -1) {
		switch(opt) {
		case 'v':
			verbose = true;
			break;
		case 'h':
			help = true;
			break;
		case 'P':
			password = std::string(argv[optind-1]);
			break;
		case 'e':
			if (!ParseValidityDays(argv[optind-1], days)) {
				std::cerr << "invalid validity days (must be 1..36500)" << std::endl;
				return 1;
			}
			break;
		case 'g':
			gen = true;
			break;
		case 'n':
			fam = std::string(argv[optind-1]);
			// family names are case-insensitive in the I2P network; normalize to lower
			std::transform(fam.begin(), fam.end(), fam.begin(), ::tolower);
			if (fam.size() + 32 > 50) {
				std::cerr << "family name too long" << std::endl;
				return 1;
			}
			break;
		case 'f':
			infofile = std::string(argv[optind-1]);
			break;
		case 'i':
			infile = std::string(argv[optind-1]);
			break;
		case 'o':
			outfile = std::string(argv[optind-1]);
			break;
		case 'c':
			certfile = std::string(argv[optind-1]);
			break;
		case 'k':
			privkey = std::string(argv[optind-1]);
			break;
		case 'V':
			verify = true;
			break;
		case 's':
			sign = true;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if(help) {
		printhelp(argv[0]);
		return 0;
	}

	if(!fam.size()) {
		// no family name
		std::cerr << "no family name specified" << std::endl;
		return 1;
	}
	// generate family key code
	if(gen) {
		if(!privkey.size()) privkey = fam + ".key";
		if(!certfile.size()) certfile = fam + ".crt";

		// never silently clobber an existing family key or certificate
		// (mirrors keygen's overwrite protection)
		if (i2pbox::FileExists(privkey)) {
			std::cerr << "private key " << privkey << " already exists (refusing to overwrite)" << std::endl;
			return 1;
		}
		if (i2pbox::FileExists(certfile)) {
			std::cerr << "certificate " << certfile << " already exists (refusing to overwrite)" << std::endl;
			return 1;
		}

		std::string cn = fam + ".family.i2p.net";


		const int privfd = i2pbox::OpenPrivateFile(privkey);
		FILE * privf = privfd < 0 ? nullptr : fdopen(privfd, "w");
		if(!privf) {
			if (privfd >= 0) close(privfd);
			fprintf(stderr, "cannot open %s: %s\n", privkey.c_str(), strerror(errno));
			return 1;
		}

		int certflags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef O_CLOEXEC
		certflags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
		certflags |= O_NOFOLLOW;
#endif
		int certfd = open(certfile.c_str(), certflags, 0644);
		FILE * certf = certfd < 0 ? nullptr : fdopen(certfd, "w");
		if(!certf) {
			if (certfd >= 0) close(certfd);
			if (privf) fclose(privf);
			unlink(privkey.c_str());
			fprintf(stderr, "cannot open %s: %s\n", certfile.c_str(), strerror(errno));
			return 1;
		}

		// openssl fagmastery starts here

		EC_KEY * k_priv = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		assert(k_priv);
		EC_KEY_set_asn1_flag(k_priv, OPENSSL_EC_NAMED_CURVE);
		EC_KEY_generate_key(k_priv);
		if(verbose) std::cout << "generated key" << std::endl;
		// -P encrypts the private key (AES-256-CBC); without it the legacy
		// unencrypted PEM format is written for backward compatibility.
		PEM_write_ECPrivateKey(privf, k_priv,
			password.empty () ? nullptr : EVP_aes_256_cbc (),
			password.empty () ? nullptr : (const unsigned char *)password.c_str (),
			(int)password.size (), nullptr, nullptr);
		fclose(privf);
		if(verbose) std::cout << "wrote private key" << std::endl;


		EVP_PKEY * ev_k = EVP_PKEY_new();
		assert(ev_k);
		assert(EVP_PKEY_assign_EC_KEY(ev_k, k_priv) == 1);

		X509 * x = X509_new();
		assert(x);

		X509_set_version(x, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x), 0);
		X509_gmtime_adj(X509_get_notBefore(x),0);
		X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days); // -e, default 10 years

		X509_set_pubkey(x, ev_k);

		X509_NAME * name = X509_get_subject_name(x);
		X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (unsigned char *) "XX", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"ST", MBSTRING_ASC, (unsigned char *) "XX", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (unsigned char *) "XX", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, (unsigned char *) "I2P Anonymous Network", -1, -1, 0);

		X509_NAME_add_entry_by_txt(name,"OU", MBSTRING_ASC, (unsigned char *) "family", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (unsigned char *) cn.c_str(), -1, -1, 0);
		X509_set_issuer_name(x,name);

		if(verbose) std::cout << "signing cert" << std::endl;
		assert(X509_sign(x, ev_k, EVP_sha256()));
		if(verbose) std::cout << "writing private key" << std::endl;
		PEM_write_X509(certf,	x);

		fclose(certf);

		EVP_PKEY_free(ev_k);
		X509_free(x);
		std::cout << "family " << fam << " made" << std::endl;
	}

	if (sign) {
		// sign
		if (!infile.size()) {
			// no router info specified
			std::cerr << "no router keys file specified" << std::endl;
			return 1;
		}
		if (!privkey.size()) {
			// no private key specified
			std::cerr << "no private key specified" << std::endl;
			return 1;
		}

		{
			std::ifstream i;
			i.open(infofile);
			if(!i.is_open()) {
				std::cerr << "cannot open " << infofile << std::endl;
				return 1;
			}
		}

		if (verbose) std::cout << "load " << infofile << std::endl;



		PrivateKeys keys;
		{
			std::ifstream fi(infile, std::ifstream::in | std::ifstream::binary);
			if(!fi.is_open()) {
				std::cerr << "cannot open " << infile << std::endl;
				return 1;
			}
			fi.seekg (0, std::ios::end);
			size_t len = fi.tellg();
			fi.seekg (0, std::ios::beg);
			if (len == (size_t)-1 || len > 64*1024*1024) {
				std::cerr << "invalid key file " << infile << std::endl;
				return 1;
			}
			uint8_t * k = new uint8_t[len];
			fi.read((char*)k, len);
			if(!keys.FromBuffer(k, len)) {
				std::cerr << "invalid key file " << infile << std::endl;
				return 1;
			}
			OPENSSL_cleanse(k, len);
			delete [] k;
		}

        RouterInfo routerInfo(infofile);
		if (routerInfo.IsUnreachable()) {
			std::cerr << "invalid router info " << infofile << std::endl;
			return 1;
		}
		LocalRouterInfo ri;
        ri.SetRouterIdentity (routerInfo.GetRouterIdentity ());
        ri.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());        

		auto ident = ri.GetIdentHash();


		if (verbose) std::cout << "add " << ident.ToBase64() << " to " << fam << std::endl;
		std::string sig;
		if(CreateFamilySignature(fam, ident, privkey, password, sig)) {
			ri.SetProperty(ROUTER_INFO_PROPERTY_FAMILY, fam);
			ri.SetProperty(ROUTER_INFO_PROPERTY_FAMILY_SIG, sig);
			if (verbose) std::cout << "signed " << sig << std::endl;
			ri.CreateBuffer(keys);
			if(!ri.SaveToFile(infofile)) {
				std::cerr << "failed to save to " << infofile << std::endl;
				return 1;
			}
			std::cout << "signed" << std::endl;
		} else {
			std::cerr << "failed to sign router info" << std::endl;
			return 1;
		}
	}

	if(verify) {
		if(!infofile.size()) {
			std::cerr << "no router info file specified" << std::endl;
			return 1;
		}
		if(!certfile.size()) {
			std::cerr << "no family certificate specified" << std::endl;
			return 1;
		}
		auto v = LoadCertificate(certfile);
		if(!v) {
			std::cerr << "invalid certificate" << std::endl;
			return 1;
		}

		{
			std::ifstream i;
			i.open(infofile);
			if(!i.is_open()) {
				std::cerr << "cannot open " << infofile << std::endl;
				return 1;
			}
		}

		if (verbose) std::cout << "load " << infofile << std::endl;

        RouterInfo routerInfo(infofile);
		if (routerInfo.IsUnreachable()) {
			std::cerr << "invalid router info " << infofile << std::endl;
			return 1;
		}
		LocalRouterInfo ri;
        ri.SetRouterIdentity (routerInfo.GetRouterIdentity ());
        ri.Update (routerInfo.GetBuffer (), routerInfo.GetBufferLen ());
		auto sig = ri.GetProperty(ROUTER_INFO_PROPERTY_FAMILY_SIG);
		std::string famLower = fam;
		std::transform(famLower.begin(), famLower.end(), famLower.begin(), ::tolower);
		std::string propFamily = ri.GetProperty(ROUTER_INFO_PROPERTY_FAMILY);
		std::transform(propFamily.begin(), propFamily.end(), propFamily.begin(), ::tolower);
		if (propFamily != famLower) {
			std::cerr << infofile << " does not belong to " << fam << std::endl;
			return 1;
		}
		auto ident = ri.GetIdentHash();

		uint8_t buf[50], sigbuf[64];
		size_t len = fam.length();
		memcpy(buf, fam.c_str(), len);
		memcpy(buf + len, (const uint8_t *) ident, 32);
		len += 32;
		Base64ToByteStream(sig, sigbuf, 64);
		if (!v->Verify(buf, len, sigbuf)) {
			std::cerr << "invalid signature" << std::endl;
			return 1;
		}
		std::cout << "verified" << std::endl;
	}
	return 0;
}
