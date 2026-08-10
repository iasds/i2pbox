// Test helper: generate a valid router.info from a PrivateKeys file.
// Needed because i2pd 2.61 requires addresses, netId and router.version
// properties for a router.info to be considered reachable/parseable.
#include "Crypto.h"
#include "RouterInfo.h"
#include "Identity.h"
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <vector>

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		std::cerr << "usage: gen_router_info <router.keys> <out.router.info> [published-host]" << std::endl;
		return 1;
	}
	i2p::crypto::InitCrypto(false);
	i2p::data::PrivateKeys keys;
	std::ifstream fi(argv[1], std::ifstream::binary);
	if (!fi.is_open())
	{
		std::cerr << "cannot open " << argv[1] << std::endl;
		return 1;
	}
	fi.seekg(0, std::ios::end);
	size_t len = fi.tellg();
	fi.seekg(0, std::ios::beg);
	std::vector<uint8_t> k(len);
	fi.read((char*)k.data(), len);
	if (!keys.FromBuffer(k.data(), len))
	{
		std::cerr << "invalid key file " << argv[1] << std::endl;
		return 1;
	}
	i2p::data::LocalRouterInfo ri;
	ri.SetRouterIdentity(keys.GetPublic());
	uint8_t sk[32] = {}, iv[16] = {};
	if (argc > 3 && argv[3][0])
		ri.AddNTCP2Address(sk, iv, boost::asio::ip::make_address(argv[3]), 12345);
	else
		ri.AddNTCP2Address(sk, iv, 12345, i2p::data::RouterInfo::eNTCP2V4);
	ri.SetProperty("caps", "L");
	ri.SetProperty("netId", "2");
	ri.SetProperty("router.version", "9.68");
	ri.CreateBuffer(keys);
	ri.SetUnreachable(false);
	if (!ri.SaveToFile(argv[2]))
	{
		std::cerr << "failed to save " << argv[2] << std::endl;
		return 1;
	}
	return 0;
}
