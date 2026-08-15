#include <iostream>
#include <cstring>
#include <string>
#include "Crypto.h"
#include "tools.h"

struct Command {
    const char *name;
    const char *desc;
    const char *usage;  // one-line usage for -h/--help; nullptr if the command prints its own help
    int (*func)(int, char**);
    bool precompute;
};

static const Command commands[] = {
    {"vain",           "Generate vanity .b32.i2p address",                    nullptr,                              tool_vain,          true},
    {"keygen",         "Generate random I2P keys",                            "<output-file> [signature-type]",     tool_keygen,        false},
    {"keyinfo",        "Display info about a private key",                    "[-v] [-d] [-p] [-b] <privatekey.dat>", tool_keyinfo,     false},
    {"famtool",        "Router family: generate, sign, or verify",            nullptr,                              tool_famtool,       false},
    {"routerinfo",     "Display router info (hosts, ports, firewall rules)",  "[-6|-f|-p|-y] <routerinfo.dat>",     tool_routerinfo,    false},
    {"regaddr",        "Register an I2P address",                             "<filename> <address>",               tool_regaddr,       false},
    {"regaddr_3ld",    "Register a 3LD address (3-step process)",             "<step1|step2|step3> <args...>",      tool_regaddr_3ld,   false},
    {"i2pbase64",      "Encode/decode I2P Base64",                            "[-d] [filename]",                    tool_i2pbase64,     false},
    {"offlinekeys",    "Generate offline signing keys",                       "<output> <keys> <signature-type> <days>", tool_offlinekeys, false},
    {"b33address",     "Convert Base64 destination to b33 address",           "(reads base64 destination from stdin)", tool_b33address, false},
    {"regaddralias",   "Register an address alias",                           "<old-file> <new-file> <address>",    tool_regaddralias,  false},
    {"x25519",         "Generate X25519 key pair for encrypted LeaseSet",     nullptr,                              tool_x25519,        false},
    {"verifyhost",     "Verify host record signature",                        "'<host record>'",                    tool_verifyhost,    false},
    {"autoconf_i2pd",  "Interactive i2pd.conf generator",                     "(interactive; answers on stdin)",    tool_autoconf_i2pd, false},
    {nullptr, nullptr, nullptr, nullptr, false}
};

static void print_usage(std::ostream &out) {
    out << "i2pbox — unified I2P toolkit (based on PurpleI2P/i2pd-tools)\n\n"
        << "Usage: i2pbox <command> [args...]\n\n"
        << "Commands:\n";
    for (const Command *c = commands; c->name; ++c) {
        out << "  " << c->name;
        int pad = 16 - (int)strlen(c->name);
        for (int i = 0; i < pad; ++i) out << ' ';
        out << c->desc << '\n';
    }
    out << "\nExample: i2pbox keygen my-router.keys ED25519-SHA512\n";
    out << "         i2pbox keyinfo privatekey.dat\n";
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(std::cout);
        return 1;
    }

    std::string cmd(argv[1]);

    // Handle help flags at top level
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        print_usage(std::cout);
        return 0;
    }

    if (cmd == "--version" || cmd == "version" || cmd == "-v" || cmd == "-V") {
        std::cout << "i2pbox " << I2PBOX_VERSION << " (i2pd " << I2PD_VERSION << ")\n";
        return 0;
    }

    for (const Command *c = commands; c->name; ++c) {
        if (cmd == c->name) {
            // Commands without their own help handling print a usage line
            // for -h/--help here; commands that handle it themselves (vain,
            // famtool, x25519) keep their original behavior.
            if (c->usage) {
                for (int i = 2; i < argc; ++i) {
                    std::string arg(argv[i]);
                    if (arg == "-h" || arg == "--help") {
                        std::cout << "Usage: i2pbox " << c->name << ' ' << c->usage << '\n';
                        return 0;
                    }
                }
            }
            i2p::crypto::InitCrypto(c->precompute); // precomputed tables only needed by vain
            // Shift argv: i2pbox cmd args... → cmd args...
            int ret = c->func(argc - 1, argv + 1);
            i2p::crypto::TerminateCrypto();
            return ret;
        }
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage(std::cerr);
    return 1;
}
