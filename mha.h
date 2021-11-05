#pragma once

#include <string>
#include <array>
#include <fstream>


namespace MHA
{
using NUM = unsigned int;
using EXNUM = unsigned long long;
constexpr unsigned NUMBITLEN = 16;

using PublicKey = std::array<NUM, NUMBITLEN>;
using PrivateRange = PublicKey;


struct PrivateKey
{
    PublicKey pubkey;

    PrivateRange range;
    NUM q;
    NUM r;
};

PrivateKey keygen();
std::string encrypt(std::string mes, const PublicKey& pubkey);
std::string decrypt(std::string crypted, const PrivateKey& privkey);
}

std::ostream& operator<<(std::ostream& os, const MHA::PublicKey& k);
std::istream& operator>>(std::istream& is, MHA::PublicKey& k);


std::ostream& operator<<(std::ostream& os, const MHA::PrivateKey& k);
std::istream& operator>>(std::istream& is, MHA::PrivateKey& k);

