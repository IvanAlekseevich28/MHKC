#pragma once

#include <string>
#include <array>
#include <fstream>


namespace MHA
{
using NUM = unsigned int;
using EXNUM = unsigned long long;
constexpr unsigned NUMBITLEN = 8;

using PublicKey = std::array<NUM, NUMBITLEN>;
using PrivateRange = PublicKey;
struct PrivateKey
{
    PrivateRange range;
    NUM q;
    NUM r;
};


PrivateKey genPrivateKey();
PublicKey genPublicKey(PrivateKey& privateKey);

std::string encrypt(std::string mes, PublicKey pubkey);
std::string decrypt(const std::string &crt, const PrivateKey& privateKey);
}


std::ostream& operator<<(std::ostream& os, const MHA::PublicKey& k);
std::istream& operator>>(std::istream& is, MHA::PublicKey& k);

std::ostream& operator<<(std::ostream& os, const MHA::PrivateKey& k);
std::istream& operator>>(std::istream& is, MHA::PrivateKey& k);
