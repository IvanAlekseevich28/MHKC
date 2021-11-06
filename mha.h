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
using PrivateKey = PublicKey;


PrivateKey genPrivateKey();
PublicKey genPublicKey(PrivateKey& privateKey);

std::string encrypt(std::string mes, const PublicKey& pubkey);
std::string decrypt(const std::string &crt, const PrivateKey& key);
}


std::ostream& operator<<(std::ostream& os, const MHA::PublicKey& k);
std::istream& operator>>(std::istream& is, MHA::PublicKey& k);
