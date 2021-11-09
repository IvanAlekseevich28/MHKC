#include "mha.h"
#include <random>
#include <ctime>
#include <numeric>

using namespace MHA;

static NUM getPrimeMoreThan(const NUM& x);
static bool isPrime(const NUM& x);
static NUM invertByMod(NUM a, NUM m);


PrivateKey MHA::genPrivateKey()
{
    std::mt19937 gen;
    gen.seed(0);

    const auto dispersion = 4;
    PrivateKey privateKey;
    auto& range = privateKey.range;

    NUM rangeSum = 0;
    for (unsigned i = 0; i < NUMBITLEN; i++)
    {
        range[i] = rangeSum + 1 + (gen() % dispersion);
        rangeSum += range[i];
    }
    privateKey.q = getPrimeMoreThan(rangeSum);
    privateKey.r = gen() % privateKey.q;

    return privateKey;
}

PublicKey MHA::genPublicKey(PrivateKey& privateKey)
{
    PublicKey publicKey;

    for (unsigned i = 0; i < NUMBITLEN; i++)
        publicKey[i] = (privateKey.r * privateKey.range[i]) % privateKey.q;

    return publicKey;
}

NUM getPrimeMoreThan(const NUM& x)
{
    NUM prime = x+1 + x%2;
    while (!isPrime(prime))
        prime += 2;

    return prime;
}

bool isPrime(const NUM& x)
{
    if (x == 2) return true;
    for (NUM i = 3; i <= sqrt(x); i+=2)
        if (x % i == 0)
            return false;
    return true;
}

std::string MHA::encrypt(std::string mes, PublicKey pubkey)
{
    constexpr unsigned blockLen = NUMBITLEN / 8;
    constexpr unsigned exblockLen = blockLen * 2;
    while (mes.size() % blockLen)
        mes.push_back(0);
    const unsigned countBlocks = (mes.size() / blockLen) + (mes.size() % blockLen ? 1 : 0);

    std::string crp;
    NUM last = 0;
    for (unsigned nBlk = 0; nBlk< countBlocks; nBlk++)
    {
        NUM S = 0;
        for (unsigned nSubBlk = 0; nSubBlk < blockLen; nSubBlk++)
        {
            const unsigned strPos = nBlk * blockLen + nSubBlk;
            const char& m = mes[strPos];
            for (unsigned nBit = 0; nBit < 8 ; nBit++)
            {
                const unsigned curIndexKeyNum = nBit + (nSubBlk * 8);
                const bool curBit = ((m >> (7 - nBit)) % 2);
                S += pubkey[curIndexKeyNum] * curBit;
            }
        }
//        S ^= last;

        for (unsigned nSubBlk = 0; nSubBlk < exblockLen; nSubBlk++)
            crp.push_back((S >> ((exblockLen - 1 -nSubBlk) * 8)) % 0x100);

        last = S;
    }

    return crp;
}


std::string MHA::decrypt(const std::string& crt, const PrivateKey& privateKey)
{
    constexpr unsigned blockLen = NUMBITLEN / 8;
    constexpr unsigned exblockLen = blockLen * 2;
    const unsigned countBlocks = crt.size() / exblockLen;
    const auto& key = privateKey.range;
    const auto invR = invertByMod(privateKey.r, privateKey.q);

    std::string mes;
    NUM last = 0;
    for (unsigned nBlk = 0; nBlk< countBlocks; nBlk++)
    {
        NUM S = 0;
        for (unsigned nSubBlk = 0; nSubBlk < exblockLen; nSubBlk++)
        {
            const unsigned strPos = nBlk * exblockLen + nSubBlk;
            const NUM m = (unsigned char)crt[strPos];
            S += m << ((exblockLen - nSubBlk - 1) * 8);
        }
        NUM decrypted = 0;
        S = (S * invR) % privateKey.q;
        for (int i = key.size() - 1; i >= 0; i --)
            if (key[i] <= S)
            {
                S -= key[i];
                decrypted += 1 << (NUMBITLEN - 1 - i);
                if (S == 0)
                    break;
            }
//        decrypted ^= last;
        for (unsigned nSubBlk = 0; nSubBlk < blockLen; nSubBlk++)
            mes.push_back((decrypted >> (nSubBlk * 8)) % 0x100);

        last = decrypted;
    }
    return mes;
}

NUM invertByMod(NUM a, NUM m)
{
    if (a < 1 or m < 2)
            return -1;

        int32_t u1 = m;
        int32_t u2 = 0;
        int32_t v1 = a;
        int32_t v2 = 1;

        while (v1 != 0)
        {
            int32_t q = u1 / v1;
            int32_t t1 = u1 - q*v1;
            int32_t t2 = u2 - q*v2;
            u1 = v1;
            u2 = v2;
            v1 = t1;
            v2 = t2;
        }

        return u1 == 1 ? (u2 + m) % m : -1;
}

using namespace std;

ostream& operator<<(ostream& os, const PublicKey& k)
{
    os << k.size() << " ";
    for (unsigned i = 0; i < k.size(); i++)
        os << k[i] << " ";

    return os;
}

istream& operator>>(istream& is, PublicKey& k)
{
    unsigned len = 0;
    is >> len;
    for (unsigned i = 0; i < len; i++)
        is >> k[i];

    return is;
}

ostream& operator<<(ostream& os, const PrivateKey& k)
{
    os << k.range
       << k.q << " "
       << k.r;

    return os;
}

istream& operator>>(istream& is, PrivateKey& k)
{
    is >> k.range >> k.q >> k.r;

    return is;
}

