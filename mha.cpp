#include "mha.h"
#include <random>
#include <ctime>
#include <numeric>

using namespace MHA;

static NUM getPrimeMoreThan(const NUM& x);
static bool isPrime(const NUM& x);
static NUM gen();


PrivateKey MHA::genPrivateKey()
{
    const auto dispersion = 4;
    PrivateKey privateKey;

    NUM rangeSum = 0;
    for (unsigned i = 0; i < NUMBITLEN; i++)
    {
        privateKey[i] = rangeSum + 1 + (gen() % dispersion);
        rangeSum += privateKey[i];
    }

    return privateKey;
}

PublicKey MHA::genPublicKey(PrivateKey& privateKey)
{
    PublicKey publicKey;
    NUM rangeSum = std::accumulate(privateKey.begin(), privateKey.end(), 0);
    NUM q = getPrimeMoreThan(rangeSum);
    NUM r = gen() % q;

    for (unsigned i = 0; i < NUMBITLEN; i++)
        publicKey[i] = (r * privateKey[i]) % q;

    r = q = 0;
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
    for (NUM i = 2; i<sqrt(x); i++)
        if (x % i == 0)
            return false;
    return true;
}

std::string MHA::encrypt(std::string mes, const PublicKey &pubkey)
{
    constexpr unsigned blockLen = NUMBITLEN / 8;
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
                S += pubkey[nBit + (nSubBlk * 8)] * ((m >> nBit) % 2);
        }
        S ^= last;

        for (unsigned nSubBlk = 0; nSubBlk < blockLen; nSubBlk++)
            crp.push_back((S >> ((blockLen - 1 -nSubBlk) * 8)) % 0x100);

        last = S;
    }

    return crp;
}


std::string MHA::decrypt(const std::string& crt, const PrivateKey& key)
{
    constexpr unsigned blockLen = NUMBITLEN / 8;
    const unsigned countBlocks = crt.size() / blockLen;

    std::string mes;
    NUM last = 0;
    for (unsigned nBlk = 0; nBlk< countBlocks; nBlk++)
    {
        NUM S = 0;
        for (unsigned nSubBlk = 0; nSubBlk < blockLen; nSubBlk++)
        {
            const unsigned strPos = nBlk * blockLen + nSubBlk;
            const NUM m = crt[strPos];
            S += m << ((blockLen - nSubBlk - 1) * 8);
        }
        NUM decrypted = 0;
        for (int i = key.size() - 1; i >= 0; i --)
            if (key[i] <= S)
            {
                S -= key[i];
                decrypted += 1 << i;
                if (S == 0)
                    break;
            }
        decrypted ^= last;
        for (unsigned nSubBlk = 0; nSubBlk < blockLen; nSubBlk++)
            mes.push_back((decrypted >> (nSubBlk * 8)) % 0x100);

        last = decrypted;
    }
    return mes;
}

static NUM gen()
{
    std::mt19937 generator;
    generator.seed(time(0));

    return generator();
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
