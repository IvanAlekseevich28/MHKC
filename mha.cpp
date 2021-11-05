#include "mha.h"
#include <random>
#include <ctime>
#include <numeric>
#include <map>

using namespace MHA;

static PrivateRange genPrivateRange();
static PrivateKey genPartPrivateKey(const PrivateRange& privRange);
static void genPublicKey(PrivateKey& privKey);
static EXNUM getPrimeMoreThan(const EXNUM& x);
static bool isPrime(const EXNUM& x);

MHA::PrivateKey MHA::keygen()
{
    auto privateKey = genPartPrivateKey(genPrivateRange());
    genPublicKey(privateKey);
    return privateKey;
}

PrivateRange genPrivateRange()
{
    const auto dispersion = 2;
    std::mt19937 gen;
    gen.seed(time(0));

    PrivateRange R;
    EXNUM rangeSum = 0;
    for (unsigned i = 0; i < NUMBITLEN; i++)
    {
        R[i] = rangeSum + 1 + (gen() % dispersion);
        rangeSum += R[i];
    }

    return R;
}

PrivateKey genPartPrivateKey(const PrivateRange& privRange)
{
    std::mt19937 gen;
    gen.seed(time(0));
    EXNUM rangeSum = std::accumulate(privRange.begin(), privRange.end(), 0);

    PrivateKey privateKey;
    privateKey.range = privRange;
    privateKey.q = getPrimeMoreThan(rangeSum);
    privateKey.r = gen() % privateKey.q;

    return privateKey;
}

static void genPublicKey(PrivateKey& privKey)
{
    for (unsigned i = 0; i < NUMBITLEN; i++)
        privKey.pubkey[i] = (privKey.r * privKey.range[i]) % privKey.q;
}

EXNUM getPrimeMoreThan(const EXNUM& x)
{
    std::mt19937 gen;
    gen.seed(time(0));

    EXNUM prime = x+1 + x%2;
    while (!isPrime(prime))
        prime += 2;

    return prime;

}

bool isPrime(const EXNUM& x)
{
    for (EXNUM i = 2; i<sqrt(x); i++)
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
            crp.push_back((S >> (nSubBlk * 8)) % 0x100);

        last = S;
    }

    return crp;
}


std::string MHA::decrypt(const std::string& crt, const PrivateKey &privkey)
{
    constexpr unsigned blockLen = NUMBITLEN / 8;
    const unsigned countBlocks = crt.size() / blockLen;
    std::map<NUM, unsigned> mapKey;
    for (unsigned i = 0; i < privkey.range.size(); i++)
        mapKey.insert(std::make_pair(privkey.range[i], i));

    std::string mes;
    NUM last = 0;
    for (unsigned nBlk = 0; nBlk< countBlocks; nBlk++)
    {
        NUM S = 0;
        for (unsigned nSubBlk = 0; nSubBlk < blockLen; nSubBlk++)
        {
            const unsigned strPos = nBlk * blockLen + nSubBlk;
            const char& m = crt[strPos];
            S += (NUM)m << (nSubBlk * 8);
        }
        NUM decrypted = 0;
        for (const auto& w : mapKey)
            if (w.first <= S)
            {
                S -= w.first;
                decrypted &= ~(1 << w.second);
                if (S == 0)
                    break;
            }

    }
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
    os << k.pubkey
       << k.range
       << k.q << " "
       << k.r;

    return os;
}

istream& operator>>(istream& is, PrivateKey& k)
{
    is >> k.pubkey >> k.range >> k.q >> k.r;

    return is;
}

