#include <iostream>
#include <bitset>
#include "mha.h"

using namespace MHA;
using namespace std;

int main()
{
    auto priKey = genPrivateKey();
    auto pubkey = genPublicKey(priKey);
    string mes = "Hello, World!";

    for (const auto& c : mes){
        cout << bitset<8>(c) << " ";
    }

    string crp = encrypt(mes, pubkey);
    cout << endl;
    for (const auto& c : crp){
        cout << bitset<8>(c) << " ";
    }

    cout << endl;
    string dcr = decrypt(crp, priKey);
    for (const auto& c : dcr){
        cout << bitset<8>(c) << " ";
    }
    cout << endl << dcr << endl;
    return 0;
}
