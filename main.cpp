#include <iostream>
#include <iomanip>
#include <bitset>
#include "mha.h"

using namespace MHA;
using namespace std;

int main()
{
    auto priKey = genPrivateKey();
    auto pubkey = genPublicKey(priKey);
    cout << "Private key: " << priKey << "\nPublic key:  " << pubkey << "\n\n";

    string mes = "H";
//    mes[0] = 0x18;

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
