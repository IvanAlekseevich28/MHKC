#include <iostream>
#include <bitset>
#include "mha.h"

using namespace MHA;
using namespace std;

int main()
{
    auto k = keygen();
    string mes = "Hello, World!";

    for (const auto& c : mes){
        cout << bitset<8>(c) << " ";
    }

    string crp = encrypt(mes, k.pubkey);
    cout << endl;
    for (const auto& c : crp){
        cout << bitset<8>(c) << " ";
    }

    cout << endl;
    string dcr = decrypt(crp, k);
    for (const auto& c : dcr){
        cout << bitset<8>(c) << " ";
    }
    cout << endl << dcr << endl;
    return 0;
}
