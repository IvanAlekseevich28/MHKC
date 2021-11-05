#include <iostream>
#include <bitset>
#include "mha.h"

using namespace MHA;
using namespace std;

int main()
{
    auto k = keygen();
    string mes = "Hello, World!";
    string crp = encrypt(mes, k.pubkey);
    for (const auto& c : crp){
        cout << bitset<8>(c) << " ";
    }
    string dcr = decrypt(crp, k);
    cout << endl << dcr << endl;
    return 0;
}
