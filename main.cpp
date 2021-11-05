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
    int c0 = 0, c1 = 0;
    for (const auto& c : crp){
        cout << bitset<8>(c) << endl;
    }
    return 0;
}
