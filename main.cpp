#include <iostream>
#include "mha.h"

using namespace MHA;
using namespace std;

int main()
{
    auto k = keygen();
    cout << k << endl;
    return 0;
}
