#include <iostream>
#include "sha256.h"
using namespace std;

int main()
{
    string input = "";
    cout << "Please enter text: ";
    cin >> input;
    string output1 = sha256(input);

    cout << "SHA-256 output is: " << output1 << endl;
    return 0;
}

