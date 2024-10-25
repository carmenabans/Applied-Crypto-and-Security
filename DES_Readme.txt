## Carmen Abans
## Ariful Islam

## Date: 2/19/2022
## Assignment 2

The algorithm gets a plaintext and a key from the user. The algorithm will output the encrypted message and the decrypted message using Data Encryption Standard (DES).

The mode of operations used is (EBC) which breaks the plaintext into 16-bit blocks and then each block is encrypted DES and finally added together to get the final message. The decrypted message is also broken into 16-bit blocks and then each block is decrypted and finally added together to get the original message.

The following are the prototypes of the functions we used along with explanations to what each does:

string hex2bin(string s);
In order to use DES the values need to be in a binary form.

string bin2hex(string s);
This function is used to display the results in a more readable format.

int bin2dec(string binary);
This function is used during S-substitution.

string dec2bin(int decimal);
This function returns value to binary to continue with the DES process.

string permute(string k, int* arr, int n);
Allows permutation to accrue throughput the DES process.

string shift_left(string pkey, int shifts);
Shifting left is a core part of the DES process.

void generateSubKeys(string key);
Allows the creation of an array of subkeys that are used in the DES process.

string XOR(string a, string b);
Allows XOR operations to occur.

string DES_encrypt(string plaintext, string key);
This function encrypts the plaintext inputted using DES.
Step 0. Convert hexadecimal to binary
-Subkeys are generated here as well
Step 1. Initial permutation
-for this step, we called IP_t which was defined globally
Step 2. Split into two parts of 32 bits
Step 3. Plaintext Expansion box from 32 to 48 using E_t which was defined globally
-subKey xor right_expanded (48 bits)
Step 4. S-box substitution
-We find the row and column indices to look up the substitution box table index
-Each around substitution occurs 8 times
-All  8 substitution box tables were defined globally (S[8][4][16])
Step 5. Permutation using P_t which was defined globally
Step 6. Function XOR Left part of the plaintext
Step 7. Swapp left and right (left(i+1) = right(i), R(i+1) = x2)

Step 8. Combine Left side and Right side
Step 9. Final permutation
Steps 3 to 7 are done 16 times.

void reverseArray(string arr[], int start, int end);
This function is a critical part of the decryption process.

string DES_decrypt(string plaintext, string key) 
Step 0. Convert hexadecimal to binary
-Subkeys are generated here as well
-After the subkeys have been made they are reversed
All other steps are the same as the DES_encrypt.

string EBC_encrypt(string plaintext, string key);
Step 1. Calculate the number of total blocks
Step 2. Divide plaintext into blocks
Step 3. Cipher the block using DES encryption
Step 4. Keep ciphertext of blocks together in a string
Steps 2 to 4 are done however many blocks there are.

string EBC_decrypt(string plaintext, string key)
Same steps as EBC_encrypt except for step 3
Step 3. Cipher the block using DES decryption

How to run code:
After unzipping the folder open and empty project in Visual Studio, go-to source files and right-click, select Add, and then select Existing Item. Find the unzipped folder and select main.cpp
After main.cpp has been added run the code and it should work.

If this doesn't work copy and paste on the following link to a web browser and run from there: https://replit.com/@abans/ECBDES-Assign2#main.cpp

This is also where we developed the code.


What happens when the code runs:
1. Users will be asked to enter a plaintext which size is a multiple of 16.
2. If the size of the plaintext is not a multiple of 16 then the user will be asked to enter again until it is. We did this because DES can only work if the plaintext message is 16-bits long so the ECB functions need to be able to create blocks that are each 16-bits long.
3. The user will be asked to enter a key that has to be the size of 16.
4. If the size of the key is not 16 then the user will be asked to enter the key again until the key is a size of 16. We did this because the key for DES needs to be 16 or else the function will not work properly.
5. The program will then display the ciphered message and deciphered message.
6. If the deciphered message matches with the original plaintext then the program will also display "ECB Works!!!!!" to show that the encryption and decryption of DES with ECB mode worked properly.