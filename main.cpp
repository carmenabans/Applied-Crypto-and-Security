/*--------------------------------------------------------------*/
/*   Assignment 02 - Data Encryption Standard (DES) algorithm   */
/*   Class:          <Practical Aspects of Modern Cryptography> */
/*   Description:    <Encryption and Decription using DES>      */
/*                   <with EBC mode of operations>              */
/*   Authors:         <Carmen Abans, Ariful Islam>              */
/*   Date: <2/19/2022>                                          */
/*--------------------------------------------------------------*/
#include <iostream>
#include <string>
#include <cmath>
#include <unordered_map>
#include <stdio.h>
using namespace std;


/***************    Tables for keys     ***************/

int pc_1[56] = {  57, 49, 41, 33, 25, 17, 9,
				          1,  58, 50, 42, 34, 26, 18,
				          10, 2,  59, 51, 43, 35, 27,
				          19, 11, 3,  60, 52, 44, 36,
				          63, 55, 47, 39, 31, 23, 15,
				          7,  62, 54, 46, 38, 30, 22,
				          14, 6,  61, 53, 45, 37, 29,
				          21, 13, 5,  28, 20, 12, 4 };

int pc_2[48] = {  14, 17, 11, 24, 1,  5,
				          3,  28, 15, 6,  21, 10,
				          23, 19, 12, 4,  26, 8,
				          16, 7,  27, 20, 13, 2,
				          41, 52, 31, 37, 47, 55,
				          30, 40, 51, 45, 33, 48,
				          44, 49, 39, 56, 34, 53,
				          46, 42, 50, 36, 29, 32 };

// In rounds 1,2 9 and 16 we make a 1 bit shift and in the others is a 2 bit shift
int leftShift_table[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };


/***************    Tables for plaintext    ***************/

// Initial Permutation table
int IP_t[64] = {  58, 50, 42, 34, 26, 18, 10, 2,
				          60, 52, 44, 36, 28, 20, 12, 4,
				          62, 54, 46, 38, 30, 22, 14, 6,
				          64, 56, 48, 40, 32, 24, 16, 8,
				          57, 49, 41, 33, 25, 17, 9,  1,
				          59, 51, 43, 35, 27, 19, 11, 3,
				          61, 53, 45, 37, 29, 21, 13, 5,
				          63, 55, 47, 39, 31, 23, 15, 7 };

// Expansion Box Table (function)
int E_t[48] = { 32, 1, 2, 3, 4, 5, 4, 5,
					6, 7, 8, 9, 8, 9, 10, 11,
					12, 13, 12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21, 20, 21,
					22, 23, 24, 25, 24, 25, 26, 27,
					28, 29, 28, 29, 30, 31, 32, 1 };

// S-box Substitution Tables (function)
int S[8][4][16] = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
                        
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
 
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
                        
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
                        
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
                        
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
                        
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
                        
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

// Permutation Table (function)
int P_t[32] = { 16, 7,  20, 21,
				        29, 12, 28, 17,
				        1,  15, 23, 26,
				        5,  18, 31, 10,
				        2,  8 , 24, 14,
				        32, 27, 3,  9,
			          19, 13, 30, 6,
		            22, 11, 4,  25 };

// Final Permutation Table
int FP_t[64] = {  40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9,  49, 17, 57, 25  };


/***************    Base Conversions    ***************/

// The original plaintext will have to be in hexadecimal

string hex2bin(string s)
{
  // hexadecimal to binary conversion
  unordered_map<char, string> mp;
  mp['0'] = "0000";
  mp['1'] = "0001";
  mp['2'] = "0010";
  mp['3'] = "0011";
  mp['4'] = "0100";
  mp['5'] = "0101";
  mp['6'] = "0110";
  mp['7'] = "0111";
  mp['8'] = "1000";
  mp['9'] = "1001";
  mp['A'] = "1010";
  mp['B'] = "1011";
  mp['C'] = "1100";
  mp['D'] = "1101";
  mp['E'] = "1110";
  mp['F'] = "1111";
  string bin = "";
  for (int i = 0; i < s.size(); i++) 
  {
    bin += mp[s[i]];
  }
  return bin;
}


string bin2hex(string s)
{
  // binary to hexadecimal conversion
  unordered_map<string, string> mp;
  mp["0000"] = "0";
  mp["0001"] = "1";
  mp["0010"] = "2";
  mp["0011"] = "3";
  mp["0100"] = "4";
  mp["0101"] = "5";  
  mp["0110"] = "6";
  mp["0111"] = "7";
  mp["1000"] = "8";
  mp["1001"] = "9";
  mp["1010"] = "A";
  mp["1011"] = "B";
  mp["1100"] = "C";
  mp["1101"] = "D";
  mp["1110"] = "E";
  mp["1111"] = "F";
  string hex = "";
  for (int i = 0; i < s.length(); i += 4) 
  {
    string ch = "";
    ch += s[i];
    ch += s[i + 1];
    ch += s[i + 2];
    ch += s[i + 3];
    hex += mp[ch];
  }
  return hex;
}

// Used in S-box 
int bin2dec(string binary)
{
  int decimal = 0;
	int counter = 0;
	int size = binary.length();
	for(int i = size-1; i >= 0; i--)
	{
    if(binary[i] == '1')
    {
      decimal += pow(2, counter);
    }
    counter++;
	}
	return decimal;
}


string dec2bin(int decimal) // for S-box substitution
{
	string binary;
  while(decimal != 0) 
  {
    binary = (decimal % 2 == 0 ? "0" : "1") + binary; 
		decimal = decimal/2;
	}
	while(binary.length() < 4){
		binary = "0" + binary;
	}
    return binary;
}

/***************    Operations    ***************/

string permute(string k, int* arr, int n)
{
  string per = "";
  for (int i = 0; i < n; i++) 
  {
    per += k[arr[i] - 1];
  }
  return per;
}

string shift_left(string pkey, int shifts)
{
  string shifted = "";
  for (int i = 0; i < shifts; i++) 
  {
    for (int j = 1; j < 28; j++) 
    {
      shifted += pkey[j];
    }
    shifted += pkey[0];
    pkey = shifted;
    shifted = "";
  }
  return pkey;
    
}

string sub_Keys[16]; // array to hold subKeys

void generateSubKeys(string key)
{
  // Step 0. Convert hexadecimal to binary
  key = hex2bin(key);

  // Step 1. Key permutation compresion to 56 bit key from 64 bit using PC-1
  key = permute(key, pc_1, 56); 

  // Step 2. Split 56 key into 2 parts of 28 bits each
  string left = key.substr(0, 28);
  string right = key.substr(28, 28);

  // Step 3. Shift leftShift_table -> string with all keys (subKeys)
  for (int i = 0; i < 16; i++) 
  {
    // Shifting
    left = shift_left(left, leftShift_table[i]);
    right = shift_left(right, leftShift_table[i]);
 
    // Combining parts
    string combine = left + right;
 
    // Key permutation compresion from 56 bits (28+28) to 48 bits using using PC-2 table
    string subKey = permute(combine, pc_2, 48);
    sub_Keys[i] = subKey; // save key generated in array subkeys for later
  }

}

// Function to do xor between two strings
string XOR(string a, string b)
{
  string output = "";
  for (int i = 0; i < a.size(); i++) 
  {
    if (a[i] == b[i]) 
    {
      output += "0";
    }
    else 
    {
      output += "1";
    }
  }
    return output;
}

/***************    DES    ***************/

string DES_encrypt(string plaintext, string key) 
{
  // Step 0. Convert hexadecimal to binary 
  plaintext = hex2bin(plaintext);
  generateSubKeys(key);
  
  // Step 1. Initial permutation
  plaintext = permute(plaintext, IP_t, 64);

  // Step 2. Split in two parts of 32 bits
  string left = plaintext.substr(0, 32);
  string right = plaintext.substr(32, 32);
  
	for(int i=0; i<16; i++) // The plain text is encrypted 16 times
  { 
    string right_expanded = ""; 
    // Step 3. Plaintext Expansion box from 32 to 48 using E_t
    right_expanded = permute(right, E_t, 48);
    //cout << "Right_expanded " << " " << bin2hex(right_expanded) << endl;
    
    // subKey xor right_expanded (48 bits)
    string x = XOR(sub_Keys[i], right_expanded); 
    //cout << "XOR " << " " << bin2hex(x) << endl;
    
    // Step 4. S-box substitution
    string op = "";
    for(int i=0;i<8; i++)
    {
      // Finding row and column indices to lookup the substituition box table index
      string row1= x.substr(i*6,1) + x.substr(i*6 + 5,1);
      int row = bin2dec(row1);
      string col1 = x.substr(i*6 + 1,1) + x.substr(i*6 + 2,1) + x.substr(i*6 + 3,1) + x.substr(i*6 + 4,1);;
			int col = bin2dec(col1);
			int val = S[i][row][col];
			op += dec2bin(val);   
		} 

    // Step 5. Permutation using P_t
    op = permute(op, P_t, 32);
    
    // Step 6. Function XOR Left part of plaintext
    string x2 = XOR(op, left);

    // Step 7. Swapp left and right (left(i+1) = right(i), R(i+1) = x2)
    left = x2; 
		if(i < 15)
    { 
      string temp = right;
			right = x2;
			left = temp;
		}
  }

    // Step 8. Combine L and R
    string combine = left + right;

    // Step 9. Final permutation
    string ciphertext = bin2hex(permute(combine, FP_t, 64));

    return ciphertext;

}

void reverseArray(string arr[], int start, int end)
{
    if (start >= end)
    return;
     
    string temp = arr[start];
    arr[start] = arr[end];
    arr[end] = temp;
     
    // Recursive Function calling
    reverseArray(arr, start + 1, end - 1);
}    

string DES_decrypt(string plaintext, string key) 
{
  // Step 0. Convert hexadecimal to binary 
  plaintext = hex2bin(plaintext);
  generateSubKeys(key);
  reverseArray(sub_Keys, 0, 15);
  // Step 1. Initial permutation
  plaintext = permute(plaintext, IP_t, 64);

  // Step 2. Split in two parts of 32 bits
  string left = plaintext.substr(0, 32);
  string right = plaintext.substr(32, 32);
  
	for(int i=0; i<16; i++) // The plain text is encrypted 16 times
  { 
    string right_expanded = ""; 
    // Step 3. Plaintext Expansion box from 32 to 48 using E_t
    right_expanded = permute(right, E_t, 48);
    //cout << "Right_expanded " << " " << bin2hex(right_expanded) << endl;
    
    // subKey xor right_expanded (48 bits)
    string x = XOR(sub_Keys[i], right_expanded); 
    //cout << "XOR " << " " << bin2hex(x) << endl;
    
    // Step 4. S-box substitution
    string op = "";
    for(int i=0;i<8; i++)
    {
      // Finding row and column indices to lookup the substituition box table index
      string row1= x.substr(i*6,1) + x.substr(i*6 + 5,1);
      int row = bin2dec(row1);
      string col1 = x.substr(i*6 + 1,1) + x.substr(i*6 + 2,1) + x.substr(i*6 + 3,1) + x.substr(i*6 + 4,1);;
			int col = bin2dec(col1);
			int val = S[i][row][col];
			op += dec2bin(val);   
		} 

    // Step 5. Permutation using P_t
    op = permute(op, P_t, 32);
    
    // Step 6. Function XOR Left part of plaintext
    string x2 = XOR(op, left);

    // Step 7. Swapp left and right (left(i+1) = right(i), R(i+1) = x2)
    left = x2; 
		if(i < 15)
    { 
      string temp = right;
			right = x2;
			left = temp;
		}
  }

    // Step 8. Combine L and R
    string combine = left + right;

    // Step 9. Final permutation
    string ciphertext = bin2hex(permute(combine, FP_t, 64));

    return ciphertext;

}


/***************   ECB    ***************/

string EBC_encrypt(string plaintext, string key)
{
  string ecb_text;
  // Step 1. Calculate number of total blocks
  int size = plaintext.length();
  int n_blocks = size/16;

  int b=0;
  int e=16;
  for(int i=0;i<n_blocks; i++)
  {
    // Step 2. Divide plaintext into blocks
    string block = plaintext.substr(b, e);
    
    // Step 3. Cipher the block using DES encryption
    string cipher_block = DES_encrypt(block, key);
    
    // Step 4. Keep ciphertext of blocks together in a string
    ecb_text = ecb_text + cipher_block;

    b += 16;
    e = i+16;
  }
  return ecb_text;
}

string EBC_decrypt(string plaintext, string key)
{
  string ecb_text;
  
  // Step 1. Calculate number of total blocks
  int size = plaintext.length();

  int n_blocks = size/16;

  int b=0;
  int e=16;
  for(int i=0;i<n_blocks; i++)
  {
    // Step 2. Divide plaintext into blocks
    string block = plaintext.substr(b, e);

    // Step 3. Cipher the block using DES decryption
    string cipher_block = DES_decrypt(block, key);

    // Step 4. Keep ciphertext of blocks together in a string
    ecb_text = ecb_text + cipher_block;

    b += 16;
    e = i+16;
  }
  return ecb_text;
}


int main() 
{
  string plaintext, key, ciphertext, deciphertext;
  
  //Testing values
  //plaintext = "123456ABCD132536223456ABCD132536323456ABCD132536";
	//key = "AABB09182736CCDD";
  
  cout<<"Enter the plain text (in hexadecimal). It must have a number of characters multiple of 16: ";
	cin>>plaintext;
  int pt_size = plaintext.length();
  
  //Checks if plaintext size is appropriate
  while (pt_size%16 != 0)
  {
    cout<<pt_size%16<<endl;
    cout<<"Error length of string is not multiple of 16"<<endl;
    cout<<"Enter the plain text (in hexadecimal). It must have a number of characters multiple of 16: "<<endl;
	  cin>>plaintext;
    pt_size = plaintext.length();
  }

	cout<<"Enter key(in hexadecimal) Must be 16 characters long: ";
	cin>>key;
  int keysize = key.length();

  //Checks if key size is appropriate
  while (keysize!=16)
  {
    cout<<"Error length of string is not 16"<<endl;
    cout<<"Enter the key (in hexadecimal). It must have a number of characters equal to 16: "<<endl;
    cin>>key;
    keysize = key.length();
  }

  ciphertext = EBC_encrypt(plaintext, key);
  cout<<"EBC Ciphertext: "<<ciphertext<<endl;

  deciphertext = EBC_decrypt(ciphertext, key);
  cout<<"EBC Deciphertext: "<<deciphertext<<endl;

  //Checks if decipher worked correctly
  if (plaintext == deciphertext)
    cout<<"ECB Works!!!!! "<<endl;
}