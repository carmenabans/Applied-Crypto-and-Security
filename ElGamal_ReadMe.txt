## README 
## Carmen Abans


## Date: 3/25/2022

The algorithm gets a key size in bits and plaintext from the user. 
The algorithm will output the encrypted message and the decrypted message using ElGamal Public-Key  Encryption.

The following are the prototypes of the functions we used along with explanations to what each does:

def exponentiation(a, n, p):
This function is the Square-and-Multiply algorithm which computes modular exponentiations. a^n(mod p)

def fermatTest(n):
This function performs Fermat's Primality Test. The function will loop at most 3 times and generates a random number between 2 < random number < n-2. 
Then it computes a^n-1(mod n) using exponentiation(a, n, p). If the result is not 1 then the function returns False meaning that the number n is not prime, 
else True is returned meaning that the number n is prime.

def isPrime(n):
This function takes in the key size in bits that the user inputed to generate a random p along with a random alpha which was between 1 and p. 
Fermat's test is performed on both p and alpha and will keep looping until both numbers are prime.

def key_generation(n):
This function takes in the key size in bits that the user inputed to generate the public key and the private key. 
The prime numbers p and alpha are initialized with isPrime(n) then a is a random number that is between 1 and p-2.
The number alpha_a is computed with exponentiation(alpha, a, p). This function returns public keys (p, alpha, alpha_a) and private key(a).

def elGamal_Encryption(p, alpha, alpha_a, m):
This function encrypts the plaintext using the ElGamal algorithm
1. The parameters are: the public key (p, alpha, alpha_a) and the plaintext (m)
2. A random integer k between 1 and p-2 is generated
3. The number v is computed from exponentiation(alpha, k, p) 
4. The number delta is computed from exponentiation(m*exponentiation(alpha_a, k, p), 1, p)
5. Finally the ciphertext is returned which is (v, delta)

def elGamal_Decryption(v, delta, p, a):
This function decrypts the ciphertext using the ElGamal algorithm
1. The private key a is used to compute V with exponentiation(v, p-1-a, p)
2. The plaintext is then recovered from exponentiation(V*delta, 1, p)
3. The decrypted message is returned

How to run code:
After unzipping the folder and opening a Google colaboratory file. 
Open elGamal.py in Notepad or Notepad++ and copy and paste all the content in a cell within the Google Colaboratory file. 
Run the code and the program should work.
This is also where we developed the code.

If this doesn't work open a new project in PyCharm delete all content in the main.py file that will be generated. 
Copy and paste the content in elGamal.py and run the code.


What happens when the code runs:
1. Users will be asked to enter a key bit size.
2. Users will then be asked to enter a message they want to decrypt, this needs to be a number.
3. The program will print out the keys generated, the message, the encrypted message, and the decrypted message.
4. If the original message and the decrypted message is the same then a "It works! :)" will appear to show that the program is working correctly
