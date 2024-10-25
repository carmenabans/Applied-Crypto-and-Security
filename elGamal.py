# Computations: Square and multiply algorithm
def exponentiation(a, n, p):
    # Initialize result
    res = 1
    # Update 'a' if 'a' >= p
    a = a % p
    while n > 0:
        # If n is odd: multiply 'a' with result
        if n % 2:
            res = (res * a) % p
            n = n - 1
        else:
            a = (a ** 2) % p
            # n must be even now
            n = n // 2
    return res % p

# Generating primes
def fermatTest(n):
    k = 3
    # Try k times
    for i in range(k):
        # Pick a random number in [2..n-2]
        a = random.randint(2, n - 2)

        # Fermat's little theorem
        if exponentiation(a, n - 1, n) != 1:
            return False
    return True


    ###########################################          Key generation          ###########################################
import random

def isPrime(n):
    # initalization
    p = random.getrandbits(n)
    alpha = random.randint(1, p)
    while fermatTest(p) == False:
        p = random.getrandbits(n)
    while fermatTest(alpha) == False:
        alpha = random.randint(1, p)
    return p, alpha

def key_generation(n):
    p, alpha = isPrime(n)                   # generator
    a = random.randint(1, p-2)              # private key
    alpha_a = exponentiation(alpha, a, p)
    return p, alpha, alpha_a, a
    #public keys (p, alpha, alpha_a), private key(a)


###########################################            Encryption            ###########################################

def elGamal_Encryption(p, alpha, alpha_a, m):
    k = random.randint(1, p-2) # random number
    v = exponentiation(alpha, k, p)
    delta = exponentiation(m*exponentiation(alpha_a, k, p), 1, p)
    return v, delta


###########################################            Decryption            ###########################################

def elGamal_Decryption(v, delta, p, a):
    V = exponentiation(v, p-1-a, p)
    m = exponentiation(V*delta, 1, p)
    return m

###########################################            Driver Code           ###########################################
n = int(input('Choose key size (in bits): '))
msg = int(input('What is your message?(in a number): '))
p, alpha, alpha_a, a = key_generation(n)
v, delta = elGamal_Encryption(p, alpha, alpha_a, msg)
de_msg = elGamal_Decryption(v, delta, p, a)

print('key generation: p =', p, ', alpha =', alpha, ', alpha^a =', alpha_a, ', a =',a)
print('The message is:', msg)
print('The encrypted message:', v, delta)
print('The decrypted message is:', de_msg)
if msg == de_msg:
    print('It works! :)')
else:
    print('Something went wrong')