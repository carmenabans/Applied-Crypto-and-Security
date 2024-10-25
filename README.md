# Applied Crypto and Security

## Introduction

This repository contains custom implementations of the Data Encryption Standard (DES) in C and the ElGamal encryption algorithm in Python, demonstrating core cryptographic principles without the use of external libraries. Additionally, it includes the Miller-Rabin primality test for probabilistic primality testing, which is essential for various cryptographic applications.

## Context

The focus of this coursework is to understand symmetric and asymmetric encryption techniques, analyzing their mechanisms and security implications. DES is a symmetric-key algorithm for the encryption of digital data, while ElGamal provides a method for public-key encryption.

## Cryptographic Concepts

- **Data Encryption Standard (DES)**: 
  DES is a symmetric-key algorithm used for the encryption of digital data. In symmetric encryption, the same key is used for both encryption and decryption. DES operates on blocks of data, dividing the input into fixed-size blocks (64 bits) and using a 56-bit key to perform multiple rounds of permutation and substitution to transform the plaintext into ciphertext. Despite being widely used in the past, DES is now considered insecure due to its short key length, making it susceptible to brute-force attacks.

- **ElGamal Encryption**: 
  ElGamal is an asymmetric encryption algorithm that provides a method for secure key exchange and data encryption. In this scheme, a user generates a public key, which can be shared freely, and a private key, which is kept secret. The security of ElGamal relies on the difficulty of solving discrete logarithm problems. The algorithm consists of three main steps: key generation, encryption, and decryption. ElGamal is widely used in cryptographic protocols, including secure messaging and digital signatures.

- **Miller-Rabin Primality Test**: 
  The Miller-Rabin test is a probabilistic algorithm used to determine whether a number is prime. It is particularly useful for cryptographic applications that require large prime numbers for key generation. Unlike deterministic tests, the Miller-Rabin test can quickly identify non-prime numbers and provides a probability of error that can be reduced by repeating the test multiple times. This property makes it efficient and effective for verifying the primality of large numbers used in cryptographic systems.



## Technologies

- **C**: Used for implementing the DES algorithm.
- **Python**: Used for implementing the ElGamal encryption algorithm and the Miller-Rabin test.


[![My Skills](https://skillicons.dev/icons?i=python,c)](https://skillicons.dev)
