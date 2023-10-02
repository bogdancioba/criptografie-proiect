#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <ctime>
#include <cmath>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <vector>

bool is_square_free(long long number) {
    for (long long i = 2; i <= sqrt(number); ++i) {
        if (number % (i * i) == 0) {
            return false;
        }
    }
    return true;
}


void register_user(const std::string& user);
BIGNUM* find_smallest_square_free_odd_multiple_of_7_greater_than_time();


void register_user(const std::string& user) {

    BIGNUM* bn_e = find_smallest_square_free_odd_multiple_of_7_greater_than_time();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing RSA key generation.\n";
        exit(1);
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0) {
        std::cerr << "Error setting RSA key length.\n";
        exit(1);
    }

    EVP_PKEY* evp_key_pair = NULL;
    if (EVP_PKEY_keygen(ctx, &evp_key_pair) <= 0) {
        std::cerr << "Error generating RSA keys.\n";
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);


    std::string private_key_filename = user + "-key.prv";
    std::string public_key_filename = user + "-key.pub";
    FILE* private_key_file = fopen(private_key_filename.c_str(), "w");
    FILE* public_key_file = fopen(public_key_filename.c_str(), "w");
    PEM_write_PrivateKey(private_key_file, evp_key_pair, NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(public_key_file, evp_key_pair);
    fclose(private_key_file);
    fclose(public_key_file);


    std::ofstream key_pubs("key-pubs.txt", std::ios::app);
    key_pubs << user << ": " << public_key_filename << "\n";
    key_pubs.close();

    std::ofstream params_file(user + "-params.txt");
    std::string dh_params = "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAt/oF+wiI7YRy0Q5VlL5jJrIq3W0e5Qg+0z4bLC4yq3wY1hCm1/q6\n"
        "SzM9hRkR6fPfl6DgoU6e1UwvfEaFPIs7s0s+2N9KZjNlT6UOu6UyjFk1TaNiEeOc\n"
        "1Qc9A+6hDa50QolQKNg/Cb4e3ljd4yH0CISGzwIDAQI=\n"
        "-----END DH PARAMETERS-----\n";
    params_file << dh_params;
    params_file.close();

    BN_free(bn_e);
}

BIGNUM* find_smallest_square_free_odd_multiple_of_7_greater_than_time() {
    long long current_time = static_cast<long long>(time(nullptr));
    long long number = ((current_time + 6) / 7) * 7 + 7;  

    while (true) {
        if (number % 2 != 0 && is_square_free(number)) {
            return BN_bin2bn(reinterpret_cast<const unsigned char*>(&number), sizeof(number), NULL);
        }
        number += 7;
    }
}


void create_email(const std::string& from, const std::string& to);
std::string encrypt_body(const std::string& plaintext, const std::string& symmetric_key, const std::string& nonce);


std::string generate_aes_key(int key_length) {
    std::string key;
    key.resize(key_length);
    RAND_bytes(reinterpret_cast<unsigned char*>(&key[0]), key_length);
    return key;
}

std::string generate_nonce(int nonce_length) {
    std::string nonce;
    nonce.resize(nonce_length);
    RAND_bytes(reinterpret_cast<unsigned char*>(&nonce[0]), nonce_length);
    return nonce;
}


std::string encrypt_body(const std::string& plaintext, const std::string& symmetric_key, const std::string& nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating cipher context.\n";
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "Error initializing encryption.\n";
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(symmetric_key.data()), reinterpret_cast<const unsigned char*>(nonce.data())) != 1) {
        std::cerr << "Error setting encryption key and nonce.\n";
        exit(1);
    }

    int outlen = 0;
    int plaintext_length = static_cast<int>(plaintext.length());
    std::string ciphertext;
    ciphertext.resize(plaintext_length + EVP_CIPHER_CTX_block_size(ctx));

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &outlen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext_length) != 1) {
        std::cerr << "Error encrypting plaintext.\n";
        exit(1);
    }

    int ciphertext_length = outlen;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[outlen]), &outlen) != 1) {
        std::cerr << "Error finishing encryption.\n";
        exit(1);
    }

    ciphertext_length += outlen;
    ciphertext.resize(ciphertext_length);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

void create_email(const std::string& from, const std::string& to, const std::string& subject, const std::string& body) {

    std::string public_key_filename;
    std::ifstream key_pubs("key-pubs.txt");
    std::string line;
    while (std::getline(key_pubs, line)) {
        if (line.substr(0, line.find(':')) == to) {
            public_key_filename = line.substr(line.find(' ') + 1);
            break;
        }
    }
    key_pubs.close();
    if (public_key_filename.empty()) {
        std::cerr << "Error: recipient not found.\n";
        exit(1);
    }

    FILE* public_key_file = fopen(public_key_filename.c_str(), "r");
    EVP_PKEY* public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);


    std::string symmetric_key = generate_aes_key(32);
    std::string nonce = generate_nonce(12);


    std::string encrypted_body = encrypt_body(body, symmetric_key, nonce);


    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Error initializing public key encryption.\n";
        exit(1);
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Error setting RSA padding.\n";
        exit(1);
    }

    size_t encrypted_key_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_key_len, reinterpret_cast<const unsigned char*>(symmetric_key.data()), symmetric_key.length()) <= 0) {
        std::cerr << "Error determining encrypted key length.\n";
        exit(1);
    }

    std::vector<unsigned char> encrypted_key(encrypted_key_len);
    if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &encrypted_key_len, reinterpret_cast<const unsigned char*>(symmetric_key.data()), symmetric_key.length()) <= 0) {
        std::cerr << "Error encrypting symmetric key.\n";
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);


    std::ofstream email_file(from + "_to_" + to + ".email");
    email_file << "From: " << from << "\n";
    email_file << "To: " << to << "\n";
    email_file << "Subject: " << subject << "\n";
    email_file << "Encrypted-Key: " << std::string(encrypted_key.begin(), encrypted_key.end()) << "\n";
    email_file << "Nonce: " << nonce << "\n";
    email_file << "Body: " << encrypted_body << "\n";
    email_file.close();
}

int main() {

    std::string plaintext = "Hello, this is an email body.";
    std::string key = generate_aes_key(32); 
    std::string nonce = generate_nonce(12); 
    std::string encrypted_body = encrypt_body(plaintext, key, nonce);

    std::string from = "Bogdan";
    std::string to = "Iulian";
    std::string subject = "Test Email";
    std::string body = "Hello, this is an email body.";

    create_email(from, to, subject, body);

    std::cout << "Encrypted body: " << encrypted_body << std::endl;

    return 0;
}
