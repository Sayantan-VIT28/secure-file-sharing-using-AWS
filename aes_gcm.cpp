#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <string>
#include <filesystem>
#include <chrono>
#include <vector>
#include <map>

namespace fs = std::filesystem;

const int SALT_LEN = 16;
const int IV_LEN = 12;
const int TAG_LEN = 16;
const int BUFFER_SIZE = 1024;

void handleErrors(const std::string& context) {
    std::cerr << "Error in " << context << ": ";
    ERR_print_errors_fp(stderr);
}

void deriveKey(const std::string& password, unsigned char* salt, unsigned char* key) {
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_LEN, 10000, EVP_sha256(), 32, key) != 1) {
        handleErrors("PBKDF2 key derivation");
        exit(1);
    }
}

bool encryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    if (!fs::exists(inputFile)) {
        std::cerr << "Error: Input file does not exist: " << inputFile << std::endl;
        return false;
    }

    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);
    if (!in.is_open() || !out.is_open()) {
        std::cerr << "Error: Cannot open input/output file." << std::endl;
        return false;
    }

    unsigned char salt[SALT_LEN], iv[IV_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) {
        handleErrors("RAND_bytes");
        return false;
    }

    unsigned char key[32];
    deriveKey(password, salt, key);

    out.write((char*)salt, SALT_LEN);
    out.write((char*)iv, IV_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        handleErrors("EVP_EncryptInit_ex");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char inBuf[BUFFER_SIZE], outBuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inLen, outLen;
    while ((inLen = in.read((char*)inBuf, BUFFER_SIZE).gcount()) > 0) {
        if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, inLen) != 1) {
            handleErrors("EVP_EncryptUpdate");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write((char*)outBuf, outLen);
    }

    if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1) {
        handleErrors("EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write((char*)outBuf, outLen);

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        handleErrors("EVP_CTRL_GCM_GET_TAG");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    out.write((char*)tag, TAG_LEN);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    if (!fs::exists(inputFile)) {
        std::cerr << "Error: Input file does not exist: " << inputFile << std::endl;
        return false;
    }

    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);
    if (!in.is_open() || !out.is_open()) {
        std::cerr << "Error: Cannot open input/output file." << std::endl;
        return false;
    }

    unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN];

    // Read salt, IV, ciphertext, then tag at the end
    in.read((char*)salt, SALT_LEN);
    in.read((char*)iv, IV_LEN);
    if (!in || in.gcount() != IV_LEN) {
        std::cerr << "Error: Invalid encrypted file format." << std::endl;
        return false;
    }

    // Get file size to read ciphertext and tag
    in.seekg(0, std::ios::end);
    size_t fileSize = in.tellg();
    size_t headerSize = SALT_LEN + IV_LEN;
    size_t ciphertextSize = fileSize - headerSize - TAG_LEN;
    in.seekg(headerSize, std::ios::beg);

    unsigned char key[32];
    deriveKey(password, salt, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        handleErrors("EVP_DecryptInit_ex");
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    unsigned char inBuf[BUFFER_SIZE], outBuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inLen, outLen;

    // Read and decrypt ciphertext
    while (ciphertextSize > 0) {
        inLen = (ciphertextSize > BUFFER_SIZE) ? BUFFER_SIZE : ciphertextSize;
        in.read((char*)inBuf, inLen);
        if (in.gcount() != inLen) {
            std::cerr << "Error: Failed to read ciphertext." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, inLen) != 1) {
            handleErrors("EVP_DecryptUpdate");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        out.write((char*)outBuf, outLen);
        ciphertextSize -= inLen;
    }

    // Read tag
    in.read((char*)tag, TAG_LEN);
    if (!in || in.gcount() != TAG_LEN) {
        std::cerr << "Error: Failed to read tag." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        fs::remove(outputFile);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        handleErrors("EVP_CTRL_GCM_SET_TAG");
        EVP_CIPHER_CTX_free(ctx);
        fs::remove(outputFile);
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        std::cerr << "Error: Invalid password or corrupted file" << std::endl;
        fs::remove(outputFile);
        return false;
    }
    out.write((char*)outBuf, outLen);

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <password> <output_dir> <input_file1> [input_file2 ...]" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string password = argv[2];
    std::string outputDir = argv[3];

    if (!fs::exists(outputDir)) fs::create_directories(outputDir);

    bool decrypt = (mode == "decrypt");
    bool allSuccess = true;

    for (int i = 4; i < argc; ++i) {
        std::string inputFile = argv[i];
        std::string ext = fs::path(inputFile).extension().string();
        std::string outputFile = (fs::path(outputDir) / (fs::path(inputFile).stem().string() + (decrypt ? "_decrypted" : "_encrypted") + ext)).string();

        std::cout << (decrypt ? "Decrypting " : "Encrypting ") << inputFile << " -> " << outputFile << std::endl;

        bool success = decrypt ? decryptFile(inputFile, outputFile, password)
                               : encryptFile(inputFile, outputFile, password);

        if (!success) {
            std::cerr << (decrypt ? "Decryption" : "Encryption") << " failed for " << inputFile << std::endl;
            allSuccess = false;
        }
    }

    return allSuccess ? 0 : 1;
}