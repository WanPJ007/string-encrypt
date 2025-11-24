#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <Windows.h>

// --- OpenSSL Headers ---
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

// 定义 AES-256 的密钥和 IV (请在实际生产环境中替换为随机生成的安全密钥)
// 密钥 (32 字节 / 256 位)
const unsigned char AES_KEYS[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0xa3, 0x1c, 0x6e, 0x01, 0x7c, 0x88, 0xd0, 0x93, 0x99, 0x8c, 0xdf, 0x23, 0x54, 0x75, 0xf5, 0x98
};
// 初始化向量 IV (16 字节 / 128 位)
const unsigned char AES_IV[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

char* base64_encode(const char* data, int data_len)
{
    //int data_len = strlen(data);   
    const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    int prepare = 0;
    int ret_len;
    int temp = 0;
    char* ret = NULL;
    char* f = NULL;
    int tmp = 0;
    char changed[4];
    int i = 0;
    ret_len = data_len / 3;
    temp = data_len % 3;
    if (temp > 0)
    {
        ret_len += 1;
    }
    ret_len = ret_len * 4 + 1;
    ret = (char*)malloc(ret_len);

    if (ret == NULL)
    {
        exit(0);
    }
    memset(ret, 0, ret_len);
    f = ret;
    while (tmp < data_len)
    {
        temp = 0;
        prepare = 0;
        memset(changed, '\0', 4);
        while (temp < 3)
        {
            //printf("tmp = %d\n", tmp);   
            if (tmp >= data_len)
            {
                break;
            }
            prepare = ((prepare << 8) | (data[tmp] & 0xFF));
            tmp++;
            temp++;
        }
        prepare = (prepare << ((3 - temp) * 8));
        //printf("before for : temp = %d, prepare = %d\n", temp, prepare);   
        for (i = 0; i < 4; i++)
        {
            if (temp < i)
            {
                changed[i] = 0x40;
            }
            else
            {
                changed[i] = (prepare >> ((3 - i) * 6)) & 0x3F;
            }
            *f = base[changed[i]];
            //printf("%.2X", changed[i]);   
            f++;
        }
    }
    *f = '\0';

    return ret;

}


std::vector<unsigned char> base64_decode(const char* data, int data_len) {
    const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    // 查找表，用于快速将 Base64 字符映射回 0-63 的值
    unsigned char table[256];
    for (int i = 0; i < 256; i++) table[i] = 0x80; // 初始化为无效值
    for (int i = 0; i < 64; i++) table[(unsigned char)base[i]] = i;

    // 估算解码后的最大长度: 编码长度的 3/4
    int est_len = data_len * 3 / 4;
    std::vector<unsigned char> decoded_bytes;
    decoded_bytes.reserve(est_len);

    int prepare = 0;
    int count = 0;
    int i = 0;

    while (i < data_len) {
        unsigned char c = (unsigned char)data[i];
        i++;

        // 忽略换行符、空格等
        if (c == '\n' || c == '\r' || c == ' ') continue;

        // 如果遇到填充符 '='，则停止或调整循环
        if (c == '=') break;

        // 查找字符对应的 6-bit 值
        if (table[c] == 0x80) {
            // 遇到无效 Base64 字符
            std::cerr << "Error: Invalid character in Base64 string." << std::endl;
            return {}; // 返回空 vector
        }

        prepare = (prepare << 6) | table[c];
        count++;

        if (count == 4) {
            // 4个Base64字符解码成3个字节
            decoded_bytes.push_back((unsigned char)((prepare >> 16) & 0xFF));
            decoded_bytes.push_back((unsigned char)((prepare >> 8) & 0xFF));
            decoded_bytes.push_back((unsigned char)(prepare & 0xFF));
            prepare = 0;
            count = 0;
        }
    }

    // 处理剩余部分
    if (count == 2) {
        // 剩余 2 个字符 (3个字节的1/3) -> 产生 1个字节
        decoded_bytes.push_back((unsigned char)(prepare >> 4) & 0xFF);
    }
    else if (count == 3) {
        // 剩余 3 个字符 (3个字节的2/3) -> 产生 2个字节
        decoded_bytes.push_back((unsigned char)((prepare >> 10) & 0xFF));
        decoded_bytes.push_back((unsigned char)((prepare >> 2) & 0xFF));
    }

    return decoded_bytes;
}

/**
 * @brief AES-256-CBC 加密函数。
 * @param plaintext 要加密的原始字符串。
 * @param encrypted [out] 加密后的字节数据 (包括 IV, 密文, 可能的 HMAC/TAG)。
 * @return 成功返回 true，否则返回 false。
 */
bool aes_encrypt(const std::string& plaintext, std::vector<unsigned char>& encrypted) {
    EVP_CIPHER_CTX* ctx = NULL;
    int len;
    int ciphertext_len;

    // 确保 OpenSSL 库已初始化 (通常在程序启动时只需调用一次)
    OpenSSL_add_all_algorithms();

    // 1. 创建和初始化上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 2. 初始化加密操作 (使用 AES 256 CBC)
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEYS, AES_IV)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 预留空间: 密文长度最大为 (明文长度 + 块大小 - 1)
    size_t required_size = plaintext.length() + AES_BLOCK_SIZE;
    encrypted.resize(required_size);

    // 3. 加密数据主体
    if (1 != EVP_EncryptUpdate(ctx, encrypted.data(), &len,
        (const unsigned char*)plaintext.c_str(), plaintext.length())) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    // 4. 完成加密 (处理任何剩余数据和填充)
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    // 调整 vector 大小到实际密文长度
    encrypted.resize(ciphertext_len);

    // 5. 清理
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

/**
 * @brief AES-256-CBC 解密函数。
 * @param encrypted 密文的字节数据。
 * @param decrypted [out] 解密后的明文字符串。
 * @return 成功返回 true，否则返回 false。
 */
bool aes_decrypt(const std::vector<unsigned char>& encrypted, std::string& decrypted) {
    EVP_CIPHER_CTX* ctx = NULL;
    int len;
    int plaintext_len;

    // 1. 创建和初始化上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 2. 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEYS, AES_IV)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 预留空间: 明文长度不会超过密文长度
    std::vector<unsigned char> decrypted_buffer(encrypted.size());

    // 3. 解密数据主体
    if (1 != EVP_DecryptUpdate(ctx, decrypted_buffer.data(), &len,
        encrypted.data(), encrypted.size())) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // 4. 完成解密 (移除填充)
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_buffer.data() + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    // 5. 转换为 std::string
    decrypted.assign((char*)decrypted_buffer.data(), plaintext_len);

    // 6. 清理
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// --- 调用示例 ---
int main() {
    // 您要加密的 JSON 字符串
    std::string plaintext_json = "shit";

    std::vector<unsigned char> encrypted_data;
    std::string decrypted_json;

    std::cout << "Original Data: " << plaintext_json.length() << " bytes." << std::endl;

    // 1. 加密
    if (aes_encrypt(plaintext_json, encrypted_data)) {
        std::cout << "Encryption Successful. Ciphertext Size: " << encrypted_data.size() << " bytes." << std::endl;

        // 注意: 密文是原始字节，通常需要 Base64 编码后才能存储或传输。
         std::string encoded_ciphertext = base64_encode(reinterpret_cast<const char*>(encrypted_data.data()), static_cast<int>(encrypted_data.size()));
         std::cout << "Base64 Encoded Ciphertext: " << encoded_ciphertext << std::endl;


        // 2. 解密
         std::vector<unsigned char> decoded_ciphertext = base64_decode(
             encoded_ciphertext.c_str(),
             static_cast<int>(encoded_ciphertext.length())
         ); // 还原为密文字节 (3)

        if (aes_decrypt(decoded_ciphertext, decrypted_json)) {
            std::cout << "\nDecryption Successful." << std::endl;
            std::cout << "Decrypted Data: " << decrypted_json << std::endl;

            // 3. 验证
            if (decrypted_json == plaintext_json) {
                std::cout << "Verification: Data integrity check passed." << std::endl;
            }
            else {
                std::cout << "Verification: WARNING - Data mismatch." << std::endl;
            }
        }
        else {
            std::cerr << "\nDecryption Failed." << std::endl;
        }
    }
    else {
        std::cerr << "\nEncryption Failed." << std::endl;
    }

    return 0;
}