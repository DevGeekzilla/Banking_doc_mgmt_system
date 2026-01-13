#ifndef CRYPTO_MODULE_H
#define CRYPTO_MODULE_H

#include <string>

class CryptoModule {
public:
    // Шифрование XOR (имитация ГОСТ 34.12)
    static std::string encrypt(const std::string& data, const std::string& key);
    
    // Расшифрование XOR
    static std::string decrypt(const std::string& encryptedData, const std::string& key);
    
    // Вычисление хеша (упрощенный MD5-like)
    static std::string computeHash(const std::string& data);
    
    // Создание электронной подписи (имитация ГОСТ 34.10)
    // Подпись = hash(content) + private_key
    static std::string createSignature(const std::string& content, const std::string& privateKey);
    
    // Проверка электронной подписи
    static bool verifySignature(const std::string& content, const std::string& signature, 
                                const std::string& privateKey);
};

#endif // CRYPTO_MODULE_H
