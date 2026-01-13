#include "CryptoModule.h"
#include <functional>
#include <sstream>
#include <iomanip>
#include <algorithm>

std::string CryptoModule::encrypt(const std::string& data, const std::string& key) {
    if (key.empty()) return data;
    
    std::string result = data;
    size_t keyLen = key.length();
    
    for (size_t i = 0; i < result.length(); ++i) {
        result[i] ^= key[i % keyLen];
    }
    
    return result;
}

std::string CryptoModule::decrypt(const std::string& encryptedData, const std::string& key) {
    // XOR - симметричное шифрование, расшифрование = шифрование
    return encrypt(encryptedData, key);
}

std::string CryptoModule::computeHash(const std::string& data) {
    // Упрощенный хеш на основе std::hash и дополнительных преобразований
    std::hash<std::string> hasher;
    size_t hashValue = hasher(data);
    
    // Дополнительные преобразования для имитации MD5-like
    std::stringstream ss;
    ss << std::hex << hashValue;
    std::string hashStr = ss.str();
    
    // Дополняем до 32 символов
    while (hashStr.length() < 32) {
        hashStr = "0" + hashStr;
    }
    if (hashStr.length() > 32) {
        hashStr = hashStr.substr(0, 32);
    }
    
    // Дополнительное перемешивание
    for (size_t i = 0; i < data.length() && i < 32; ++i) {
        hashStr[i] = ((hashStr[i] + data[i]) % 256);
    }
    
    return hashStr;
}

std::string CryptoModule::createSignature(const std::string& content, const std::string& privateKey) {
    std::string hash = computeHash(content);
    // Подпись = hash + private_key (конкатенация)
    return hash + privateKey;
}

bool CryptoModule::verifySignature(const std::string& content, const std::string& signature, 
                                   const std::string& privateKey) {
    if (signature.length() < 32) return false;
    
    std::string computedHash = computeHash(content);
    std::string expectedSignature = computedHash + privateKey;
    
    return signature == expectedSignature;
}
