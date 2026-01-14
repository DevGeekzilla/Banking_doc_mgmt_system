#include "CryptoModule.h"
#include <functional>
#include <sstream>
#include <iomanip>
#include <algorithm>

// XOR-шифр имитирует ГОСТ 34.12 (симметричное блочное шифрование)
// ГОСТ 34.13 определяет режимы (ECB, CBC, OFB и т.д.) — здесь XOR в ECB-подобном режиме
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

// Хеш на основе std::hash имитирует ГОСТ 34.11-2012 (Streebog)
std::string CryptoModule::computeHash(const std::string& data) {
    // Упрощенный хеш на основе std::hash и дополнительных преобразований
    std::hash<std::string> hasher;
    size_t hashValue = hasher(data);
    
    // Дополнительные преобразования для имитации MD5-like
    std::stringstream ss;
    ss << std::hex << std::uppercase << hashValue;
    std::string hashStr = ss.str();
    
    // Дополняем до 32 символов нулями слева
    while (hashStr.length() < 32) {
        hashStr = "0" + hashStr;
    }
    if (hashStr.length() > 32) {
        hashStr = hashStr.substr(0, 32);
    }
    
    // Дополнительное перемешивание с использованием только печатаемых символов
    // Используем XOR и модуль для получения только hex-символов (0-9, A-F)
    for (size_t i = 0; i < data.length() && i < 32; ++i) {
        unsigned char hashChar = hashStr[i];
        unsigned char dataChar = static_cast<unsigned char>(data[i]);
        unsigned char mixed = (hashChar ^ dataChar) % 16;
        // Преобразуем в hex-символ (0-9, A-F)
        if (mixed < 10) {
            hashStr[i] = '0' + mixed;
        } else {
            hashStr[i] = 'A' + (mixed - 10);
        }
    }
    
    return hashStr;
}

// Подпись hash + key имитирует ГОСТ 34.10-2012 (ECDSA)
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
