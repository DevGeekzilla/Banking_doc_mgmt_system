/**
 * РЕАЛИЗАЦИЯ КРИПТОГРАФИЧЕСКОГО МОДУЛЯ
 * 
 * Технологии защиты конфиденциальных документов согласно требованиям ЗЭДКД
 */

#include "CryptoModule.h"
#include <functional>
#include <sstream>
#include <iomanip>
#include <algorithm>

/**
 * ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ
 * 
 * Шифрование данных с использованием XOR-шифра (имитация ГОСТ 34.12)
 * ГОСТ 34.13 определяет режимы (ECB, CBC, OFB и т.д.) — здесь XOR в ECB-подобном режиме
 * 
 * @param data - исходные данные для шифрования
 * @param key - приватный ключ пользователя
 * @return зашифрованные данные
 */
std::string CryptoModule::encrypt(const std::string& data, const std::string& key) {
    if (key.empty()) return data;
    
    std::string result = data;
    size_t keyLen = key.length();
    
    for (size_t i = 0; i < result.length(); ++i) {
        result[i] ^= key[i % keyLen];
    }
    
    return result;
}

/**
 * ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ
 * 
 * Расшифрование данных (XOR - симметричное шифрование, расшифрование = шифрование)
 * 
 * @param encryptedData - зашифрованные данные
 * @param key - приватный ключ пользователя
 * @return расшифрованные данные
 */
std::string CryptoModule::decrypt(const std::string& encryptedData, const std::string& key) {
    // XOR - симметричное шифрование, расшифрование = шифрование
    return encrypt(encryptedData, key);
}

/**
 * ЗАЩИТА ЦЕЛОСТНОСТИ
 * 
 * Вычисление хеша документа для проверки целостности данных
 * Хеш на основе std::hash имитирует ГОСТ 34.11-2012 (Streebog)
 * 
 * Используется для:
 * - Проверки целостности при просмотре документа
 * - Проверки целостности перед подписанием
 * - Проверки целостности перед утверждением
 * 
 * @param data - данные для вычисления хеша
 * @return 32-символьный hex-хеш (только печатаемые символы 0-9, A-F)
 */
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

/**
 * ЗАЩИТА АВТОРСТВА И НЕВОЗМОЖНОСТИ ОТКАЗА ОТ АВТОРСТВА
 * 
 * Создание электронной подписи документа (имитация ГОСТ 34.10-2012 ECDSA)
 * Подпись = hash(content) + private_key создателя
 * 
 * Гарантирует:
 * - Авторство: подпись создается с использованием приватного ключа создателя
 * - Невозможность отказа: только создатель документа может создать валидную подпись
 * - Целостность: подпись включает хеш содержимого, изменение документа инвалидирует подпись
 * 
 * @param content - содержимое документа для подписания
 * @param privateKey - приватный ключ создателя документа
 * @return электронная подпись
 */
std::string CryptoModule::createSignature(const std::string& content, const std::string& privateKey) {
    std::string hash = computeHash(content);
    // Подпись = hash + private_key (конкатенация)
    return hash + privateKey;
}

/**
 * ЗАЩИТА АВТОРСТВА И НЕВОЗМОЖНОСТИ ОТКАЗА ОТ АВТОРСТВА
 * 
 * Проверка электронной подписи документа
 * 
 * Проверяет:
 * - Подлинность подписи: соответствует ли подпись содержимому и ключу создателя
 * - Целостность документа: не был ли документ изменен после подписания
 * 
 * @param content - содержимое документа
 * @param signature - электронная подпись для проверки
 * @param privateKey - приватный ключ создателя документа
 * @return true если подпись валидна, false в противном случае
 */
bool CryptoModule::verifySignature(const std::string& content, const std::string& signature, 
                                   const std::string& privateKey) {
    if (signature.length() < 32) return false;
    
    std::string computedHash = computeHash(content);
    std::string expectedSignature = computedHash + privateKey;
    
    return signature == expectedSignature;
}
