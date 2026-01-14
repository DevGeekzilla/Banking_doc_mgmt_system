/**
 * КРИПТОГРАФИЧЕСКИЙ МОДУЛЬ (CryptoModule)
 * 
 * Комплекс программ, реализующих технологии защиты конфиденциальных документов:
 * 
 * 1. ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ:
 *    - encrypt() / decrypt() - симметричное шифрование XOR (имитация ГОСТ 34.12)
 *    - Документы хранятся в зашифрованном виде, доступны только авторизованным пользователям
 * 
 * 2. ЗАЩИТА ЦЕЛОСТНОСТИ:
 *    - computeHash() - вычисление хеша документа (имитация ГОСТ 34.11-2012 Streebog)
 *    - Проверка целостности при просмотре, подписании и утверждении документов
 * 
 * 3. ОБЕСПЕЧЕНИЕ АУТЕНТИФИКАЦИИ:
 *    - Интегрировано с системой аутентификации пользователей (Menu::authenticate)
 *    - Каждый пользователь имеет уникальный приватный ключ для шифрования
 * 
 * 4. ЗАЩИТА АВТОРСТВА И НЕВОЗМОЖНОСТИ ОТКАЗА ОТ АВТОРСТВА:
 *    - createSignature() / verifySignature() - электронная подпись (имитация ГОСТ 34.10-2012 ECDSA)
 *    - Подпись = hash(content) + private_key создателя документа
 *    - Невозможность подделки: подпись создается с использованием приватного ключа создателя
 */
#ifndef CRYPTO_MODULE_H
#define CRYPTO_MODULE_H

#include <string>

class CryptoModule {
public:
    // Шифрование XOR (имитация ГОСТ 34.12) - ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ
    static std::string encrypt(const std::string& data, const std::string& key);
    
    // Расшифрование XOR - ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ
    static std::string decrypt(const std::string& encryptedData, const std::string& key);
    
    // Вычисление хеша (упрощенный MD5-like, имитация ГОСТ 34.11-2012) - ЗАЩИТА ЦЕЛОСТНОСТИ
    static std::string computeHash(const std::string& data);
    
    // Создание электронной подписи (имитация ГОСТ 34.10-2012) - ЗАЩИТА АВТОРСТВА
    // Подпись = hash(content) + private_key
    static std::string createSignature(const std::string& content, const std::string& privateKey);
    
    // Проверка электронной подписи - ЗАЩИТА АВТОРСТВА И НЕВОЗМОЖНОСТИ ОТКАЗА
    static bool verifySignature(const std::string& content, const std::string& signature, 
                                const std::string& privateKey);
};

#endif // CRYPTO_MODULE_H
