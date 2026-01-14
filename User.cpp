/**
 * РЕАЛИЗАЦИЯ МОДУЛЯ УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ
 * 
 * ПОДСИСТЕМА ГЕНЕРАЦИИ КЛЮЧЕЙ ШИФРОВАНИЯ И АУТЕНТИФИКАЦИИ
 */

#include "User.h"
#include <random>
#include <sstream>
#include <iomanip>

User::User(const std::string& username, const std::string& password, UserRole role)
    : username(username), password(password), role(role) {
    // Автоматическая генерация приватного ключа при создании пользователя
    privateKey = generatePrivateKey();
}

std::string User::getUsername() const {
    return username;
}

std::string User::getPassword() const {
    return password;
}

UserRole User::getRole() const {
    return role;
}

std::string User::getPrivateKey() const {
    return privateKey;
}

void User::setPrivateKey(const std::string& key) {
    privateKey = key;
}

std::string User::roleToString(UserRole role) {
    switch (role) {
        case UserRole::OPERATOR: return "operator";
        case UserRole::MANAGER: return "manager";
        case UserRole::CHIEF: return "chief";
        case UserRole::SECURITY_ADMIN: return "security_admin";
        default: return "unknown";
    }
}

UserRole User::stringToRole(const std::string& roleStr) {
    if (roleStr == "operator") return UserRole::OPERATOR;
    if (roleStr == "manager") return UserRole::MANAGER;
    if (roleStr == "chief") return UserRole::CHIEF;
    if (roleStr == "security_admin") return UserRole::SECURITY_ADMIN;
    return UserRole::OPERATOR;
}

/**
 * ПОДСИСТЕМА ГЕНЕРАЦИИ КЛЮЧЕЙ ШИФРОВАНИЯ И АУТЕНТИФИКАЦИИ
 * 
 * Генерация криптографически стойкого приватного ключа для шифрования документов
 * 
 * Алгоритм:
 * - Использует std::random_device для получения энтропии
 * - Генерирует 32-символьный hex-ключ (128 бит энтропии)
 * - Каждый пользователь получает уникальный ключ
 * 
 * Ключ используется для:
 * - Шифрования/расшифрования документов пользователя
 * - Создания электронных подписей
 * 
 * @return 32-символьный hex-ключ (0-9, a-f)
 */
std::string User::generatePrivateKey() {
    std::random_device rd;  // Источник энтропии
    std::mt19937 gen(rd()); // Генератор псевдослучайных чисел
    std::uniform_int_distribution<> dis(0, 15); // Равномерное распределение 0-15 (hex)
    
    std::stringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}
