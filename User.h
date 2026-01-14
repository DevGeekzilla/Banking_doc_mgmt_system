/**
 * МОДУЛЬ УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ И КЛЮЧАМИ
 * 
 * ПОДСИСТЕМА ГЕНЕРАЦИИ КЛЮЧЕЙ ШИФРОВАНИЯ И АУТЕНТИФИКАЦИИ
 * 
 * Реализует:
 * - Хранение учетных данных пользователей (username, password)
 * - Ролевую модель доступа (OPERATOR, MANAGER, CHIEF, SECURITY_ADMIN)
 * - Генерацию и хранение приватных ключей для шифрования (generatePrivateKey)
 * - Управление ключами: каждый пользователь имеет уникальный 32-символьный hex-ключ
 */
#ifndef USER_H
#define USER_H

#include <string>

// Роли пользователей для разграничения доступа
enum class UserRole {
    OPERATOR,        // Оператор: создание и просмотр документов
    MANAGER,         // Менеджер: подписание документов
    CHIEF,           // Руководитель: утверждение/отклонение документов
    SECURITY_ADMIN   // Администратор безопасности: полный доступ + просмотр журнала аудита
};

class User {
private:
    std::string username;
    std::string password;
    UserRole role;
    std::string privateKey;

public:
    User(const std::string& username, const std::string& password, UserRole role);
    
    std::string getUsername() const;
    std::string getPassword() const;
    UserRole getRole() const;
    std::string getPrivateKey() const;
    
    void setPrivateKey(const std::string& key);
    
    static std::string roleToString(UserRole role);
    static UserRole stringToRole(const std::string& roleStr);
    
    // Генерация приватного ключа
    static std::string generatePrivateKey();
};

#endif // USER_H
