#ifndef USER_H
#define USER_H

#include <string>

enum class UserRole {
    OPERATOR,
    MANAGER,
    CHIEF,
    SECURITY_ADMIN
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
