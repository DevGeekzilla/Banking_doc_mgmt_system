#include "User.h"
#include <random>
#include <sstream>
#include <iomanip>

User::User(const std::string& username, const std::string& password, UserRole role)
    : username(username), password(password), role(role) {
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

std::string User::generatePrivateKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}
