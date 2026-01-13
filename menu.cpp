#include "menu.h"
#include "CryptoModule.h"
#include "Audit.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <limits>
#include <algorithm>
#include <cstdio>

Menu::Menu() : currentUser(nullptr), nextDocumentId(1) {
    initializeUsers();
    loadUsers();
    loadDocuments();
}

Menu::~Menu() {
    saveDocuments();
    saveUsers();
}

void Menu::initializeUsers() {
    // Хардкод пользователей
    users.clear();
    users.push_back(User("operator1", "pass123", UserRole::OPERATOR));
    users.push_back(User("manager1", "pass123", UserRole::MANAGER));
    users.push_back(User("chief1", "pass123", UserRole::CHIEF));
    users.push_back(User("security_admin1", "pass123", UserRole::SECURITY_ADMIN));
}

void Menu::loadUsers() {
    std::ifstream file("users.json");
    if (file.is_open()) {
        // Простой парсинг JSON (упрощенный)
        // Для прототипа - если файл существует, загружаем ключи
        std::string line;
        std::string jsonContent;
        while (std::getline(file, line)) {
            jsonContent += line;
        }
        file.close();
        
        // Простой поиск ключей по имени пользователя
        for (auto& user : users) {
            std::string searchStr = "\"" + user.getUsername() + "\"";
            size_t pos = jsonContent.find(searchStr);
            if (pos != std::string::npos) {
                // Ищем privateKey после имени пользователя
                size_t keyPos = jsonContent.find("\"privateKey\"", pos);
                if (keyPos != std::string::npos) {
                    size_t valueStart = jsonContent.find("\"", keyPos + 13) + 1;
                    size_t valueEnd = jsonContent.find("\"", valueStart);
                    if (valueEnd != std::string::npos) {
                        std::string key = jsonContent.substr(valueStart, valueEnd - valueStart);
                        user.setPrivateKey(key);
                    }
                }
            }
        }
    }
}

void Menu::saveUsers() {
    std::ofstream file("users.json");
    if (file.is_open()) {
        file << "{\n  \"users\": [\n";
        for (size_t i = 0; i < users.size(); ++i) {
            file << "    {\n";
            file << "      \"username\": \"" << users[i].getUsername() << "\",\n";
            file << "      \"role\": \"" << User::roleToString(users[i].getRole()) << "\",\n";
            file << "      \"privateKey\": \"" << escapeJsonString(users[i].getPrivateKey()) << "\"\n";
            file << "    }";
            if (i < users.size() - 1) file << ",";
            file << "\n";
        }
        file << "  ]\n}";
        file.close();
    }
}

void Menu::loadDocuments() {
    std::ifstream file("documents.json");
    if (!file.is_open()) {
        return;
    }
    
    // Простой парсинг JSON
    std::string line;
    std::string jsonContent;
    while (std::getline(file, line)) {
        jsonContent += line;
    }
    file.close();
    
    // Упрощенный парсинг (для прототипа)
    // В реальном проекте использовали бы nlohmann/json
    size_t pos = jsonContent.find("\"documents\"");
    if (pos == std::string::npos) return;
    
    // Находим документы
    size_t start = jsonContent.find("[", pos);
    if (start == std::string::npos) return;
    
    // Простой парсинг каждого документа
    // Для прототипа - упрощенная версия
}

void Menu::saveDocuments() {
    std::ofstream file("documents.json");
    if (file.is_open()) {
        file << "{\n  \"documents\": [\n";
        for (size_t i = 0; i < documents.size(); ++i) {
            const Document& doc = documents[i];
            file << "    {\n";
            file << "      \"id\": " << doc.getId() << ",\n";
            file << "      \"type\": \"" << Document::typeToString(doc.getType()) << "\",\n";
            file << "      \"content\": \"" << escapeJsonString(doc.getContent()) << "\",\n";
            file << "      \"creator\": \"" << doc.getCreator() << "\",\n";
            file << "      \"status\": \"" << Document::statusToString(doc.getStatus()) << "\",\n";
            file << "      \"hash\": \"" << doc.getHash() << "\",\n";
            file << "      \"signature\": \"" << doc.getSignature() << "\",\n";
            file << "      \"timestamp\": " << doc.getTimestamp() << "\n";
            file << "    }";
            if (i < documents.size() - 1) file << ",";
            file << "\n";
        }
        file << "  ]\n}";
        file.close();
    }
}

User* Menu::authenticate() {
    std::string username, password;
    
    std::cout << "\n=== Аутентификация ===\n";
    std::cout << "Имя пользователя: ";
    std::cin >> username;
    std::cout << "Пароль: ";
    std::cin >> password;
    
    for (auto& user : users) {
        if (user.getUsername() == username && user.getPassword() == password) {
            Audit::log(username, "LOGIN", "Successful login");
            return &user;
        }
    }
    
    Audit::logAccessAttempt(username, "LOGIN", false);
    std::cout << "Ошибка: Неверное имя пользователя или пароль.\n";
    return nullptr;
}

bool Menu::hasPermission(const std::string& action) {
    if (!currentUser) return false;
    
    UserRole role = currentUser->getRole();
    
    if (action == "create" || action == "read") {
        return true; // Все могут читать и создавать
    }
    if (action == "sign") {
        return role == UserRole::MANAGER || role == UserRole::CHIEF || 
               role == UserRole::SECURITY_ADMIN;
    }
    if (action == "approve") {
        return role == UserRole::CHIEF || role == UserRole::SECURITY_ADMIN;
    }
    if (action == "reject") {
        return role == UserRole::CHIEF || role == UserRole::SECURITY_ADMIN;
    }
    if (action == "view_all" || action == "view_log") {
        return role == UserRole::SECURITY_ADMIN;
    }
    
    return false;
}

Document* Menu::findDocument(int id) {
    for (auto& doc : documents) {
        if (doc.getId() == id) {
            return &doc;
        }
    }
    return nullptr;
}

User* Menu::findUser(const std::string& username) {
    for (auto& user : users) {
        if (user.getUsername() == username) {
            return &user;
        }
    }
    return nullptr;
}

std::string Menu::escapeJsonString(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 0x20) {
                    // Экранируем управляющие символы
                    char buf[7];
                    sprintf(buf, "\\u%04x", (unsigned char)c);
                    result += buf;
                } else {
                    result += c;
                }
                break;
        }
    }
    return result;
}

DocumentType Menu::selectDocumentType() {
    int choice;
    std::cout << "\nВыберите тип документа:\n";
    std::cout << "1. Кредитная заявка\n";
    std::cout << "2. Кредитный договор\n";
    std::cout << "3. Внутренний приказ\n";
    std::cout << "Выбор: ";
    std::cin >> choice;
    
    switch (choice) {
        case 1: return DocumentType::CREDIT_APPLICATION;
        case 2: return DocumentType::CREDIT_CONTRACT;
        case 3: return DocumentType::INTERNAL_ORDER;
        default: return DocumentType::CREDIT_APPLICATION;
    }
}

void Menu::createDocument() {
    if (!hasPermission("create")) {
        std::cout << "Ошибка: У вас нет прав на создание документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "CREATE_DOCUMENT", false);
        return;
    }
    
    DocumentType type = selectDocumentType();
    
    std::string content;
    std::cout << "\nВведите содержимое документа: ";
    std::cin.ignore();
    std::getline(std::cin, content);
    
    Document doc(nextDocumentId++, type, content, currentUser->getUsername());
    
    // Вычисляем хеш
    std::string hash = CryptoModule::computeHash(content);
    doc.setHash(hash);
    
    // Шифруем содержимое
    std::string encrypted = CryptoModule::encrypt(content, currentUser->getPrivateKey());
    doc.setContent(encrypted);
    
    documents.push_back(doc);
    
    Audit::logDocumentAction(currentUser->getUsername(), "CREATE", doc.getId(), 
                            Document::typeToString(type));
    
    std::cout << "Документ создан с ID: " << doc.getId() << "\n";
    saveDocuments();
}

void Menu::viewDocuments() {
    std::cout << "\n=== Список документов ===\n";
    if (documents.empty()) {
        std::cout << "Документов нет.\n";
        return;
    }
    
    for (const auto& doc : documents) {
        std::cout << "ID: " << doc.getId() 
                  << " | Тип: " << Document::typeToString(doc.getType())
                  << " | Создатель: " << doc.getCreator()
                  << " | Статус: " << Document::statusToString(doc.getStatus()) << "\n";
    }
    
    Audit::log(currentUser->getUsername(), "VIEW_DOCUMENTS_LIST");
}

void Menu::viewDocument(int id) {
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "Документ с ID " << id << " не найден.\n";
        return;
    }
    
    std::cout << "\n=== Документ ID: " << id << " ===\n";
    std::cout << "Тип: " << Document::typeToString(doc->getType()) << "\n";
    std::cout << "Создатель: " << doc->getCreator() << "\n";
    std::cout << "Статус: " << Document::statusToString(doc->getStatus()) << "\n";
    std::cout << "Хеш: " << doc->getHash() << "\n";
    std::cout << "Подпись: " << (doc->getSignature().empty() ? "нет" : "есть") << "\n";
    
    // Расшифровываем содержимое (используем ключ создателя)
    User* creator = findUser(doc->getCreator());
    if (creator) {
        std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
        std::cout << "Содержимое (расшифровано): " << decrypted << "\n";
    } else {
        std::cout << "Содержимое: [зашифровано, создатель не найден]\n";
    }
    
    Audit::logDocumentAction(currentUser->getUsername(), "VIEW", id);
}

void Menu::signDocument(int id) {
    if (!hasPermission("sign")) {
        std::cout << "Ошибка: У вас нет прав на подписание документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "SIGN_DOCUMENT", false);
        return;
    }
    
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "Документ с ID " << id << " не найден.\n";
        return;
    }
    
    if (doc->getStatus() != DocumentStatus::DRAFT) {
        std::cout << "Ошибка: Документ уже подписан или утвержден.\n";
        return;
    }
    
    // Расшифровываем для подписания
    std::string decrypted = CryptoModule::decrypt(doc->getContent(), currentUser->getPrivateKey());
    
    // Создаем подпись
    std::string signature = CryptoModule::createSignature(decrypted, currentUser->getPrivateKey());
    doc->setSignature(signature);
    doc->setStatus(DocumentStatus::SIGNED);
    
    Audit::logDocumentAction(currentUser->getUsername(), "SIGN", id);
    std::cout << "Документ подписан.\n";
    saveDocuments();
}

void Menu::approveDocument(int id) {
    if (!hasPermission("approve")) {
        std::cout << "Ошибка: У вас нет прав на утверждение документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "APPROVE_DOCUMENT", false);
        return;
    }
    
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "Документ с ID " << id << " не найден.\n";
        return;
    }
    
    if (doc->getStatus() != DocumentStatus::SIGNED) {
        std::cout << "Ошибка: Документ должен быть сначала подписан.\n";
        return;
    }
    
    // Проверяем подпись
    User* creator = findUser(doc->getCreator());
    if (!creator) {
        std::cout << "Ошибка: Создатель документа не найден.\n";
        return;
    }
    std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
    
    if (creator && !CryptoModule::verifySignature(decrypted, doc->getSignature(), creator->getPrivateKey())) {
        std::cout << "Предупреждение: Подпись не прошла проверку.\n";
    }
    
    doc->setStatus(DocumentStatus::APPROVED);
    
    Audit::logDocumentAction(currentUser->getUsername(), "APPROVE", id);
    std::cout << "Документ утвержден.\n";
    saveDocuments();
}

void Menu::rejectDocument(int id) {
    if (!hasPermission("reject")) {
        std::cout << "Ошибка: У вас нет прав на отклонение документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "REJECT_DOCUMENT", false);
        return;
    }
    
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "Документ с ID " << id << " не найден.\n";
        return;
    }
    
    doc->setStatus(DocumentStatus::REJECTED);
    
    Audit::logDocumentAction(currentUser->getUsername(), "REJECT", id);
    std::cout << "Документ отклонен.\n";
    saveDocuments();
}

void Menu::decryptDocument(int id) {
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "Документ с ID " << id << " не найден.\n";
        return;
    }
    
    User* creator = findUser(doc->getCreator());
    if (creator) {
        std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
        std::cout << "\nРасшифрованное содержимое: " << decrypted << "\n";
    } else {
        std::cout << "Ошибка: Создатель документа не найден.\n";
    }
    
    Audit::logDocumentAction(currentUser->getUsername(), "DECRYPT", id);
}

void Menu::showOperatorMenu() {
    int choice;
    do {
        std::cout << "\n=== Меню оператора ===\n";
        std::cout << "1. Создать документ\n";
        std::cout << "2. Просмотреть список документов\n";
        std::cout << "3. Просмотреть документ\n";
        std::cout << "4. Выход\n";
        std::cout << "Выбор: ";
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                createDocument();
                break;
            case 2:
                viewDocuments();
                break;
            case 3: {
                int id;
                std::cout << "Введите ID документа: ";
                std::cin >> id;
                viewDocument(id);
                break;
            }
            case 4:
                Audit::log(currentUser->getUsername(), "LOGOUT");
                return;
            default:
                std::cout << "Неверный выбор.\n";
        }
    } while (true);
}

void Menu::showManagerMenu() {
    int choice;
    do {
        std::cout << "\n=== Меню менеджера ===\n";
        std::cout << "1. Создать документ\n";
        std::cout << "2. Просмотреть список документов\n";
        std::cout << "3. Просмотреть документ\n";
        std::cout << "4. Подписать документ\n";
        std::cout << "5. Выход\n";
        std::cout << "Выбор: ";
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                createDocument();
                break;
            case 2:
                viewDocuments();
                break;
            case 3: {
                int id;
                std::cout << "Введите ID документа: ";
                std::cin >> id;
                viewDocument(id);
                break;
            }
            case 4: {
                int id;
                std::cout << "Введите ID документа для подписания: ";
                std::cin >> id;
                signDocument(id);
                break;
            }
            case 5:
                Audit::log(currentUser->getUsername(), "LOGOUT");
                return;
            default:
                std::cout << "Неверный выбор.\n";
        }
    } while (true);
}

void Menu::showChiefMenu() {
    int choice;
    do {
        std::cout << "\n=== Меню руководителя ===\n";
        std::cout << "1. Создать документ\n";
        std::cout << "2. Просмотреть список документов\n";
        std::cout << "3. Просмотреть документ\n";
        std::cout << "4. Подписать документ\n";
        std::cout << "5. Утвердить документ\n";
        std::cout << "6. Отклонить документ\n";
        std::cout << "7. Выход\n";
        std::cout << "Выбор: ";
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                createDocument();
                break;
            case 2:
                viewDocuments();
                break;
            case 3: {
                int id;
                std::cout << "Введите ID документа: ";
                std::cin >> id;
                viewDocument(id);
                break;
            }
            case 4: {
                int id;
                std::cout << "Введите ID документа для подписания: ";
                std::cin >> id;
                signDocument(id);
                break;
            }
            case 5: {
                int id;
                std::cout << "Введите ID документа для утверждения: ";
                std::cin >> id;
                approveDocument(id);
                break;
            }
            case 6: {
                int id;
                std::cout << "Введите ID документа для отклонения: ";
                std::cin >> id;
                rejectDocument(id);
                break;
            }
            case 7:
                Audit::log(currentUser->getUsername(), "LOGOUT");
                return;
            default:
                std::cout << "Неверный выбор.\n";
        }
    } while (true);
}

void Menu::showSecurityAdminMenu() {
    int choice;
    do {
        std::cout << "\n=== Меню администратора безопасности ===\n";
        std::cout << "1. Создать документ\n";
        std::cout << "2. Просмотреть список документов\n";
        std::cout << "3. Просмотреть документ\n";
        std::cout << "4. Подписать документ\n";
        std::cout << "5. Утвердить документ\n";
        std::cout << "6. Отклонить документ\n";
        std::cout << "7. Просмотреть журнал аудита\n";
        std::cout << "8. Выход\n";
        std::cout << "Выбор: ";
        std::cin >> choice;
        
        switch (choice) {
            case 1:
                createDocument();
                break;
            case 2:
                viewDocuments();
                break;
            case 3: {
                int id;
                std::cout << "Введите ID документа: ";
                std::cin >> id;
                viewDocument(id);
                break;
            }
            case 4: {
                int id;
                std::cout << "Введите ID документа для подписания: ";
                std::cin >> id;
                signDocument(id);
                break;
            }
            case 5: {
                int id;
                std::cout << "Введите ID документа для утверждения: ";
                std::cin >> id;
                approveDocument(id);
                break;
            }
            case 6: {
                int id;
                std::cout << "Введите ID документа для отклонения: ";
                std::cin >> id;
                rejectDocument(id);
                break;
            }
            case 7: {
                std::cout << "\n=== Журнал аудита ===\n";
                std::cout << Audit::readLog() << "\n";
                Audit::log(currentUser->getUsername(), "VIEW_AUDIT_LOG");
                break;
            }
            case 8:
                Audit::log(currentUser->getUsername(), "LOGOUT");
                return;
            default:
                std::cout << "Неверный выбор.\n";
        }
    } while (true);
}

void Menu::run() {
    std::cout << "=== Система защищенного электронного документооборота ===\n";
    
    currentUser = authenticate();
    if (!currentUser) {
        std::cout << "Ошибка аутентификации. Выход.\n";
        return;
    }
    
    std::cout << "\nДобро пожаловать, " << currentUser->getUsername() 
              << " (" << User::roleToString(currentUser->getRole()) << ")\n";
    
    switch (currentUser->getRole()) {
        case UserRole::OPERATOR:
            showOperatorMenu();
            break;
        case UserRole::MANAGER:
            showManagerMenu();
            break;
        case UserRole::CHIEF:
            showChiefMenu();
            break;
        case UserRole::SECURITY_ADMIN:
            showSecurityAdminMenu();
            break;
    }
}
