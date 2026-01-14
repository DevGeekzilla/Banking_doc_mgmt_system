#include "menu.h"
#include "CryptoModule.h"
#include "Audit.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <limits>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstring>

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
    // Хардкод пользователей с фиксированными ключами
    users.clear();
    
    User op("operator1", "pass123", UserRole::OPERATOR);
    op.setPrivateKey("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"); // Фиксированный ключ 32 символа
    users.push_back(op);
    
    User mgr("manager1", "pass123", UserRole::MANAGER);
    mgr.setPrivateKey("b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7"); // Фиксированный ключ
    users.push_back(mgr);
    
    User chf("chief1", "pass123", UserRole::CHIEF);
    chf.setPrivateKey("c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"); // Фиксированный ключ
    users.push_back(chf);
    
    User sec("security_admin1", "pass123", UserRole::SECURITY_ADMIN);
    sec.setPrivateKey("d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9"); // Фиксированный ключ
    users.push_back(sec);
}

void Menu::loadUsers() {
    std::ifstream file("users.bin", std::ios::binary);
    if (!file.is_open()) {
        return; // Файл не существует, используем фиксированные ключи
    }
    
    // Читаем количество пользователей
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    // Читаем каждого пользователя
    for (size_t i = 0; i < count && i < users.size(); ++i) {
        // Читаем username
        size_t usernameLen;
        file.read(reinterpret_cast<char*>(&usernameLen), sizeof(usernameLen));
        std::string username(usernameLen, '\0');
        file.read(&username[0], usernameLen);
        
        // Читаем privateKey
        size_t keyLen;
        file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
        std::string key(keyLen, '\0');
        file.read(&key[0], keyLen);
        
        // Находим пользователя и устанавливаем ключ
        for (auto& user : users) {
            if (user.getUsername() == username) {
                user.setPrivateKey(key);
                break;
            }
        }
    }
    
    file.close();
}

void Menu::saveUsers() {
    std::ofstream file("users.bin", std::ios::binary);
    if (!file.is_open()) {
        return;
    }
    
    // Записываем количество пользователей
    size_t count = users.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    // Записываем каждого пользователя
    for (const auto& user : users) {
        // Записываем username
        std::string username = user.getUsername();
        size_t usernameLen = username.length();
        file.write(reinterpret_cast<const char*>(&usernameLen), sizeof(usernameLen));
        file.write(username.c_str(), usernameLen);
        
        // Записываем privateKey
        std::string key = user.getPrivateKey();
        size_t keyLen = key.length();
        file.write(reinterpret_cast<const char*>(&keyLen), sizeof(keyLen));
        file.write(key.c_str(), keyLen);
    }
    
    file.close();
}

void Menu::loadDocuments() {
    std::ifstream file("documents.bin", std::ios::binary);
    if (!file.is_open()) {
        return;
    }
    
    // Читаем количество документов
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    int maxId = 0;
    
    // Читаем каждый документ
    for (size_t i = 0; i < count; ++i) {
        // Читаем id
        int id;
        file.read(reinterpret_cast<char*>(&id), sizeof(id));
        if (id > maxId) maxId = id;
        
        // Читаем type
        int typeInt;
        file.read(reinterpret_cast<char*>(&typeInt), sizeof(typeInt));
        DocumentType type = static_cast<DocumentType>(typeInt);
        
        // Читаем content
        size_t contentLen;
        file.read(reinterpret_cast<char*>(&contentLen), sizeof(contentLen));
        std::string content(contentLen, '\0');
        file.read(&content[0], contentLen);
        
        // Читаем creator
        size_t creatorLen;
        file.read(reinterpret_cast<char*>(&creatorLen), sizeof(creatorLen));
        std::string creator(creatorLen, '\0');
        file.read(&creator[0], creatorLen);
        
        // Читаем status
        int statusInt;
        file.read(reinterpret_cast<char*>(&statusInt), sizeof(statusInt));
        DocumentStatus status = static_cast<DocumentStatus>(statusInt);
        
        // Читаем hash
        size_t hashLen;
        file.read(reinterpret_cast<char*>(&hashLen), sizeof(hashLen));
        std::string hash(hashLen, '\0');
        file.read(&hash[0], hashLen);
        
        // Читаем signature
        size_t signatureLen;
        file.read(reinterpret_cast<char*>(&signatureLen), sizeof(signatureLen));
        std::string signature(signatureLen, '\0');
        file.read(&signature[0], signatureLen);
        
        // Читаем timestamp
        std::time_t timestamp;
        file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
        
        // Создаем документ
        Document doc(id, type, content, creator);
        doc.setStatus(status);
        doc.setHash(hash);
        doc.setSignature(signature);
        doc.setTimestamp(timestamp);
        
        documents.push_back(doc);
    }
    
    file.close();
    
    // Обновляем nextDocumentId
    if (maxId > 0) {
        nextDocumentId = maxId + 1;
    }
}

void Menu::saveDocuments() {
    std::ofstream file("documents.bin", std::ios::binary);
    if (!file.is_open()) {
        return;
    }
    
    // Записываем количество документов
    size_t count = documents.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    // Записываем каждый документ
    for (const auto& doc : documents) {
        // Записываем id
        int id = doc.getId();
        file.write(reinterpret_cast<const char*>(&id), sizeof(id));
        
        // Записываем type
        int typeInt = static_cast<int>(doc.getType());
        file.write(reinterpret_cast<const char*>(&typeInt), sizeof(typeInt));
        
        // Записываем content
        std::string content = doc.getContent();
        size_t contentLen = content.length();
        file.write(reinterpret_cast<const char*>(&contentLen), sizeof(contentLen));
        file.write(content.c_str(), contentLen);
        
        // Записываем creator
        std::string creator = doc.getCreator();
        size_t creatorLen = creator.length();
        file.write(reinterpret_cast<const char*>(&creatorLen), sizeof(creatorLen));
        file.write(creator.c_str(), creatorLen);
        
        // Записываем status
        int statusInt = static_cast<int>(doc.getStatus());
        file.write(reinterpret_cast<const char*>(&statusInt), sizeof(statusInt));
        
        // Записываем hash
        std::string hash = doc.getHash();
        size_t hashLen = hash.length();
        file.write(reinterpret_cast<const char*>(&hashLen), sizeof(hashLen));
        file.write(hash.c_str(), hashLen);
        
        // Записываем signature
        std::string signature = doc.getSignature();
        size_t signatureLen = signature.length();
        file.write(reinterpret_cast<const char*>(&signatureLen), sizeof(signatureLen));
        file.write(signature.c_str(), signatureLen);
        
        // Записываем timestamp
        std::time_t timestamp = doc.getTimestamp();
        file.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
    }
    
    file.close();
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
    
    // Расшифровываем для подписания (используем ключ создателя документа)
    User* creator = findUser(doc->getCreator());
    if (!creator) {
        std::cout << "Ошибка: Создатель документа не найден.\n";
        return;
    }
    std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
    
    // Создаем подпись ключом создателя (для прототипа - создатель подписывает свой документ)
    std::string signature = CryptoModule::createSignature(decrypted, creator->getPrivateKey());
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
