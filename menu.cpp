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
#include <iomanip>
#include <ctime>
#include <cctype>

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
    
    // Проверяем, что файл не пустой
    file.seekg(0, std::ios::end);
    if (file.tellg() < static_cast<std::streampos>(sizeof(size_t))) {
        file.close();
        return;
    }
    file.seekg(0, std::ios::beg);
    
    // Читаем количество пользователей
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    // Валидация количества
    if (count > 100) {
        file.close();
        return;
    }
    
    // Читаем каждого пользователя
    for (size_t i = 0; i < count && i < users.size(); ++i) {
        if (file.eof() || file.fail()) break;
        
        // Читаем username
        size_t usernameLen;
        file.read(reinterpret_cast<char*>(&usernameLen), sizeof(usernameLen));
        if (file.fail() || usernameLen > 100) break;
        std::string username(usernameLen, '\0');
        file.read(&username[0], usernameLen);
        if (file.fail()) break;
        
        // Читаем privateKey
        size_t keyLen;
        file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
        if (file.fail() || keyLen > 200) break; // Валидация длины ключа
        std::string key(keyLen, '\0');
        file.read(&key[0], keyLen);
        if (file.fail()) break;
        
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
        return; // Файл не существует - это нормально при первом запуске
    }
    
    // Проверяем, что файл не пустой
    file.seekg(0, std::ios::end);
    if (file.tellg() < static_cast<std::streampos>(sizeof(size_t))) {
        file.close();
        return;
    }
    file.seekg(0, std::ios::beg);
    
    // Читаем количество документов
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    // Валидация количества документов
    if (count > 10000) { // Разумный лимит
        file.close();
        return;
    }
    
    int maxId = 0;
    size_t loadedCount = 0;
    
    // Читаем каждый документ
    for (size_t i = 0; i < count; ++i) {
        // Проверяем, что файл не закончился
        if (file.eof() || file.fail()) {
            break;
        }
        
        // Читаем id
        int id;
        file.read(reinterpret_cast<char*>(&id), sizeof(id));
        if (file.fail()) break;
        if (id > maxId) maxId = id;
        
        // Читаем type
        int typeInt;
        file.read(reinterpret_cast<char*>(&typeInt), sizeof(typeInt));
        if (file.fail()) break;
        if (typeInt < 0 || typeInt > 2) break; // Валидация типа
        DocumentType type = static_cast<DocumentType>(typeInt);
        
        // Читаем content
        size_t contentLen;
        file.read(reinterpret_cast<char*>(&contentLen), sizeof(contentLen));
        if (file.fail() || contentLen > 100000) break; // Валидация длины
        std::string content(contentLen, '\0');
        file.read(&content[0], contentLen);
        if (file.fail()) break;
        
        // Читаем creator
        size_t creatorLen;
        file.read(reinterpret_cast<char*>(&creatorLen), sizeof(creatorLen));
        if (file.fail() || creatorLen > 100) break; // Валидация длины
        std::string creator(creatorLen, '\0');
        file.read(&creator[0], creatorLen);
        if (file.fail()) break;
        
        // Читаем status
        int statusInt;
        file.read(reinterpret_cast<char*>(&statusInt), sizeof(statusInt));
        if (file.fail()) break;
        if (statusInt < 0 || statusInt > 3) break; // Валидация статуса
        DocumentStatus status = static_cast<DocumentStatus>(statusInt);
        
        // Читаем hash
        size_t hashLen;
        file.read(reinterpret_cast<char*>(&hashLen), sizeof(hashLen));
        if (file.fail()) break;
        std::string hash;
        if (hashLen > 0 && hashLen < 1000) { // Валидация длины хеша
            hash.resize(hashLen);
            file.read(&hash[0], hashLen);
            if (file.fail()) break;
        }
        
        // Читаем signature
        size_t signatureLen;
        file.read(reinterpret_cast<char*>(&signatureLen), sizeof(signatureLen));
        if (file.fail()) break;
        if (signatureLen > 10000) break; // Валидация длины
        std::string signature(signatureLen, '\0');
        if (signatureLen > 0) {
            file.read(&signature[0], signatureLen);
            if (file.fail()) break;
        }
        
        // Читаем timestamp
        std::time_t timestamp;
        file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
        if (file.fail()) break;
        
        // Создаем документ
        Document doc(id, type, content, creator);
        doc.setStatus(status);
        doc.setHash(hash);
        doc.setSignature(signature);
        doc.setTimestamp(timestamp);
        
        documents.push_back(doc);
        loadedCount++;
    }
    
    file.close();
    
    // Обновляем nextDocumentId
    if (maxId > 0) {
        nextDocumentId = maxId + 1;
    }
    
    if (loadedCount < count) {
        // Некоторые документы не загрузились - сохраняем то, что загрузилось
        saveDocuments();
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

/**
 * ОБЕСПЕЧЕНИЕ АУТЕНТИФИКАЦИИ
 * 
 * Проверка учетных данных пользователя перед предоставлением доступа к системе
 * 
 * Процесс:
 * 1. Запрос имени пользователя и пароля
 * 2. Поиск пользователя в базе данных
 * 3. Проверка соответствия пароля
 * 4. Логирование успешного входа или попытки доступа
 * 
 * @return указатель на объект User при успешной аутентификации, nullptr в противном случае
 */
User* Menu::authenticate() {
    std::string username, password;
    
    std::cout << "\n========================================\n";
    std::cout << "         АУТЕНТИФИКАЦИЯ\n";
    std::cout << "========================================\n";
    std::cout << "Имя пользователя: ";
    std::cin >> username;
    std::cout << "Пароль: ";
    std::cin >> password;
    
    // Поиск пользователя и проверка пароля
    for (auto& user : users) {
        if (user.getUsername() == username && user.getPassword() == password) {
            Audit::log(username, "LOGIN", "Successful login");
            return &user;
        }
    }
    
    // Логирование неудачной попытки входа
    Audit::logAccessAttempt(username, "LOGIN", false);
    std::cout << "\n[ОШИБКА] Неверное имя пользователя или пароль.\n";
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

std::string Menu::stringToHex(const std::string& str) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char c : str) {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

void Menu::formatTimestamp(std::time_t timestamp, std::string& output) {
    std::tm timeinfo;
#ifdef _WIN32
    // Используем безопасную версию для Windows
    localtime_s(&timeinfo, &timestamp);
    std::tm* timeinfo_ptr = &timeinfo;
#else
    // Для других платформ используем стандартную функцию
    std::tm* timeinfo_ptr = std::localtime(&timestamp);
#endif
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo_ptr);
    output = buffer;
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

/**
 * НАБОР СВЯЗАННЫХ СО СХЕМОЙ ЭЛЕКТРОННЫХ УЧЕТНЫХ ФОРМ
 * 
 * Интерактивные формы для ввода данных документов разных типов
 * Каждый тип документа имеет свою специализированную форму с соответствующими полями
 * 
 * Формы реализуют структурированный учет документов:
 * - Кредитная заявка: сумма, срок, назначение
 * - Кредитный договор: стороны, сумма, условия
 * - Внутренний приказ: номер, дата, содержание, подписант
 * 
 * @param type - тип документа для создания формы
 * @return структурированное содержимое документа в формате "Поле: значение | ..."
 */
std::string Menu::createDocumentForm(DocumentType type) {
    std::string content;
    std::cin.ignore(); // Очистка буфера ввода
    
    // Приоритет 4: Интерактивные формы для документов
    switch (type) {
        case DocumentType::CREDIT_APPLICATION: {
            std::cout << "\n=== Форма кредитной заявки ===\n";
            std::string sum, term, purpose;
            std::cout << "Сумма кредита: ";
            std::getline(std::cin, sum);
            std::cout << "Срок кредита: ";
            std::getline(std::cin, term);
            std::cout << "Назначение кредита: ";
            std::getline(std::cin, purpose);
            content = "Сумма: " + sum + " | Срок: " + term + " | Назначение: " + purpose;
            break;
        }
        case DocumentType::CREDIT_CONTRACT: {
            std::cout << "\n=== Форма кредитного договора ===\n";
            std::string party1, party2, sum, conditions;
            std::cout << "Сторона 1 (кредитор): ";
            std::getline(std::cin, party1);
            std::cout << "Сторона 2 (заемщик): ";
            std::getline(std::cin, party2);
            std::cout << "Сумма договора: ";
            std::getline(std::cin, sum);
            std::cout << "Условия договора: ";
            std::getline(std::cin, conditions);
            content = "Сторона 1: " + party1 + " | Сторона 2: " + party2 + 
                     " | Сумма: " + sum + " | Условия: " + conditions;
            break;
        }
        case DocumentType::INTERNAL_ORDER: {
            std::cout << "\n=== Форма внутреннего приказа ===\n";
            std::string number, date, content_text, signer;
            std::cout << "Номер приказа: ";
            std::getline(std::cin, number);
            std::cout << "Дата приказа: ";
            std::getline(std::cin, date);
            std::cout << "Содержание приказа: ";
            std::getline(std::cin, content_text);
            std::cout << "Подписант: ";
            std::getline(std::cin, signer);
            content = "Номер: " + number + " | Дата: " + date + 
                     " | Содержание: " + content_text + " | Подписант: " + signer;
            break;
        }
    }
    
    return content;
}

/**
 * ИНТЕРАКТИВНАЯ СХЕМА ПРОХОЖДЕНИЯ УЧЕТА: СОЗДАНИЕ ДОКУМЕНТА
 * 
 * Этап 1 жизненного цикла документа: СОЗДАНИЕ (DRAFT)
 * 
 * Процесс:
 * 1. Проверка прав доступа (только OPERATOR и SECURITY_ADMIN могут создавать)
 * 2. Выбор типа документа
 * 3. Заполнение интерактивной формы (createDocumentForm)
 * 4. Вычисление хеша для защиты целостности
 * 5. Шифрование содержимого для обеспечения конфиденциальности
 * 6. Сохранение документа со статусом DRAFT
 * 7. Логирование действия в журнал аудита
 * 
 * Технологии защиты:
 * - Конфиденциальность: документ шифруется приватным ключом создателя
 * - Целостность: вычисляется и сохраняется хеш документа
 * - Аутентификация: проверка прав доступа перед созданием
 */
void Menu::createDocument() {
    if (!hasPermission("create")) {
        std::cout << "\n[ОШИБКА] У вас нет прав на создание документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "CREATE_DOCUMENT", false);
        return;
    }
    
    DocumentType type = selectDocumentType();
    
    // Используем интерактивную форму для ввода данных
    std::string content = createDocumentForm(type);
    
    // Валидация содержимого
    if (content.empty()) {
        std::cout << "\n[ОШИБКА] Содержимое документа не может быть пустым.\n";
        return;
    }
    
    Document doc(nextDocumentId++, type, content, currentUser->getUsername());
    
    // ЗАЩИТА ЦЕЛОСТНОСТИ: Вычисляем хеш документа
    std::string hash = CryptoModule::computeHash(content);
    doc.setHash(hash);
    
    // ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ: Шифруем содержимое приватным ключом создателя
    std::string encrypted = CryptoModule::encrypt(content, currentUser->getPrivateKey());
    doc.setContent(encrypted);
    
    documents.push_back(doc);
    
    // Приоритет 2: Расширить аудит документов - детализация создания
    std::string details = "Type: " + Document::typeToString(type) + 
                         " | Size: " + std::to_string(content.length()) + " bytes" +
                         " | Hash: " + hash.substr(0, 8) + "...";
    Audit::logDocumentAction(currentUser->getUsername(), "CREATE", doc.getId(), details);
    
    std::cout << "\n[УСПЕХ] Документ успешно создан!\n";
    std::cout << "ID документа: " << doc.getId() << "\n";
    std::cout << "Тип: " << Document::typeToString(type) << "\n";
    std::cout << "Размер: " << content.length() << " байт\n";
    std::cout << "Хеш: " << hash << "\n";
    
    saveDocuments();
}

void Menu::viewDocuments() {
    std::cout << "\n========================================\n";
    std::cout << "     СПИСОК ДОКУМЕНТОВ\n";
    std::cout << "========================================\n";
    
    if (documents.empty()) {
        std::cout << "Документов в системе нет.\n";
        std::cout << "========================================\n";
        return;
    }
    
    std::cout << "Всего документов: " << documents.size() << "\n\n";
    std::cout << std::left << std::setw(6) << "ID" 
              << std::setw(20) << "Тип" 
              << std::setw(15) << "Создатель" 
              << std::setw(12) << "Статус" << "\n";
    std::cout << std::string(60, '-') << "\n";
    
    for (const auto& doc : documents) {
        std::cout << std::left << std::setw(6) << doc.getId()
                  << std::setw(20) << Document::typeToString(doc.getType())
                  << std::setw(15) << doc.getCreator()
                  << std::setw(12) << Document::statusToString(doc.getStatus()) << "\n";
    }
    
    std::cout << "========================================\n";
    
    Audit::log(currentUser->getUsername(), "VIEW_DOCUMENTS_LIST");
}

/**
 * ПРОСМОТР ДОКУМЕНТА С ПРОВЕРКОЙ ЗАЩИТЫ
 * 
 * Демонстрирует работу всех технологий защиты:
 * 
 * 1. ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ:
 *    - Отображение зашифрованного содержимого в HEX-формате
 *    - Расшифровка документа для авторизованных пользователей
 * 
 * 2. ЗАЩИТА ЦЕЛОСТНОСТИ:
 *    - Отображение сохраненного хеша документа
 *    - Вычисление хеша расшифрованного содержимого
 *    - Сравнение хешей для проверки целостности
 *    - Автоматический пересчет хеша, если он был пустым
 * 
 * 3. ЗАЩИТА АВТОРСТВА:
 *    - Отображение информации о наличии электронной подписи
 *    - Информация о создателе документа
 * 
 * @param id - идентификатор документа для просмотра
 */
void Menu::viewDocument(int id) {
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "\n[ОШИБКА] Документ с ID " << id << " не найден.\n";
        return;
    }
    
    std::cout << "\n========================================\n";
    std::cout << "     ДОКУМЕНТ ID: " << id << "\n";
    std::cout << "========================================\n";
    std::cout << "Тип документа: " << Document::typeToString(doc->getType()) << "\n";
    std::cout << "Создатель: " << doc->getCreator() << "\n";
    std::cout << "Статус: " << Document::statusToString(doc->getStatus()) << "\n";
    
    // Форматируем дату создания
    std::string dateStr;
    formatTimestamp(doc->getTimestamp(), dateStr);
    std::cout << "Дата создания: " << dateStr << "\n";
    
    // ЗАЩИТА ЦЕЛОСТНОСТИ: Отображаем хеш документа
    std::string hash = doc->getHash();
    if (hash.empty()) {
        std::cout << "Хеш: [не вычислен]\n";
    } else {
        // Проверяем, что хеш не содержит непечатаемые символы
        std::string displayHash;
        for (char c : hash) {
            if (std::isprint(static_cast<unsigned char>(c)) || c == '\0') {
                displayHash += c;
            } else {
                displayHash += '?';
            }
        }
        std::cout << "Хеш: " << displayHash << " (длина: " << hash.length() << ")\n";
    }
    
    std::cout << "Подпись: " << (doc->getSignature().empty() ? "нет" : "есть") << "\n";
    
    // ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ: Показываем зашифрованное содержимое в hex формате
    std::string encryptedHex = stringToHex(doc->getContent());
    std::cout << "\n--- Зашифрованное содержимое (HEX) ---\n";
    // Показываем первые 64 символа hex, если длиннее
    if (encryptedHex.length() > 64) {
        std::cout << encryptedHex.substr(0, 64) << "... (показано 32 байта из " 
                  << (doc->getContent().length()) << ")\n";
    } else {
        std::cout << encryptedHex << "\n";
    }
    
    // ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ: Расшифровываем содержимое (используем ключ создателя)
    User* creator = findUser(doc->getCreator());
    bool decryptSuccess = false;
    if (creator) {
        try {
            std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
            std::cout << "\n--- Расшифрованное содержимое ---\n";
            std::cout << decrypted;
            if (!decrypted.empty() && decrypted.back() != '\n') {
                std::cout << "\n";
            }
            
            // ЗАЩИТА ЦЕЛОСТНОСТИ: Проверка целостности при просмотре
            std::string computedHash = CryptoModule::computeHash(decrypted);
            
            // Если хеш был пустым, сохраняем вычисленный
            if (hash.empty()) {
                doc->setHash(computedHash);
                hash = computedHash; // Обновляем локальную переменную
                saveDocuments();
                std::cout << "\n[ИНФО] Хеш пересчитан и сохранен: " << hash << "\n";
            }
            
            std::cout << "\n--- Проверка целостности ---\n";
            // Форматируем хеши для вывода (убираем непечатаемые символы)
            std::string displayStoredHash;
            for (char c : hash) {
                if (std::isprint(static_cast<unsigned char>(c))) {
                    displayStoredHash += c;
                } else {
                    displayStoredHash += '?';
                }
            }
            std::string displayComputedHash;
            for (char c : computedHash) {
                if (std::isprint(static_cast<unsigned char>(c))) {
                    displayComputedHash += c;
                } else {
                    displayComputedHash += '?';
                }
            }
            std::cout << "Сохраненный хеш: " << (displayStoredHash.empty() ? "[пусто]" : displayStoredHash) 
                      << " (длина: " << hash.length() << ")\n";
            std::cout << "Вычисленный хеш: " << (displayComputedHash.empty() ? "[пусто]" : displayComputedHash) 
                      << " (длина: " << computedHash.length() << ")\n";
            if (computedHash == hash) {
                std::cout << "[OK] Целостность подтверждена\n";
            } else {
                std::cout << "[ERROR] Целостность нарушена!\n";
            }
            
            decryptSuccess = true;
            std::string hashStatus = (computedHash == doc->getHash() ? "OK" : "FAILED");
            Audit::logDocumentAction(currentUser->getUsername(), "DECRYPT_SUCCESS", id, 
                                    "Hash check: " + hashStatus);
        } catch (const std::exception& e) {
            std::cout << "\n[ERROR] Ошибка расшифровки: " << e.what() << "\n";
            Audit::logDocumentAction(currentUser->getUsername(), "DECRYPT_FAILED", id, 
                                    "Decryption error: " + std::string(e.what()));
        } catch (...) {
            std::cout << "\n[ERROR] Неизвестная ошибка при расшифровке\n";
            Audit::logDocumentAction(currentUser->getUsername(), "DECRYPT_FAILED", id, "Decryption error");
        }
    } else {
        std::cout << "\n[ERROR] Создатель документа не найден в системе\n";
        Audit::logDocumentAction(currentUser->getUsername(), "DECRYPT_FAILED", id, "Creator not found");
    }
    
    std::cout << "========================================\n";
    
    Audit::logDocumentAction(currentUser->getUsername(), "VIEW", id);
}

/**
 * ИНТЕРАКТИВНАЯ СХЕМА ПРОХОЖДЕНИЯ УЧЕТА: ПОДПИСАНИЕ ДОКУМЕНТА
 * 
 * Этап 2 жизненного цикла документа: ПОДПИСАНИЕ (DRAFT -> SIGNED)
 * 
 * Процесс:
 * 1. Проверка прав доступа (только MANAGER и SECURITY_ADMIN могут подписывать)
 * 2. Проверка статуса документа (должен быть DRAFT)
 * 3. Расшифровка документа для проверки содержимого
 * 4. ЗАЩИТА ЦЕЛОСТНОСТИ: Проверка хеша перед подписанием
 * 5. ЗАЩИТА АВТОРСТВА: Создание электронной подписи приватным ключом создателя
 * 6. Изменение статуса на SIGNED
 * 7. Логирование действия в журнал аудита
 * 
 * Технологии защиты:
 * - Целостность: проверка хеша перед подписанием (документ не должен быть изменен)
 * - Авторство: подпись создается с использованием приватного ключа создателя
 * - Невозможность отказа: только создатель может создать валидную подпись
 */
void Menu::signDocument(int id) {
    if (!hasPermission("sign")) {
        std::cout << "\n[ОШИБКА] У вас нет прав на подписание документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "SIGN_DOCUMENT", false);
        return;
    }
    
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "\n[ОШИБКА] Документ с ID " << id << " не найден.\n";
        return;
    }
    
    if (doc->getStatus() != DocumentStatus::DRAFT) {
        std::cout << "\n[ОШИБКА] Документ уже подписан или утвержден.\n";
        std::cout << "Текущий статус: " << Document::statusToString(doc->getStatus()) << "\n";
        return;
    }
    
    // ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ: Расшифровываем для подписания (используем ключ создателя документа)
    User* creator = findUser(doc->getCreator());
    if (!creator) {
        std::cout << "\n[ОШИБКА] Создатель документа не найден в системе.\n";
        return;
    }
    std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
    
    // ЗАЩИТА ЦЕЛОСТНОСТИ: Проверка целостности при подписании
    std::string computedHash = CryptoModule::computeHash(decrypted);
    std::string storedHash = doc->getHash();
    
    // Если хеш пустой, используем вычисленный
    if (storedHash.empty()) {
        doc->setHash(computedHash);
        storedHash = computedHash;
        std::cout << "[ИНФО] Хеш документа пересчитан.\n";
    }
    
    std::cout << "\n--- Проверка целостности перед подписанием ---\n";
    std::cout << "Сохраненный хеш: " << storedHash << "\n";
    std::cout << "Вычисленный хеш: " << computedHash << "\n";
    
    if (computedHash != storedHash) {
        std::cout << "\n[ОШИБКА] Целостность документа нарушена!\n";
        std::cout << "Подпись не может быть поставлена.\n";
        Audit::logDocumentAction(currentUser->getUsername(), "SIGN_FAILED", id, 
                                "Integrity check failed: hash mismatch");
        return;
    }
    
    std::cout << "[OK] Целостность подтверждена, подписание разрешено.\n";
    
    // ЗАЩИТА АВТОРСТВА И НЕВОЗМОЖНОСТИ ОТКАЗА: Создаем подпись ключом создателя
    std::string signature = CryptoModule::createSignature(decrypted, creator->getPrivateKey());
    doc->setSignature(signature);
    doc->setStatus(DocumentStatus::SIGNED);
    
    Audit::logDocumentAction(currentUser->getUsername(), "SIGN", id, 
                            "Hash verified: " + computedHash.substr(0, 8) + "...");
    std::cout << "\n[УСПЕХ] Документ успешно подписан.\n";
    std::cout << "Статус изменен на: " << Document::statusToString(DocumentStatus::SIGNED) << "\n";
    saveDocuments();
}

/**
 * ИНТЕРАКТИВНАЯ СХЕМА ПРОХОЖДЕНИЯ УЧЕТА: УТВЕРЖДЕНИЕ ДОКУМЕНТА
 * 
 * Этап 3 жизненного цикла документа: УТВЕРЖДЕНИЕ (SIGNED -> APPROVED)
 * 
 * Процесс:
 * 1. Проверка прав доступа (только CHIEF и SECURITY_ADMIN могут утверждать)
 * 2. Проверка статуса документа (должен быть SIGNED)
 * 3. Расшифровка документа для проверки содержимого
 * 4. ЗАЩИТА ЦЕЛОСТНОСТИ: Проверка хеша перед утверждением
 * 5. ЗАЩИТА АВТОРСТВА: Проверка электронной подписи
 * 6. Изменение статуса на APPROVED
 * 7. Логирование действия в журнал аудита
 * 
 * Технологии защиты:
 * - Целостность: проверка хеша (документ не должен быть изменен)
 * - Авторство: проверка электронной подписи (подтверждение авторства создателя)
 * - Невозможность отказа: валидная подпись доказывает авторство
 */
void Menu::approveDocument(int id) {
    if (!hasPermission("approve")) {
        std::cout << "\n[ОШИБКА] У вас нет прав на утверждение документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "APPROVE_DOCUMENT", false);
        return;
    }
    
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "\n[ОШИБКА] Документ с ID " << id << " не найден.\n";
        return;
    }
    
    if (doc->getStatus() != DocumentStatus::SIGNED) {
        std::cout << "\n[ОШИБКА] Документ должен быть сначала подписан.\n";
        std::cout << "Текущий статус: " << Document::statusToString(doc->getStatus()) << "\n";
        return;
    }
    
    // ОБЕСПЕЧЕНИЕ КОНФИДЕНЦИАЛЬНОСТИ: Расшифровка для проверки
    User* creator = findUser(doc->getCreator());
    if (!creator) {
        std::cout << "\n[ОШИБКА] Создатель документа не найден в системе.\n";
        return;
    }
    
    std::string decrypted = CryptoModule::decrypt(doc->getContent(), creator->getPrivateKey());
    
    // ЗАЩИТА ЦЕЛОСТНОСТИ: Проверяем целостность перед утверждением
    std::string computedHash = CryptoModule::computeHash(decrypted);
    std::string storedHash = doc->getHash();
    if (storedHash.empty()) {
        doc->setHash(computedHash);
        storedHash = computedHash;
    }
    
    bool integrityOK = (computedHash == storedHash);
    // ЗАЩИТА АВТОРСТВА: Проверка электронной подписи
    bool signatureOK = CryptoModule::verifySignature(decrypted, doc->getSignature(), creator->getPrivateKey());
    
    std::cout << "\n--- Проверка перед утверждением ---\n";
    std::cout << "Целостность: " << (integrityOK ? "[OK]" : "[ERROR]") << "\n";
    std::cout << "Подпись: " << (signatureOK ? "[OK]" : "[ERROR]") << "\n";
    
    if (!signatureOK) {
        std::cout << "\n[ПРЕДУПРЕЖДЕНИЕ] Подпись не прошла проверку, но документ будет утвержден.\n";
        Audit::logDocumentAction(currentUser->getUsername(), "APPROVE_WARNING", id, 
                                "Signature verification failed");
    }
    
    if (!integrityOK) {
        std::cout << "\n[ОШИБКА] Целостность документа нарушена! Утверждение отменено.\n";
        Audit::logDocumentAction(currentUser->getUsername(), "APPROVE_FAILED", id, 
                                "Integrity check failed");
        return;
    }
    
    doc->setStatus(DocumentStatus::APPROVED);
    
    std::string sigStatus = (signatureOK ? "OK" : "FAILED");
    Audit::logDocumentAction(currentUser->getUsername(), "APPROVE", id, 
                            "Integrity: OK, Signature: " + sigStatus);
    std::cout << "\n[УСПЕХ] Документ успешно утвержден.\n";
    std::cout << "Статус изменен на: " << Document::statusToString(DocumentStatus::APPROVED) << "\n";
    saveDocuments();
}

void Menu::rejectDocument(int id) {
    if (!hasPermission("reject")) {
        std::cout << "\n[ОШИБКА] У вас нет прав на отклонение документов.\n";
        Audit::logAccessAttempt(currentUser->getUsername(), "REJECT_DOCUMENT", false);
        return;
    }
    
    Document* doc = findDocument(id);
    if (!doc) {
        std::cout << "\n[ОШИБКА] Документ с ID " << id << " не найден.\n";
        return;
    }
    
    if (doc->getStatus() == DocumentStatus::REJECTED) {
        std::cout << "\n[ИНФО] Документ уже отклонен.\n";
        return;
    }
    
    std::string oldStatus = Document::statusToString(doc->getStatus());
    doc->setStatus(DocumentStatus::REJECTED);
    
    Audit::logDocumentAction(currentUser->getUsername(), "REJECT", id, 
                            "Previous status: " + oldStatus);
    std::cout << "\n[УСПЕХ] Документ отклонен.\n";
    std::cout << "Предыдущий статус: " << oldStatus << "\n";
    std::cout << "Новый статус: " << Document::statusToString(DocumentStatus::REJECTED) << "\n";
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

/**
 * ОБЩИЙ ИНТЕРФЕЙС ДЛЯ УПРАВЛЕНИЯ ПРОТОТИПОМ
 * 
 * Главная точка входа в систему ЗЭДКД
 * 
 * Процесс:
 * 1. Инициализация системы (загрузка пользователей и документов)
 * 2. ОБЕСПЕЧЕНИЕ АУТЕНТИФИКАЦИИ: проверка учетных данных
 * 3. Отображение ролевого меню в зависимости от роли пользователя
 * 4. Обработка команд пользователя до выхода из системы
 * 
 * Ролевые меню:
 * - OPERATOR: создание и просмотр документов
 * - MANAGER: + подписание документов
 * - CHIEF: + утверждение/отклонение документов
 * - SECURITY_ADMIN: + просмотр журнала аудита
 */
void Menu::run() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "  СИСТЕМА ЗАЩИЩЕННОГО ЭЛЕКТРОННОГО\n";
    std::cout << "      ДОКУМЕНТООБОРОТА (ЗЭДКД)\n";
    std::cout << "========================================\n";
    
    // ОБЕСПЕЧЕНИЕ АУТЕНТИФИКАЦИИ
    currentUser = authenticate();
    if (!currentUser) {
        std::cout << "\n[ОШИБКА] Аутентификация не удалась. Выход из системы.\n";
        return;
    }
    
    std::cout << "\n[УСПЕХ] Добро пожаловать, " << currentUser->getUsername() << "!\n";
    std::cout << "Роль: " << User::roleToString(currentUser->getRole()) << "\n";
    std::cout << "========================================\n";
    
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
