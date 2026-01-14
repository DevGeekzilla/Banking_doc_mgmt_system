#ifndef MENU_H
#define MENU_H

#include "User.h"
#include "Document.h"
#include <vector>
#include <string>

class Menu {
private:
    User* currentUser;
    std::vector<Document> documents;
    std::vector<User> users;
    int nextDocumentId;
    
    // Инициализация пользователей
    void initializeUsers();
    
    // Загрузка/сохранение документов
    void loadDocuments();
    void saveDocuments();
    
    // Загрузка/сохранение пользователей
    void loadUsers();
    void saveUsers();
    
    // Аутентификация
    User* authenticate();
    
    // Меню для разных ролей
    void showOperatorMenu();
    void showManagerMenu();
    void showChiefMenu();
    void showSecurityAdminMenu();
    
    // Операции с документами
    void createDocument();
    void viewDocuments();
    void viewDocument(int id);
    void signDocument(int id);
    void approveDocument(int id);
    void rejectDocument(int id);
    void decryptDocument(int id);
    
    // Вспомогательные функции
    DocumentType selectDocumentType();
    std::string createDocumentForm(DocumentType type);
    bool hasPermission(const std::string& action);
    Document* findDocument(int id);
    User* findUser(const std::string& username);
    std::string stringToHex(const std::string& str);
    void formatTimestamp(std::time_t timestamp, std::string& output);
    
public:
    Menu();
    ~Menu();
    
    void run();
};

#endif // MENU_H
