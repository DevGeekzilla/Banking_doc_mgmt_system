/**
 * МОДУЛЬ ЖУРНАЛА АУДИТА
 * 
 * Обеспечивает логирование всех действий в системе для:
 * - Отслеживания доступа к документам
 * - Контроля операций с документами (создание, подписание, утверждение)
 * - Регистрации попыток доступа (успешных и неудачных)
 * - Анализа действий пользователей
 * 
 * Все действия записываются в файл audit.log с временными метками
 */
#ifndef AUDIT_H
#define AUDIT_H

#include <string>
#include <ctime>

class Audit {
public:
    static void log(const std::string& username, const std::string& action, 
                   const std::string& details = "");
    
    static void logDocumentAction(const std::string& username, const std::string& action, 
                                  int documentId, const std::string& details = "");
    
    static void logAccessAttempt(const std::string& username, const std::string& resource, 
                                bool success);
    
    static std::string readLog();
    
private:
    static std::string getCurrentTime();
    static const std::string LOG_FILE;
};

#endif // AUDIT_H
