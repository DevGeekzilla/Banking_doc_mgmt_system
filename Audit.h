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
