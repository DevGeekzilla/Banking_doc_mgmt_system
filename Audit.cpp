#include "Audit.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

const std::string Audit::LOG_FILE = "audit.log";

std::string Audit::getCurrentTime() {
    std::time_t now = std::time(nullptr);
    std::tm* timeinfo = std::localtime(&now);
    
    std::stringstream ss;
    ss << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void Audit::log(const std::string& username, const std::string& action, 
                const std::string& details) {
    std::ofstream file(LOG_FILE, std::ios::app);
    if (file.is_open()) {
        file << "[" << getCurrentTime() << "] User: " << username 
             << " | Action: " << action;
        if (!details.empty()) {
            file << " | Details: " << details;
        }
        file << std::endl;
        file.close();
    }
}

void Audit::logDocumentAction(const std::string& username, const std::string& action, 
                              int documentId, const std::string& details) {
    std::ofstream file(LOG_FILE, std::ios::app);
    if (file.is_open()) {
        file << "[" << getCurrentTime() << "] User: " << username 
             << " | Action: " << action 
             << " | Document ID: " << documentId;
        if (!details.empty()) {
            file << " | Details: " << details;
        }
        file << std::endl;
        file.close();
    }
}

void Audit::logAccessAttempt(const std::string& username, const std::string& resource, 
                            bool success) {
    std::ofstream file(LOG_FILE, std::ios::app);
    if (file.is_open()) {
        file << "[" << getCurrentTime() << "] User: " << username 
             << " | Access Attempt: " << resource 
             << " | Result: " << (success ? "SUCCESS" : "DENIED") << std::endl;
        file.close();
    }
}

std::string Audit::readLog() {
    std::ifstream file(LOG_FILE);
    if (!file.is_open()) {
        return "Log file not found or empty.";
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    
    return buffer.str();
}
