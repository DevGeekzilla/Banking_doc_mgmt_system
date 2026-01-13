#ifndef DOCUMENT_H
#define DOCUMENT_H

#include <string>
#include <ctime>

enum class DocumentType {
    CREDIT_APPLICATION,  // кредитная заявка
    CREDIT_CONTRACT,     // кредитный договор
    INTERNAL_ORDER       // внутренний приказ
};

enum class DocumentStatus {
    DRAFT,
    SIGNED,
    APPROVED,
    REJECTED
};

class Document {
private:
    int id;
    DocumentType type;
    std::string content;
    std::string creator;
    DocumentStatus status;
    std::string hash;
    std::string signature;
    std::time_t timestamp;

public:
    Document();
    Document(int id, DocumentType type, const std::string& content, 
             const std::string& creator);
    
    int getId() const;
    DocumentType getType() const;
    std::string getContent() const;
    std::string getCreator() const;
    DocumentStatus getStatus() const;
    std::string getHash() const;
    std::string getSignature() const;
    std::time_t getTimestamp() const;
    
    void setType(DocumentType type);
    void setContent(const std::string& content);
    void setStatus(DocumentStatus status);
    void setHash(const std::string& hash);
    void setSignature(const std::string& signature);
    void setTimestamp(std::time_t timestamp);
    
    static std::string typeToString(DocumentType type);
    static DocumentType stringToType(const std::string& typeStr);
    
    static std::string statusToString(DocumentStatus status);
    static DocumentStatus stringToStatus(const std::string& statusStr);
};

#endif // DOCUMENT_H
