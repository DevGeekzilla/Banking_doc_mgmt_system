#include "Document.h"
#include <ctime>

Document::Document() : id(0), type(DocumentType::CREDIT_APPLICATION), 
                       status(DocumentStatus::DRAFT), timestamp(std::time(nullptr)) {
}

Document::Document(int id, DocumentType type, const std::string& content, 
                   const std::string& creator)
    : id(id), type(type), content(content), creator(creator), 
      status(DocumentStatus::DRAFT), timestamp(std::time(nullptr)) {
}

int Document::getId() const {
    return id;
}

DocumentType Document::getType() const {
    return type;
}

std::string Document::getContent() const {
    return content;
}

std::string Document::getCreator() const {
    return creator;
}

DocumentStatus Document::getStatus() const {
    return status;
}

std::string Document::getHash() const {
    return hash;
}

std::string Document::getSignature() const {
    return signature;
}

std::time_t Document::getTimestamp() const {
    return timestamp;
}

void Document::setType(DocumentType type) {
    this->type = type;
}

void Document::setContent(const std::string& content) {
    this->content = content;
}

void Document::setStatus(DocumentStatus status) {
    this->status = status;
}

void Document::setHash(const std::string& hash) {
    this->hash = hash;
}

void Document::setSignature(const std::string& signature) {
    this->signature = signature;
}

void Document::setTimestamp(std::time_t timestamp) {
    this->timestamp = timestamp;
}

std::string Document::typeToString(DocumentType type) {
    switch (type) {
        case DocumentType::CREDIT_APPLICATION: return "credit_application";
        case DocumentType::CREDIT_CONTRACT: return "credit_contract";
        case DocumentType::INTERNAL_ORDER: return "internal_order";
        default: return "unknown";
    }
}

DocumentType Document::stringToType(const std::string& typeStr) {
    if (typeStr == "credit_application") return DocumentType::CREDIT_APPLICATION;
    if (typeStr == "credit_contract") return DocumentType::CREDIT_CONTRACT;
    if (typeStr == "internal_order") return DocumentType::INTERNAL_ORDER;
    return DocumentType::CREDIT_APPLICATION;
}

std::string Document::statusToString(DocumentStatus status) {
    switch (status) {
        case DocumentStatus::DRAFT: return "draft";
        case DocumentStatus::SIGNED: return "signed";
        case DocumentStatus::APPROVED: return "approved";
        case DocumentStatus::REJECTED: return "rejected";
        default: return "unknown";
    }
}

DocumentStatus Document::stringToStatus(const std::string& statusStr) {
    if (statusStr == "draft") return DocumentStatus::DRAFT;
    if (statusStr == "signed") return DocumentStatus::SIGNED;
    if (statusStr == "approved") return DocumentStatus::APPROVED;
    if (statusStr == "rejected") return DocumentStatus::REJECTED;
    return DocumentStatus::DRAFT;
}
