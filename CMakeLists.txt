cmake_minimum_required(VERSION 3.10)
project(BankingDocMgmtSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Исходные файлы
set(SOURCES
    main.cpp
    User.cpp
    Document.cpp
    CryptoModule.cpp
    Audit.cpp
    menu.cpp
)

# Заголовочные файлы
set(HEADERS
    User.h
    Document.h
    CryptoModule.h
    Audit.h
    menu.h
)

# Создание исполняемого файла
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Для Windows
if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        WIN32_EXECUTABLE FALSE
    )
endif()
