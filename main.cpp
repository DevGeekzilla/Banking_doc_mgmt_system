#include "menu.h"
#include <iostream>
#include <locale>
#ifdef _WIN32
#include <windows.h>
#endif

int main() {
    // Установка кодировки для Windows консоли
    #ifdef _WIN32
        // Пробуем установить UTF-8 (работает в Windows 10 версии 1903+)
        if (SetConsoleOutputCP(65001) == 0) {
            // Если UTF-8 не поддерживается, используем Windows-1251
            SetConsoleOutputCP(1251);
            SetConsoleCP(1251);
        } else {
            SetConsoleCP(65001);
        }
    #endif
    
    // Установка локали для корректной работы с кириллицей
    try {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    } catch (...) {
        try {
            std::locale::global(std::locale("Russian_Russia.1251"));
        } catch (...) {
            // Используем системную локаль по умолчанию
            std::locale::global(std::locale(""));
        }
    }
    
    try {
        Menu menu;
        menu.run();
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
