#pragma once

#ifdef DLL2_EXPORTS
#define DLL2_API __declspec(dllexport)
#else
#define DLL2_API __declspec(dllimport)
#endif

struct DLL2_API ProcessInfo {
    wchar_t processName[260];  // Имя процесса
    double cpuUsage;          // Использование ЦП в процентах
    size_t memoryUsage;       // Использование памяти в байтах
    double diskReadRate;      // Скорость чтения с диска (байт/сек)
    double diskWriteRate;     // Скорость записи на диск (байт/сек)
    double networkSent;       // Отправлено по сети (байт/сек)
    double networkReceived;   // Получено по сети (байт/сек)
}; 