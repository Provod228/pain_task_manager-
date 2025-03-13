#include "ProcessInfo.h"
#include <windows.h>
#include <psapi.h>
#include <pdh.h>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <future>
#include "pch.h"
#include "ProcessMonitor.h"
#include <unordered_map>
#include <chrono>

#pragma comment(lib, "pdh.lib")

// Размер пула потоков
const size_t THREAD_POOL_SIZE = 4;

// Структура для хранения времени CPU процесса
struct ProcessCPUData {
    ULARGE_INTEGER lastCPU;
    ULARGE_INTEGER lastUserCPU;
    ULARGE_INTEGER lastKernelCPU;
    ULONGLONG lastTime;
    double lastCpuUsage;
};

// Кэш для хранения данных процессов
struct ProcessCacheData {
    ProcessCPUData cpuData;
    std::wstring name;
    ULONGLONG lastUpdateTime;
    size_t memoryUsage;
    double diskReadRate;
    double diskWriteRate;
    double networkSent;
    double networkReceived;
    bool needsUpdate;
};

// Структуры для хранения счетчиков IO
struct IOCounters {
    ULONGLONG readBytes;
    ULONGLONG writeBytes;
    ULONGLONG lastUpdateTime;
};

// Структура для хранения PDH счетчиков
struct PDHCounters {
    PDH_HQUERY query;
    PDH_HCOUNTER diskReadCounter;
    PDH_HCOUNTER diskWriteCounter;
    PDH_HCOUNTER networkSentCounter;
    PDH_HCOUNTER networkRecvCounter;
    ULONGLONG lastUpdateTime;
    double lastDiskRead;
    double lastDiskWrite;
    double lastNetworkSent;
    double lastNetworkRecv;
};

// Пул потоков
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;

public:
    ThreadPool(size_t threads) : stop(false) {
        for(size_t i = 0; i < threads; ++i)
            workers.emplace_back([this] {
                while(true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { 
                            return stop || !tasks.empty(); 
                        });
                        if(stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
    }

    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for(std::thread &worker: workers)
            worker.join();
    }
};

// Глобальные переменные
static std::unordered_map<DWORD, ProcessCacheData> processCache;
static DWORD numProcessors = 0;
static const ULONGLONG CACHE_TIMEOUT = 1000; // 1 секунда
static std::mutex cacheMutex;
static ThreadPool* threadPool = nullptr;
static PDHCounters pdhCounters = {};

ProcessMonitor::ProcessMonitor() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    numProcessors = sysInfo.dwNumberOfProcessors;
    if (!threadPool) {
        threadPool = new ThreadPool(THREAD_POOL_SIZE);
    }

    // Инициализация PDH счетчиков
    PDH_STATUS status = PdhOpenQuery(NULL, 0, &pdhCounters.query);
    if (status == ERROR_SUCCESS) {
        PDH_STATUS counterStatus;

        // Добавляем счетчики диска
        counterStatus = PdhAddEnglishCounterW(pdhCounters.query,
            L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
            0, &pdhCounters.diskReadCounter);
        if (counterStatus != ERROR_SUCCESS) {
            // Ошибка добавления счетчика
        }

        counterStatus = PdhAddEnglishCounterW(pdhCounters.query,
            L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
            0, &pdhCounters.diskWriteCounter);
        if (counterStatus != ERROR_SUCCESS) {
            // Ошибка добавления счетчика
        }

        // Добавляем счетчики сети
        counterStatus = PdhAddEnglishCounterW(pdhCounters.query,
            L"\\Network Interface(*)\\Bytes Sent/sec",
            0, &pdhCounters.networkSentCounter);
        if (counterStatus != ERROR_SUCCESS) {
            // Ошибка добавления счетчика
        }

        counterStatus = PdhAddEnglishCounterW(pdhCounters.query,
            L"\\Network Interface(*)\\Bytes Received/sec",
            0, &pdhCounters.networkRecvCounter);
        if (counterStatus != ERROR_SUCCESS) {
            // Ошибка добавления счетчика
        }

        // Первый сбор данных для инициализации
        if (PdhCollectQueryData(pdhCounters.query) != ERROR_SUCCESS) {
            // Ошибка сбора данных
        }
        pdhCounters.lastUpdateTime = GetTickCount64();
    } else {
        // Ошибка открытия PDH запроса
    }
}

ProcessMonitor::~ProcessMonitor() {
    if (pdhCounters.query) {
        PdhCloseQuery(pdhCounters.query);
    }
    delete threadPool;
    threadPool = nullptr;
    
    std::lock_guard<std::mutex> lock(cacheMutex);
    processCache.clear();
}

void UpdateProcessData(DWORD processID, ProcessCacheData& cacheEntry) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) return;

    // Обновляем имя процесса только если оно пустое
    if (cacheEntry.name.empty()) {
        WCHAR szProcessPath[MAX_PATH];
        if (GetProcessImageFileNameW(hProcess, szProcessPath, MAX_PATH)) {
            WCHAR* processName = wcsrchr(szProcessPath, L'\\');
            cacheEntry.name = processName ? processName + 1 : szProcessPath;
        }
    }

    // Обновляем информацию о памяти
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        cacheEntry.memoryUsage = pmc.WorkingSetSize;
    }

    // Обновляем CPU
    FILETIME now, creation, exit, kernel, user;
    GetSystemTimeAsFileTime(&now);
    
    if (GetProcessTimes(hProcess, &creation, &exit, &kernel, &user)) {
        ULONGLONG time = *((PULONGLONG)&now);
        ULONGLONG kernelTime = *((PULONGLONG)&kernel);
        ULONGLONG userTime = *((PULONGLONG)&user);

        auto& cpuData = cacheEntry.cpuData;
        
        if (cpuData.lastTime != 0) {
            ULONGLONG timeDiff = time - cpuData.lastTime;
            if (timeDiff > 0) {
                ULONGLONG totalTime = (kernelTime - cpuData.lastKernelCPU.QuadPart) + 
                                    (userTime - cpuData.lastUserCPU.QuadPart);
                cpuData.lastCpuUsage = (totalTime * 100.0) / (timeDiff * numProcessors);
            }
        }

        cpuData.lastTime = time;
        cpuData.lastKernelCPU.QuadPart = kernelTime;
        cpuData.lastUserCPU.QuadPart = userTime;
    }

    // Обновляем информацию о дисковой и сетевой активности
    ULONGLONG currentTime = GetTickCount64();
    if (currentTime - pdhCounters.lastUpdateTime >= 1000) { // Обновляем раз в секунду
        if (PdhCollectQueryData(pdhCounters.query) == ERROR_SUCCESS) {
            PDH_FMT_COUNTERVALUE counterValue;
            DWORD counterType;

            // Получаем значения счетчиков диска
            if (PdhGetFormattedCounterValue(pdhCounters.diskReadCounter, 
                PDH_FMT_DOUBLE, &counterType, &counterValue) == ERROR_SUCCESS) {
                pdhCounters.lastDiskRead = counterValue.doubleValue;
                cacheEntry.diskReadRate = pdhCounters.lastDiskRead / (1024.0 * 1024.0); // Конвертируем в МБ/с
            }

            if (PdhGetFormattedCounterValue(pdhCounters.diskWriteCounter,
                PDH_FMT_DOUBLE, &counterType, &counterValue) == ERROR_SUCCESS) {
                pdhCounters.lastDiskWrite = counterValue.doubleValue;
                cacheEntry.diskWriteRate = pdhCounters.lastDiskWrite / (1024.0 * 1024.0); // Конвертируем в МБ/с
            }

            // Получаем значения счетчиков сети
            if (PdhGetFormattedCounterValue(pdhCounters.networkSentCounter,
                PDH_FMT_DOUBLE, &counterType, &counterValue) == ERROR_SUCCESS) {
                pdhCounters.lastNetworkSent = counterValue.doubleValue;
                cacheEntry.networkSent = pdhCounters.lastNetworkSent / (1024.0 * 1024.0); // Конвертируем в МБ/с
            }

            if (PdhGetFormattedCounterValue(pdhCounters.networkRecvCounter,
                PDH_FMT_DOUBLE, &counterType, &counterValue) == ERROR_SUCCESS) {
                pdhCounters.lastNetworkRecv = counterValue.doubleValue;
                cacheEntry.networkReceived = pdhCounters.lastNetworkRecv / (1024.0 * 1024.0); // Конвертируем в МБ/с
            }

            pdhCounters.lastUpdateTime = currentTime;
        }
    }

    CloseHandle(hProcess);
    cacheEntry.needsUpdate = false;
}

ProcessInfo ProcessMonitor::GetProcessInfo(DWORD processID) {
    ProcessInfo info = {};
    auto now = std::chrono::steady_clock::now();
    auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto& cacheEntry = processCache[processID];
        bool needUpdate = (nowMs - cacheEntry.lastUpdateTime) >= CACHE_TIMEOUT;

        if (needUpdate) {
            cacheEntry.needsUpdate = true;
            cacheEntry.lastUpdateTime = nowMs;
            
            // Асинхронное обновление данных
            threadPool->enqueue([processID]() {
                std::lock_guard<std::mutex> updateLock(cacheMutex);
                if (auto it = processCache.find(processID); it != processCache.end()) {
                    UpdateProcessData(processID, it->second);
                }
            });
        }

        // Возвращаем последние известные данные
        wcscpy_s(info.processName, cacheEntry.name.c_str());
        info.cpuUsage = cacheEntry.cpuData.lastCpuUsage;
        info.memoryUsage = cacheEntry.memoryUsage;
        info.diskReadRate = cacheEntry.diskReadRate;
        info.diskWriteRate = cacheEntry.diskWriteRate;
        info.networkSent = cacheEntry.networkSent;
        info.networkReceived = cacheEntry.networkReceived;
    }

    return info;
}

// Глобальная функция-обертка
static ProcessMonitor* g_monitor = nullptr;

extern "C" DLL2_API ProcessInfo __stdcall GetProcessInfo(DWORD processID) {
    if (!g_monitor) {
        g_monitor = new ProcessMonitor();
    }
    return g_monitor->GetProcessInfo(processID);
} 