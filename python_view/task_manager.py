import os
import sys
import time
import ctypes
import threading
import weakref
import getpass
from datetime import datetime
from collections import deque
from typing import Dict, List
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem, 
    QVBoxLayout, QHBoxLayout, QPushButton, QWidget, QHeaderView,
    QLabel, QTabWidget, QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPointF
from PyQt5.QtGui import QColor, QFont, QPainter
from PyQt5.QtChart import QChart, QChartView, QLineSeries, QValueAxis
from concurrent.futures import ThreadPoolExecutor

# Константы для доступа к процессам
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_TERMINATE = 0x0001

# Структуры для Windows API
class SYSTEM_PERFORMANCE_INFO(ctypes.Structure):
    _fields_ = [
        ("IdleTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
        ("Reserved1", ctypes.c_int64 * 2),
        ("IoReadTransferCount", ctypes.c_int64),
        ("IoWriteTransferCount", ctypes.c_int64),
        ("Reserved2", ctypes.c_int64 * 2),
        ("SystemCalls", ctypes.c_uint32),
    ]

class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t)
    ]

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD)
    ]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong)
    ]

class SystemMetrics:
    def __init__(self):
        self._setup_performance_counters()
        self._prev_cpu_times = self._get_cpu_times()
        self._prev_disk_counters = self._get_disk_counters()
        self._prev_net_counters = self._get_network_counters()
        self._process_times = {}
        self._process_io = {}  # Для хранения предыдущих значений IO
        
        # Загружаем DLL для мониторинга процессов
        try:
            if getattr(sys, 'frozen', False):
                # Если запущено как exe (PyInstaller)
                base_path = os.path.dirname(sys.executable)
            else:
                # Если запущено как Python скрипт
                base_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
            
            self.dll_path = os.path.join(base_path, "Dll2.dll")
            if not os.path.exists(self.dll_path):
                print(f"DLL not found at {self.dll_path}")
                raise FileNotFoundError(f"DLL not found at {self.dll_path}")
                
            self.process_dll = ctypes.WinDLL(self.dll_path)
            
            # Определяем структуру ProcessInfo из DLL
            class ProcessInfoStruct(ctypes.Structure):
                _fields_ = [
                    ("processName", ctypes.c_wchar * 260),
                    ("cpuUsage", ctypes.c_double),
                    ("memoryUsage", ctypes.c_size_t),
                    ("diskReadRate", ctypes.c_double),
                    ("diskWriteRate", ctypes.c_double),
                    ("networkSent", ctypes.c_double),
                    ("networkReceived", ctypes.c_double)
                ]
            
            # Настраиваем функцию GetProcessInfo
            self.process_dll.GetProcessInfo.argtypes = [ctypes.c_ulong]
            self.process_dll.GetProcessInfo.restype = ProcessInfoStruct
            self.ProcessInfoStruct = ProcessInfoStruct
            self.use_dll = True
        except Exception as e:
            print(f"Failed to load DLL: {e}")
            self.use_dll = False
        
    def _setup_performance_counters(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.psapi = ctypes.WinDLL('psapi', use_last_error=True)
        self.pdh = ctypes.WinDLL('pdh', use_last_error=True)
        
        # Настраиваем типы для функций
        self.kernel32.GetSystemTimes.argtypes = [
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME)
        ]
        self.kernel32.GetSystemTimes.restype = wintypes.BOOL
        
        self.kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
        self.kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
        
        # Добавляем определение для GetProcessMemoryInfo
        self.psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD
        ]
        self.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        # Добавляем определение для GetProcessIoCounters
        self.kernel32.GetProcessIoCounters.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(IO_COUNTERS)
        ]
        self.kernel32.GetProcessIoCounters.restype = wintypes.BOOL

    def _get_cpu_times(self) -> Dict[str, int]:
        idle_time = FILETIME()
        kernel_time = FILETIME()
        user_time = FILETIME()
        
        if not self.kernel32.GetSystemTimes(
            ctypes.byref(idle_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time)
        ):
            return {'idle': 0, 'kernel': 0, 'user': 0}
            
        return {
            'idle': (idle_time.dwHighDateTime << 32) | idle_time.dwLowDateTime,
            'kernel': (kernel_time.dwHighDateTime << 32) | kernel_time.dwLowDateTime,
            'user': (user_time.dwHighDateTime << 32) | user_time.dwLowDateTime
        }

    def get_cpu_usage(self) -> float:
        current = self._get_cpu_times()
        prev = self._prev_cpu_times
        
        idle_diff = current['idle'] - prev['idle']
        kernel_diff = current['kernel'] - prev['kernel']
        user_diff = current['user'] - prev['user']
        total_diff = kernel_diff + user_diff
        
        self._prev_cpu_times = current
        if total_diff > 0:
            return 100.0 * (1.0 - idle_diff / total_diff)
        return 0.0

    def get_memory_info(self) -> Dict[str, int]:
        meminfo = MEMORYSTATUSEX()
        meminfo.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        
        if not self.kernel32.GlobalMemoryStatusEx(ctypes.byref(meminfo)):
            return {'total': 0, 'available': 0, 'percent': 0}
            
        return {
            'total': meminfo.ullTotalPhys,
            'available': meminfo.ullAvailPhys,
            'percent': meminfo.dwMemoryLoad
        }

    def _get_disk_counters(self) -> Dict[str, int]:
        counters = {'read_bytes': 0, 'write_bytes': 0}
        try:
            # Используем Windows Performance Counters через ctypes
            query = ctypes.c_void_p()
            self.pdh.PdhOpenQueryW(None, 0, ctypes.byref(query))
            
            counter_read = ctypes.c_void_p()
            counter_write = ctypes.c_void_p()
            
            self.pdh.PdhAddCounterW(
                query,
                "\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                0,
                ctypes.byref(counter_read)
            )
            self.pdh.PdhAddCounterW(
                query,
                "\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                0,
                ctypes.byref(counter_write)
            )
            
            self.pdh.PdhCollectQueryData(query)
            
            value = wintypes.DWORD()
            self.pdh.PdhGetFormattedCounterValue(
                counter_read,
                0x00000100,  # PDH_FMT_LONG
                None,
                ctypes.byref(value)
            )
            counters['read_bytes'] = value.value
            
            self.pdh.PdhGetFormattedCounterValue(
                counter_write,
                0x00000100,  # PDH_FMT_LONG
                None,
                ctypes.byref(value)
            )
            counters['write_bytes'] = value.value
            
            self.pdh.PdhCloseQuery(query)
        except Exception:
            pass
        return counters

    def _get_network_counters(self) -> Dict[str, int]:
        counters = {'bytes_sent': 0, 'bytes_recv': 0}
        try:
            query = ctypes.c_void_p()
            self.pdh.PdhOpenQueryW(None, 0, ctypes.byref(query))
            
            counter_sent = ctypes.c_void_p()
            counter_recv = ctypes.c_void_p()
            
            self.pdh.PdhAddCounterW(
                query,
                "\\Network Interface(*)\\Bytes Sent/sec",
                0,
                ctypes.byref(counter_sent)
            )
            self.pdh.PdhAddCounterW(
                query,
                "\\Network Interface(*)\\Bytes Received/sec",
                0,
                ctypes.byref(counter_recv)
            )
            
            self.pdh.PdhCollectQueryData(query)
            
            value = wintypes.DWORD()
            self.pdh.PdhGetFormattedCounterValue(
                counter_sent,
                0x00000100,  # PDH_FMT_LONG
                None,
                ctypes.byref(value)
            )
            counters['bytes_sent'] = value.value
            
            self.pdh.PdhGetFormattedCounterValue(
                counter_recv,
                0x00000100,  # PDH_FMT_LONG
                None,
                ctypes.byref(value)
            )
            counters['bytes_recv'] = value.value
            
            self.pdh.PdhCloseQuery(query)
        except Exception:
            pass
        return counters

    def get_disk_io(self) -> Dict[str, float]:
        current = self._get_disk_counters()
        prev = self._prev_disk_counters
        time_diff = 1.0  # 1 second interval
        
        read_bytes = (current['read_bytes'] - prev['read_bytes']) / time_diff
        write_bytes = (current['write_bytes'] - prev['write_bytes']) / time_diff
        
        self._prev_disk_counters = current
        return {
            'read_bytes': read_bytes,
            'write_bytes': write_bytes
        }

    def get_network_io(self) -> Dict[str, float]:
        current = self._get_network_counters()
        prev = self._prev_net_counters
        time_diff = 1.0  # 1 second interval
        
        bytes_sent = (current['bytes_sent'] - prev['bytes_sent']) / time_diff
        bytes_recv = (current['bytes_recv'] - prev['bytes_recv']) / time_diff
        
        self._prev_net_counters = current
        return {
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv
        }

    def get_cpu_freq(self) -> Dict[str, float]:
        try:
            # Используем Windows Management API через ctypes
            freq = ctypes.c_uint64()
            if self.kernel32.QueryPerformanceFrequency(ctypes.byref(freq)):
                return {'current': freq.value / 1000000.0}  # Конвертируем в MHz
        except Exception:
            pass
        return {'current': 0.0}

    def get_boot_time(self) -> float:
        try:
            return self.kernel32.GetTickCount64() / 1000.0
        except Exception:
            return time.time()

    def get_process_io_counters(self, handle, pid) -> Dict[str, float]:
        """Получает информацию о дисковой и сетевой активности процесса"""
        io = IO_COUNTERS()
        current_time = time.time()
        
        if not self.kernel32.GetProcessIoCounters(handle, ctypes.byref(io)):
            return {
                'disk_read': 0.0,
                'disk_write': 0.0,
                'network_sent': 0.0,
                'network_recv': 0.0
            }
            
        current_io = {
            'time': current_time,
            'read': io.ReadTransferCount,
            'write': io.WriteTransferCount,
            'other': io.OtherTransferCount
        }
        
        if pid in self._process_io:
            prev_io = self._process_io[pid]
            time_diff = current_time - prev_io['time']
            
            if time_diff > 0:
                disk_read = (current_io['read'] - prev_io['read']) / time_diff
                disk_write = (current_io['write'] - prev_io['write']) / time_diff
                network = (current_io['other'] - prev_io['other']) / time_diff
                
                # Разделяем сетевой трафик поровну между отправкой и получением
                # так как Windows API не предоставляет точной информации
                network_half = network / 2
                
                self._process_io[pid] = current_io
                return {
                    'disk_read': disk_read,
                    'disk_write': disk_write,
                    'network_sent': network_half,
                    'network_recv': network_half
                }
        
        self._process_io[pid] = current_io
        return {
            'disk_read': 0.0,
            'disk_write': 0.0,
            'network_sent': 0.0,
            'network_recv': 0.0
        }

    def get_processes(self) -> List[Dict]:
        processes = []
        
        # Если DLL доступна, используем её для получения информации о процессах
        if hasattr(self, 'use_dll') and self.use_dll:
            try:
                process_ids = (wintypes.DWORD * 1024)()
                cb_needed = wintypes.DWORD()
                
                if not self.psapi.EnumProcesses(
                    ctypes.byref(process_ids),
                    ctypes.sizeof(process_ids),
                    ctypes.byref(cb_needed)
                ):
                    return processes
                    
                n_processes = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
                
                for i in range(n_processes):
                    try:
                        pid = process_ids[i]
                        if pid <= 0:
                            continue
                            
                        proc_info = self.process_dll.GetProcessInfo(pid)
                        
                        processes.append({
                            'pid': pid,
                            'name': proc_info.processName,
                            'cpu_percent': proc_info.cpuUsage,
                            'memory_info': {'rss': proc_info.memoryUsage},
                            'disk_read': proc_info.diskReadRate,
                            'disk_write': proc_info.diskWriteRate,
                            'network_sent': proc_info.networkSent,
                            'network_recv': proc_info.networkReceived
                        })
                    except:
                        continue
                
                return processes
            except:
                pass
        
        # Стандартный метод получения процессов (если DLL недоступна)
        process_ids = (wintypes.DWORD * 1024)()
        cb_needed = wintypes.DWORD()
        
        if not self.psapi.EnumProcesses(
            ctypes.byref(process_ids),
            ctypes.sizeof(process_ids),
            ctypes.byref(cb_needed)
        ):
            return processes
            
        n_processes = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
        current_time = time.time()
        
        for i in range(n_processes):
            try:
                pid = process_ids[i]
                if pid <= 0:
                    continue
                    
                handle = self.kernel32.OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    False,
                    pid
                )
                
                if not handle:
                    continue
                    
                try:
                    name_buffer = (ctypes.c_char * 260)()
                    if self.psapi.GetProcessImageFileNameA(handle, name_buffer, 260):
                        name = os.path.basename(name_buffer.value.decode('utf-8', errors='ignore'))
                    else:
                        continue
                        
                    creation_time = FILETIME()
                    exit_time = FILETIME()
                    kernel_time = FILETIME()
                    user_time = FILETIME()
                    
                    if self.kernel32.GetProcessTimes(
                        handle,
                        ctypes.byref(creation_time),
                        ctypes.byref(exit_time),
                        ctypes.byref(kernel_time),
                        ctypes.byref(user_time)
                    ):
                        kernel = ((kernel_time.dwHighDateTime << 32) | kernel_time.dwLowDateTime)
                        user = ((user_time.dwHighDateTime << 32) | user_time.dwLowDateTime)
                        
                        if pid in self._process_times:
                            old_time = self._process_times[pid]['time']
                            old_kernel = self._process_times[pid]['kernel']
                            old_user = self._process_times[pid]['user']
                            
                            time_diff = current_time - old_time
                            if time_diff > 0:
                                cpu_percent = ((kernel - old_kernel) + (user - old_user)) / (time_diff * 10000000)
                            else:
                                cpu_percent = 0
                        else:
                            cpu_percent = 0
                            
                        self._process_times[pid] = {
                            'time': current_time,
                            'kernel': kernel,
                            'user': user
                        }
                    else:
                        cpu_percent = 0
                        
                    pmc = PROCESS_MEMORY_COUNTERS()
                    pmc.cb = ctypes.sizeof(pmc)
                    if self.psapi.GetProcessMemoryInfo(
                        handle,
                        ctypes.byref(pmc),
                        ctypes.sizeof(pmc)
                    ):
                        memory = pmc.WorkingSetSize
                    else:
                        memory = 0
                        
                    io_info = self.get_process_io_counters(handle, pid)
                        
                    processes.append({
                        'pid': pid,
                        'name': name,
                        'cpu_percent': cpu_percent,
                        'memory_info': {'rss': memory},
                        'disk_read': io_info['disk_read'],
                        'disk_write': io_info['disk_write'],
                        'network_sent': io_info['network_sent'],
                        'network_recv': io_info['network_recv']
                    })
                    
                finally:
                    self.kernel32.CloseHandle(handle)
                    
            except:
                continue
        
        return processes

class DataCollector(QThread):
    data_updated = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._stop_flag = threading.Event()
        self.interval = 1.0
        self._cache = {}
        self._process_cache = {}
        self._cache_lock = threading.Lock()
        self._process_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._last_full_update = 0
        self._full_update_interval = 5.0
        self.metrics = SystemMetrics()
        
    def run(self):
        while not self._stop_flag.is_set():
            try:
                system_info = self.collect_system_info()
                self.data_updated.emit(system_info)
                time.sleep(max(0, self.interval - (time.time() % self.interval)))
            except Exception:
                continue
                
    def stop(self):
        self._stop_flag.set()
        self.executor.shutdown(wait=False)
        
    def collect_system_info(self) -> dict:
        current_time = time.time()
        
        with self._cache_lock:
            info = {
                'cpu_percent': self.metrics.get_cpu_usage(),
                'memory': self.metrics.get_memory_info(),
                'disk': self.metrics.get_disk_io(),
                'network': self.metrics.get_network_io(),
                'cpu_freq': self.metrics.get_cpu_freq(),
                'boot_time': self.metrics.get_boot_time(),
                'last_update': current_time,
                'processes': self.metrics.get_processes()  # Теперь это список процессов
            }
            
            self._cache = info
            return info

    def update_process_list(self, system_info: dict):
        processes = system_info.get('processes', [])
        if not processes:
            return
            
        # Создаем список процессов для отображения
        process_list = []
        for proc_info in processes:
            try:
                if not isinstance(proc_info, dict):
                    continue
                    
                name = proc_info.get('name', '')
                pid = proc_info.get('pid', 0)
                
                if not name or not pid:
                    continue
                    
                # Убираем цифры из скобок в имени процесса
                display_name = name
                
                cpu = proc_info.get('cpu_percent', 0.0)
                memory = proc_info.get('memory_info', {}).get('rss', 0) / (1024*1024)
                disk = (proc_info.get('disk_read', 0) + proc_info.get('disk_write', 0)) / (1024*1024)
                network = (proc_info.get('network_sent', 0) + proc_info.get('network_recv', 0)) / (1024*1024)
                
                process_list.append({
                    'pid': pid,
                    'name': display_name,
                    'cpu': cpu,
                    'memory': memory,
                    'disk': disk,
                    'network': network
                })
            except Exception:
                continue
                
        # Сортируем по использованию CPU
        process_list.sort(key=lambda x: x['cpu'], reverse=True)
        
        # Обновляем таблицу
        self.table.setRowCount(len(process_list))
        for row, proc in enumerate(process_list):
            try:
                items = [
                    (0, f"{proc['name']}", proc['name']),
                    (1, f"{proc['cpu']:.1f}%", proc['cpu']),
                    (2, f"{proc['memory']:.1f} МБ", proc['memory']),
                    (3, f"{proc['disk']:.1f} МБ/с", proc['disk']),
                    (4, f"{proc['network']:.1f} МБ/с", proc['network'])
                ]
                
                for col, text, value in items:
                    item = self.table.item(row, col)
                    if item is None:
                        item = NumericTableWidgetItem(text)
                        self.table.setItem(row, col, item)
                    elif item.text() != text:
                        item.setText(text)
                    item.setData(Qt.UserRole, value)
            except Exception:
                continue

class NumericTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        try:
            return float(self.data(Qt.UserRole)) < float(other.data(Qt.UserRole))
        except (ValueError, TypeError):
            return self.text() < other.text()

class PerformanceTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data_lock = threading.Lock()
        self._update_lock = threading.Lock()
        self.init_data()
        self.init_ui()
        
    def init_data(self):
        # Используем deque для эффективного управления размером списка
        self.values = {
            metric: deque(maxlen=60) 
            for metric in ['cpu', 'memory', 'disk', 'network']
        }
        self.current_metric = 'cpu'
        self._prev_values = {}
        self._last_update = 0
        self._update_interval = 0.5  # Обновление графика каждые 0.5 секунды
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Главный горизонтальный layout
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Левая панель с кнопками
        left_panel = QWidget()
        left_panel.setFixedWidth(200)
        left_panel.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
            }
        """)
        left_panel_layout = QVBoxLayout(left_panel)
        left_panel_layout.setContentsMargins(0, 0, 0, 0)
        left_panel_layout.setSpacing(0)
        
        # Создаем кнопки для переключения метрик
        self.metric_buttons = {}
        metrics = {
            'cpu': ('ЦП', '#1e1e1e', '#094771'),
            'memory': ('Память', '#1e1e1e', '#772940'),
            'disk': ('Диск', '#1e1e1e', '#2d5a27'),
            'network': ('Ethernet', '#1e1e1e', '#775209')
        }
        
        for metric, (label, bg_color, hover_color) in metrics.items():
            btn = QPushButton(label)
            btn.setFixedHeight(40)
            btn.setCheckable(True)
            btn.setFont(QFont('Segoe UI', 9))
            btn.clicked.connect(lambda checked, m=metric: self.switch_metric(m))
            btn.setStyleSheet(f"""
                QPushButton {{
                    text-align: left;
                    padding: 10px;
                    border: none;
                    background-color: {bg_color};
                    color: #ffffff;
                }}
                QPushButton:checked {{
                    background-color: {hover_color};
                }}
                QPushButton:hover:!checked {{
                    background-color: {hover_color};
                    opacity: 0.8;
                }}
            """)
            self.metric_buttons[metric] = btn
            left_panel_layout.addWidget(btn)
        
        left_panel_layout.addStretch()
        
        # Правая панель с графиком
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 10, 10, 10)
        
        # График
        self.chart = QChart()
        self.chart.setAnimationOptions(QChart.NoAnimation)
        self.chart.setBackgroundVisible(False)
        self.chart.legend().hide()
        self.chart.setTitle("ЦП")
        self.chart.setTitleFont(QFont('Segoe UI', 20))
        
        # Серия данных
        self.series = QLineSeries()
        pen = self.series.pen()
        pen.setWidth(2)
        pen.setColor(QColor("#3794ff"))
        self.series.setPen(pen)
        self.chart.addSeries(self.series)
        
        # Настройка осей
        self.axis_x = QValueAxis()
        self.axis_x.setRange(0, 60)
        self.axis_x.setVisible(True)
        self.axis_x.setLabelsVisible(True)
        self.axis_x.setGridLineVisible(True)
        self.axis_x.setMinorGridLineVisible(False)
        self.axis_x.setTitleText("Время (с)")
        self.axis_x.setLabelFormat("%d")
        
        self.axis_y = QValueAxis()
        self.axis_y.setRange(0, 100)
        self.axis_y.setVisible(True)
        self.axis_y.setLabelsVisible(True)
        self.axis_y.setGridLineVisible(True)
        self.axis_y.setMinorGridLineVisible(False)
        self.axis_y.setLabelFormat("%.1f")
        
        # Настройка цветов осей для темной темы
        grid_color = QColor("#333333")
        self.axis_x.setGridLineColor(grid_color)
        self.axis_y.setGridLineColor(grid_color)
        self.axis_x.setLabelsColor(QColor("#808080"))
        self.axis_y.setLabelsColor(QColor("#808080"))
        
        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)
        self.series.attachAxis(self.axis_x)
        self.series.attachAxis(self.axis_y)
        
        # Виджет графика
        chart_view = QChartView(self.chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
        right_layout.addWidget(chart_view)
        
        # Информационные метки
        info_widget = QWidget()
        self.info_layout = QGridLayout(info_widget)  # Сохраняем ссылку на layout
        self.info_layout.setContentsMargins(10, 10, 10, 10)
        self.info_layout.setSpacing(10)
        
        # Создаем метки в три колонки
        labels = [
            ("Использование", "19%"),
            ("Скорость", "2,79"),
            ("Процессы", "184"),
            ("Потоки", "2010"),
            ("Дескрипторы", "74108"),
            ("Время работы", "0:05:46:41")
        ]
        
        self.info_labels = {}  # Словарь для хранения меток
        for i, (label, value) in enumerate(labels):
            row = i // 3
            col = i % 3
            
            container = QWidget()
            container_layout = QVBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.setSpacing(5)
            
            value_label = QLabel(value)
            value_label.setFont(QFont('Segoe UI', 11))
            name_label = QLabel(label)
            name_label.setFont(QFont('Segoe UI', 9))
            name_label.setStyleSheet("color: #666666;")
            
            container_layout.addWidget(value_label)
            container_layout.addWidget(name_label)
            
            self.info_layout.addWidget(container, row, col)
            self.info_labels[label] = value_label  # Сохраняем ссылку на метку
        
        right_layout.addWidget(info_widget)
        
        # Добавляем панели в главный layout
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel, 1)
        
        layout.addLayout(main_layout)
        
        # Активируем первую кнопку
        self.metric_buttons['cpu'].setChecked(True)

    def switch_metric(self, metric):
        self.current_metric = metric
        for m, btn in self.metric_buttons.items():
            btn.setChecked(m == metric)
        
        # Обновляем цвет графика
        colors = {
            'cpu': '#3794ff',
            'memory': '#ff4a4a',
            'disk': '#4aff4a',
            'network': '#ffd700'
        }
        
        pen = self.series.pen()
        pen.setColor(QColor(colors[metric]))
        self.series.setPen(pen)
        
        # Обновляем заголовок и метки
        titles = {
            'cpu': ('ЦП', 'Использование (%)'),
            'memory': ('Память', 'Использование (%)'),
            'disk': ('Диск', 'МБ/с'),
            'network': ('Ethernet', 'МБ/с')
        }
        title, y_label = titles[metric]
        self.chart.setTitle(title)
        self.axis_y.setTitleText(y_label)
        
        # Устанавливаем диапазон оси Y в зависимости от метрики
        if metric in ['cpu', 'memory']:
            self.axis_y.setRange(0, 100)
        else:
            # Для диска и сети используем динамический диапазон
            values = list(self.values[metric])
            if values:
                max_value = max(values)
                if max_value <= 0.1:  # Если значения очень маленькие
                    self.axis_y.setRange(0, 1)
                else:
                    self.axis_y.setRange(0, max_value * 1.2)  # Добавляем 20% сверху
            else:
                self.axis_y.setRange(0, 10)  # Начальный диапазон
        
        # Обновляем данные графика
        self.update_chart()

    def update_chart(self):
        with self._update_lock:
            self.series.clear()
            values = list(self.values[self.current_metric])
            if not values:
                return
            
            # Обновляем диапазон оси Y для диска и сети
            if self.current_metric in ['disk', 'network']:
                max_value = max(values)
                if max_value <= 0.1:  # Если значения очень маленькие
                    self.axis_y.setRange(0, 1)
                elif max_value > self.axis_y.max():
                    self.axis_y.setRange(0, max_value * 1.2)
            
            # Добавляем точки на график
            points = [QPointF(i, v) for i, v in enumerate(values)]
            self.series.append(points)

    def update_data(self, system_info: dict):
        current_time = time.time()
        
        # Проверяем интервал обновления
        if current_time - self._last_update < self._update_interval:
            return
            
        with self._data_lock:
            metrics_data = self.calculate_metrics(system_info)
            
            # Обновляем значения для всех метрик
            for metric, value in metrics_data.items():
                self.values[metric].append(value)
            
            # Обновляем график если это текущая метрика
            if self.current_metric in metrics_data:
                self.update_chart()
                
            self.update_labels(system_info, metrics_data)
            self._last_update = current_time
            
    def calculate_metrics(self, system_info: dict) -> dict:
        metrics = {}
        
        # CPU
        metrics['cpu'] = system_info.get('cpu_percent', 0.0)
        
        # Память
        memory = system_info.get('memory', {})
        total_memory = memory.get('total', 1)
        used_memory = total_memory - memory.get('available', 0)
        metrics['memory'] = (
            (used_memory / total_memory) * 100 if total_memory > 0 else 0.0
        )
        
        # Получаем данные о диске напрямую из процессов
        total_disk_read = 0.0
        total_disk_write = 0.0
        total_net_sent = 0.0
        total_net_recv = 0.0
        
        for proc in system_info.get('processes', []):
            total_disk_read += proc.get('disk_read', 0)
            total_disk_write += proc.get('disk_write', 0)
            total_net_sent += proc.get('network_sent', 0)
            total_net_recv += proc.get('network_recv', 0)
        
        # Конвертируем в МБ/с
        metrics['disk'] = (total_disk_read + total_disk_write) / (1024 * 1024)
        metrics['network'] = (total_net_sent + total_net_recv) / (1024 * 1024)
        
        return metrics

    def update_labels(self, system_info: dict, metrics_data: dict):
        with self._update_lock:
            # Обновляем метки
            new_values = {
                'Использование': f"{metrics_data.get('cpu', 0):.1f}%",
                'Скорость': (
                    f"{system_info.get('cpu_freq', {}).get('current', 0) / 1000:.1f} GHz"
                    if system_info.get('cpu_freq') else "N/A"
                ),
                'Процессы': str(len(system_info.get('processes', []))),
                'Потоки': str(sum(1 for p in system_info.get('processes', []))),
                'Дескрипторы': str(sum(1 for p in system_info.get('processes', []))),
                'Время работы': self._format_uptime(system_info.get('boot_time', 0))
            }
            
            # Обновляем только изменившиеся значения
            for label, value in new_values.items():
                if label in self.info_labels:
                    current = self.info_labels[label].text()
                    if current != value:
                        self.info_labels[label].setText(value)

    def _format_uptime(self, boot_time):
        if not boot_time:
            return "00:00:00"
        uptime = datetime.now() - datetime.fromtimestamp(boot_time)
        total_seconds = int(uptime.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

class UsersTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.prev_disk_bytes = {}
        self.prev_net_bytes = {}
        self.last_update = time.time()
        self.user_cache = {}
        self.username_cache = {}
        self.metrics = SystemMetrics()
        self._current_username = getpass.getuser()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Создаем таблицу пользователей
        self.table = QTableWidget()
        self.table.setFont(QFont('Segoe UI', 9))
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Пользователь", "ЦП", "Память", "Диск", "Сеть"
        ])

        # Настройка таблицы
        header = self.table.horizontalHeader()
        header.setFont(QFont('Segoe UI', 9))
        for i in range(5):
            header.setSectionResizeMode(i, QHeaderView.Stretch)

        layout.addWidget(self.table)

    def get_process_username(self, pid):
        return self._current_username

    def update_data(self, system_info):
        current_time = time.time()
        if current_time - self.last_update < 1.0:  # Обновляем раз в секунду
            return

        self.last_update = current_time
        
        # Инициализируем статистику пользователя
        user_stats = {
            self._current_username: {
                'cpu': 0.0,
                'memory': 0,
                'disk': 0.0,
                'network': 0.0
            }
        }

        # Собираем данные со всех процессов
        total_disk_read = 0.0
        total_disk_write = 0.0
        total_net_sent = 0.0
        total_net_recv = 0.0
        
        for proc_info in system_info.get('processes', []):
            try:
                # Суммируем CPU и память
                user_stats[self._current_username]['cpu'] += (
                    proc_info.get('cpu_percent', 0)
                )
                user_stats[self._current_username]['memory'] += (
                    proc_info.get('memory_info', {}).get('rss', 0)
                )
                
                # Суммируем диск и сеть
                total_disk_read += proc_info.get('disk_read', 0)
                total_disk_write += proc_info.get('disk_write', 0)
                total_net_sent += proc_info.get('network_sent', 0)
                total_net_recv += proc_info.get('network_recv', 0)
            except:
                continue

        # Конвертируем память в МБ
        user_stats[self._current_username]['memory'] /= (1024 * 1024)
        
        # Конвертируем диск и сеть в МБ/с
        disk_total = (total_disk_read + total_disk_write) / (1024 * 1024)
        net_total = (total_net_sent + total_net_recv) / (1024 * 1024)
        user_stats[self._current_username]['disk'] = disk_total
        user_stats[self._current_username]['network'] = net_total

        # Обновляем таблицу
        self.update_table(user_stats)

    def update_table(self, user_stats):
        self.table.setRowCount(len(user_stats))
        for row, (username, stats) in enumerate(user_stats.items()):
            items = [
                (0, username),
                (1, f"{stats['cpu']:.1f}%"),
                (2, f"{stats['memory']:.1f} МБ"),
                (3, f"{stats['disk']:.1f} МБ/с"),
                (4, f"{stats['network']:.1f} МБ/с")
            ]
            
            for col, value in items:
                item = self.table.item(row, col)
                if item is None:
                    item = QTableWidgetItem(value)
                    self.table.setItem(row, col, item)
                elif item.text() != value:
                    item.setText(value)

class TaskManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.is_dark_theme = False
        self.process_cache = weakref.WeakValueDictionary()
        self.user_cache = {}
        self.last_full_update = 0
        self.update_interval = 2.0
        self.full_update_interval = 10.0
        self.last_process_update = 0
        self.process_update_interval = 1.0
        self.metrics = SystemMetrics()
        self.setup_collector()
        self.init_ui()
        
    def setup_collector(self):
        self.collector = DataCollector(self)
        self.collector.data_updated.connect(self.update_data)
        self.collector.start()
        
    def closeEvent(self, event):
        self.collector.stop()
        super().closeEvent(event)
        
    def init_ui(self):
        self.setWindowTitle("Диспетчер задач")
        self.setGeometry(100, 100, 1000, 600)
        self.sort_column = 0
        self.sort_order = Qt.AscendingOrder

        # Создание центрального виджета
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Создание вкладок
        self.tab_widget = QTabWidget()
        self.tab_widget.setFont(QFont('Segoe UI', 10))
        
        # Вкладка процессов
        process_tab = QWidget()
        process_layout = QVBoxLayout(process_tab)

        # Создание таблицы
        self.table = QTableWidget()
        self.table.setFont(QFont('Segoe UI', 9))
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Имя", "ЦП", "Память", "Диск", "Сеть"
        ])
        
        # Настройка таблицы
        header = self.table.horizontalHeader()
        header.sectionClicked.connect(self.on_header_clicked)
        header.setFont(QFont('Segoe UI', 9))
        for i in range(5):
            header.setSectionResizeMode(i, QHeaderView.Stretch)
        
        # Нижняя панель с кнопками
        bottom_panel = QWidget()
        bottom_layout = QHBoxLayout(bottom_panel)
        
        # Кнопка смены темы
        self.theme_button = QPushButton("🌙 Темная тема")
        self.theme_button.setFont(QFont('Segoe UI', 9))
        self.theme_button.clicked.connect(self.toggle_theme)
        
        # Кнопка "Снять задачу"
        kill_button = QPushButton("Снять задачу")
        kill_button.setFont(QFont('Segoe UI', 9))
        kill_button.clicked.connect(self.kill_selected_process)
        
        bottom_layout.addWidget(self.theme_button)
        bottom_layout.addStretch()
        bottom_layout.addWidget(kill_button)
        
        process_layout.addWidget(self.table)
        process_layout.addWidget(bottom_panel)
        
        # Вкладка производительности
        self.performance_tab = PerformanceTab()
        
        # Вкладка пользователей
        self.users_tab = UsersTab()
        
        # Добавление вкладок
        self.tab_widget.addTab(process_tab, "ПРОЦЕССЫ")
        self.tab_widget.addTab(self.performance_tab, "ПРОИЗВОДИТЕЛЬНОСТЬ")
        self.tab_widget.addTab(self.users_tab, "ПОЛЬЗОВАТЕЛИ")
        
        main_layout.addWidget(self.tab_widget)

        # Применяем тему
        self.apply_theme()
        
        # Инициализируем пустую таблицу
        self.table.setRowCount(0)

    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        self.theme_button.setText("☀️" if self.is_dark_theme else "🌙")
        self.apply_theme()

    def apply_theme(self):
        if self.is_dark_theme:
            self.theme_button.setText("☀️")
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #1e1e1e;
                    color: #ffffff;
                }
                QTableWidget {
                    background-color: #1e1e1e;
                    color: #ffffff;
                    gridline-color: #333333;
                    border: none;
                }
                QTableWidget::item {
                    padding: 5px;
                    border-bottom: 1px solid #333333;
                }
                QTableWidget::item:selected {
                    background-color: #094771;
                    color: #ffffff;
                }
                QHeaderView::section {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    padding: 5px;
                    border: none;
                    border-right: 1px solid #333333;
                    border-bottom: 1px solid #333333;
                }
                QPushButton {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: 1px solid #3d3d3d;
                    padding: 5px 10px;
                    border-radius: 2px;
                }
                QPushButton:hover {
                    background-color: #3d3d3d;
                }
                QTabWidget::pane {
                    border-top: 1px solid #333333;
                    background-color: #1e1e1e;
                }
                QTabBar::tab {
                    background-color: #2d2d2d;
                    color: #ffffff;
                    border: none;
                    padding: 8px 20px;
                    min-width: 150px;
                }
                QTabBar::tab:selected {
                    background-color: #1e1e1e;
                    border-top: 1px solid #333333;
                    border-right: 1px solid #333333;
                    border-left: 1px solid #333333;
                }
                QTabBar::tab:hover:!selected {
                    background-color: #3d3d3d;
                }
                QChartView {
                    background-color: #1e1e1e;
                }
            """)
            self.performance_tab.chart.setBackgroundBrush(QColor("#1e1e1e"))
            self.performance_tab.chart.setTitleBrush(QColor("#ffffff"))
            self.performance_tab.axis_y.setLabelsBrush(QColor("#ffffff"))
            self.performance_tab.axis_y.setTitleBrush(QColor("#ffffff"))
            
            # Обновляем стили для левой панели в PerformanceTab
            metrics_dark = {
                'cpu': ('#1e1e1e', '#094771'),
                'memory': ('#1e1e1e', '#772940'),
                'disk': ('#1e1e1e', '#2d5a27'),
                'network': ('#1e1e1e', '#775209')
            }
            
            for metric, (bg_color, hover_color) in metrics_dark.items():
                if metric in self.performance_tab.metric_buttons:
                    btn = self.performance_tab.metric_buttons[metric]
                    btn.setStyleSheet(f"""
                        QPushButton {{
                            text-align: left;
                            padding: 10px;
                            border: none;
                            background-color: {bg_color};
                            color: #ffffff;
                        }}
                        QPushButton:checked {{
                            background-color: {hover_color};
                        }}
                        QPushButton:hover:!checked {{
                            background-color: {hover_color};
                            opacity: 0.8;
                        }}
                    """)
            
            # Обновляем цвет графика
            pen = self.performance_tab.series.pen()
            pen.setColor(QColor("#3794ff"))
            self.performance_tab.series.setPen(pen)
            
            # Обновляем стили для информационных меток
            for i in range(self.performance_tab.info_layout.count()):
                widget = self.performance_tab.info_layout.itemAt(i).widget()
                if widget:
                    widget.setStyleSheet("""
                        QLabel {
                            color: #ffffff;
                        }
                        QLabel[class="info-name"] {
                            color: #808080;
                        }
                    """)
        else:
            # Оставляем существующие стили для светлой темы
            self.theme_button.setText("🌙")
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #f0f0f0;
                    color: #000000;
                }
                QTableWidget {
                    background-color: #ffffff;
                    color: #000000;
                    gridline-color: #e0e0e0;
                    border: none;
                }
                QTableWidget::item {
                    padding: 5px;
                    border-bottom: 1px solid #e0e0e0;
                }
                QTableWidget::item:selected {
                    background-color: #cce8ff;
                    color: #000000;
                }
                QHeaderView::section {
                    background-color: #f5f5f5;
                    color: #000000;
                    padding: 5px;
                    border: none;
                    border-right: 1px solid #e0e0e0;
                    border-bottom: 1px solid #e0e0e0;
                }
                QPushButton {
                    background-color: #ffffff;
                    color: #000000;
                    border: 1px solid #e0e0e0;
                    padding: 5px 10px;
                    border-radius: 2px;
                }
                QPushButton:hover {
                    background-color: #f5f5f5;
                }
                QTabWidget::pane {
                    border-top: 1px solid #e0e0e0;
                }
                QTabBar::tab {
                    background-color: #f5f5f5;
                    color: #000000;
                    border: none;
                    padding: 8px 20px;
                    min-width: 150px;
                }
                QTabBar::tab:selected {
                    background-color: #ffffff;
                    border-top: 1px solid #e0e0e0;
                    border-right: 1px solid #e0e0e0;
                    border-left: 1px solid #e0e0e0;
                }
                QTabBar::tab:hover:!selected {
                    background-color: #e0e0e0;
                }
            """)

    def on_header_clicked(self, logical_index):
        if self.sort_column == logical_index:
            self.sort_order = Qt.DescendingOrder if self.sort_order == Qt.AscendingOrder else Qt.AscendingOrder
        else:
            self.sort_column = logical_index
            self.sort_order = Qt.AscendingOrder
        self.table.sortItems(self.sort_column, self.sort_order)

    def update_process_list(self, system_info: dict):
        processes = system_info.get('processes', [])
        if not processes:
            return
            
        # Создаем список процессов для отображения
        process_list = []
        for proc_info in processes:
            try:
                if not isinstance(proc_info, dict):
                    continue
                    
                name = proc_info.get('name', '')
                pid = proc_info.get('pid', 0)
                
                if not name or not pid:
                    continue
                    
                # Убираем цифры из скобок в имени процесса
                display_name = name
                
                cpu = proc_info.get('cpu_percent', 0.0)
                memory = proc_info.get('memory_info', {}).get('rss', 0) / (1024*1024)
                disk = (proc_info.get('disk_read', 0) + proc_info.get('disk_write', 0)) / (1024*1024)
                network = (proc_info.get('network_sent', 0) + proc_info.get('network_recv', 0)) / (1024*1024)
                
                process_list.append({
                    'pid': pid,
                    'name': display_name,
                    'cpu': cpu,
                    'memory': memory,
                    'disk': disk,
                    'network': network
                })
            except Exception:
                continue
                
        # Сортируем по использованию CPU
        process_list.sort(key=lambda x: x['cpu'], reverse=True)
        
        # Обновляем таблицу
        self.table.setRowCount(len(process_list))
        for row, proc in enumerate(process_list):
            try:
                items = [
                    (0, f"{proc['name']}", proc['name']),
                    (1, f"{proc['cpu']:.1f}%", proc['cpu']),
                    (2, f"{proc['memory']:.1f} МБ", proc['memory']),
                    (3, f"{proc['disk']:.1f} МБ/с", proc['disk']),
                    (4, f"{proc['network']:.1f} МБ/с", proc['network'])
                ]
                
                for col, text, value in items:
                    item = self.table.item(row, col)
                    if item is None:
                        item = NumericTableWidgetItem(text)
                        self.table.setItem(row, col, item)
                    elif item.text() != text:
                        item.setText(text)
                    item.setData(Qt.UserRole, value)
            except Exception:
                continue

    def kill_selected_process(self):
        selected_items = self.table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            pid = int(self.table.item(row, 0).text().split()[0])
            try:
                handle = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_TERMINATE, False, pid
                )
                if handle:
                    ctypes.windll.kernel32.TerminateProcess(handle, -1)
                    ctypes.windll.kernel32.CloseHandle(handle)
            except Exception:
                pass

    def update_data(self, system_info: dict):
        # Обновляем все вкладки с новыми данными
        self.performance_tab.update_data(system_info)
        self.users_tab.update_data(system_info)
        self.update_process_list(system_info)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = TaskManagerWindow()
    window.show()
    sys.exit(app.exec_())
