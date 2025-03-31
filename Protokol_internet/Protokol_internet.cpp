#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <windows.h>
using namespace std;

void setConsoleToUTF8() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

// Функция для выполнения системной команды и получения вывода
vector<string> executeCommand(const wstring& command) {
    vector<string> output;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        cerr << "CreatePipe failed!" << endl;
        return output;
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    // Преобразуем команду в широкую строку (LPWSTR)
    wchar_t* cmd = const_cast<wchar_t*>(command.c_str());

    if (!CreateProcess(
        NULL, // Приложение
        cmd,  // Командная строка
        NULL, // Атрибуты процесса
        NULL, // Атрибуты потока
        TRUE, // Наследование дескрипторов
        0,    // Флаги создания
        NULL, // Окружение
        NULL, // Текущий каталог
        &si,  // STARTUPINFO
        &pi   // PROCESS_INFORMATION
    )) {
        DWORD error = GetLastError();
        cerr << "CreateProcess failed! Error code: " << error << endl;
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return output;
    }

    CloseHandle(hWritePipe);

    char buffer[128];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        output.push_back(string(buffer, bytesRead));
    }

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

// Функция для получения номера автономной системы по IP-адресу
string getASNumber(const string& ip) {
    // Используем whois для получения информации об IP-адресе
    wstring command = L"whois " + wstring(ip.begin(), ip.end()) + L" | findstr \"origin:\"";
    auto output = executeCommand(command);
    if (!output.empty()) {
        return output[0];
    }
    return "Unknown";
}

int main() {
    setConsoleToUTF8();
    setlocale(0, "");

    string domain;
    cout << "Введите доменное имя или IP-адрес: ";
    cin >> domain;

    // Выполняем команду tracert
    wstring command = L"tracert " + wstring(domain.begin(), domain.end());
    auto tracertOutput = executeCommand(command);

    // Регулярное выражение для поиска IP-адресов
    regex ipRegex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
    smatch match;

    // Выводим заголовок таблицы
    cout << "| № по порядку | IP    | AS    |\n";
    cout << "|---|---|---|\n";

    int count = 1;
    for (const auto& line : tracertOutput) {
        if (regex_search(line, match, ipRegex)) {
            string ip = match.str(0);
            string asNumber = getASNumber(ip);
            cout << "| " << count++ << " | " << ip << " | " << asNumber << " |\n";
        }
    }

    return 0;
}
