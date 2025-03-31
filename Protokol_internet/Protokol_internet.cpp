#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <windows.h>
#include <sstream>
#include <algorithm>

using namespace std;
void initConsole() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, "Russian");
}

vector<string> executeCommand(const string& cmd) {
    vector<string> output;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return output;
    }

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES;

    string command = "cmd.exe /c " + cmd + " 2>nul";

    if (!CreateProcessA(NULL, (LPSTR)command.c_str(), NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return output;
    }

    CloseHandle(hWritePipe);

    char buffer[4096];
    DWORD bytesRead;
    string result;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        result.append(buffer, bytesRead);
    }

    stringstream ss(result);
    string line;
    while (getline(ss, line)) {
        if (!line.empty()) {
            output.push_back(line);
        }
    }

    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

/*
Проверка, является ли IP-адрес приватным (внутренним)
 @param ip Проверяемый IP-адрес
 @return true если адрес приватный, false если публичный
 */
bool isPrivateIP(const string& ip) {
    try {
        // проверка приватных IP
        if (ip.compare(0, 3, "10.") == 0 ||
            ip.compare(0, 4, "172.") == 0 ||
            ip.compare(0, 8, "192.168.") == 0 ||
            ip.compare(0, 4, "127.") == 0 ||
            ip.compare(0, 8, "169.254.") == 0) {
            return true;
        }

        //проверка для 172.16-31.x.x
        if (ip.compare(0, 4, "172.") == 0) {
            size_t pos = ip.find('.', 4);
            if (pos != string::npos) {
                int second = stoi(ip.substr(4, pos - 4));
                if (second >= 16 && second <= 31) {
                    return true;
                }
            }
        }
    }
    catch (...) {
        // В случае ошибки считаем IP не приватным
        return false;
    }
    return false;
}

/*
 Получение номера автономной системы (AS) для IP-адреса
 @param ip IP-адрес для проверки
 @return Строка с номером AS или "Private"/"Unknown"
 */
string getASNumber(const string& ip) {
    if (isPrivateIP(ip)) {
        return "Private";
    }

    try {
        auto whoisOutput = executeCommand("whois " + ip);
        regex asPattern(R"(origin:\s*AS(\d+))", regex_constants::icase);
        smatch match;

        for (const auto& line : whoisOutput) {
            if (regex_search(line, match, asPattern)) {
                return "AS" + match[1].str();
            }
        }
    }
    catch (const regex_error& e) {
        cerr << "Ошибка регулярного выражения: " << e.what() << endl;
    }
    catch (...) {
        cerr << "Неизвестная ошибка при обработке whois" << endl;
    }

    return "Unknown";
}

int main() {
    initConsole();

    cout << "Трассировка автономных систем" << endl;
    cout << "Введите домен или IP: ";

    string target;
    getline(cin, target);
    if (target.empty()) {
        target = "google.com";
    }

    try {
        auto tracertResult = executeCommand("tracert -d " + target);
        regex ipRegex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
        vector<string> ipList;

        for (const auto& line : tracertResult) {
            smatch match;
            if (regex_search(line, match, ipRegex)) {
                string ip = match[0];
                if (find(ipList.begin(), ipList.end(), ip) == ipList.end()) {
                    ipList.push_back(ip);
                }
            }
        }

        cout << "\n+-----+-----------------+---------------+" << endl;
        cout << "|  №  | IP-адрес        | AS номер      |" << endl;
        cout << "+-----+-----------------+---------------+" << endl;

        for (size_t i = 0; i < ipList.size(); ++i) {
            string asNumber = getASNumber(ipList[i]);
            cout << "| " << i + 1 << "\t| " << ipList[i] << "\t| " << asNumber << "\t|" << endl;
        }

        cout << "+-----+-----------------+---------------+" << endl;
    }
    catch (const regex_error& e) {
        cerr << "Ошибка в регулярном выражении: " << e.what() << endl;
        return 1;
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    catch (...) {
        cerr << "Неизвестная ошибка" << endl;
        return 1;
    }

    return 0;
}
