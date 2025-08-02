#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <wintrust.h>
#include <Softpub.h>
#include <Shlwapi.h>
#include <conio.h>
#include <iomanip>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "shlwapi.lib")

struct DllInfo {
    DWORD pid;
    std::wstring processName;
    std::wstring dllName;
    bool hasSignature;
    bool isSuspect;
};

bool isDllSuspicious(const std::wstring& dllName) {
    std::wstring lowerDll = dllName;
    CharLowerBuff(&lowerDll[0], (DWORD)lowerDll.size());

    // Palavras suspeitas comuns em cheats
    const std::vector<std::wstring> suspiciousWords = {
        L"cheat", L"hack", L"inject", L"aimbot", L"wallhack", L"suspect", L"phantom", L"ghost", L"exploit"
    };

    for (const auto& word : suspiciousWords) {
        if (lowerDll.find(word) != std::wstring::npos)
            return true;
    }
    return false;
}

bool verifySignature(const std::wstring& filePath) {
    LONG lStatus;
    DWORD dwLastError;

    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = 0;
    winTrustData.hWVTStateData = NULL;
    winTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    winTrustData.dwUIContext = 0;

    lStatus = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    return (lStatus == ERROR_SUCCESS);
}

std::vector<DllInfo> scanProcesses() {
    std::vector<DllInfo> results;

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Erro ao criar snapshot de processos.\n";
        return results;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        std::wcerr << L"Erro ao obter primeiro processo.\n";
        return results;
    }

    std::vector<PROCESSENTRY32> processos;

    do {
        processos.push_back(pe32);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    int total = (int)processos.size();
    int current = 0;

    for (auto& proc : processos) {
        current++;
        std::wcout << L"\rEscaneando processos... " << current << L"/" << total << L" (" << (current * 100 / total) << L"%)   ";

        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc.th32ProcessID);
        if (hModuleSnap == INVALID_HANDLE_VALUE) continue;

        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hModuleSnap, &me32)) {
            do {
                std::wstring dllPath = me32.szExePath;
                bool hasSig = verifySignature(dllPath);
                bool suspect = isDllSuspicious(me32.szModule);

                DllInfo info;
                info.pid = proc.th32ProcessID;
                info.processName = proc.szExeFile;
                info.dllName = me32.szModule;
                info.hasSignature = hasSig;
                info.isSuspect = suspect;

                results.push_back(info);

            } while (Module32Next(hModuleSnap, &me32));
        }
        CloseHandle(hModuleSnap);
    }

    std::wcout << L"\nEscaneamento finalizado.\n";
    return results;
}

void printColored(const std::wstring& text, int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
    std::wcout << text;
    SetConsoleTextAttribute(hConsole, 7);
}

void showResults(const std::vector<DllInfo>& results) {
    std::wcout << L"\n===== RESULTADOS =====\n";

    for (const auto& dll : results) {
        if (dll.isSuspect) {
            printColored(L"[SUSPEITA] ", FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::wcout << dll.dllName;
        }
        else if (!dll.hasSignature) {
            printColored(L"[ASSINATURA INVÁLIDA] ", FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::wcout << dll.dllName;
        }
        else {
            printColored(L"[OK] ", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << dll.dllName;
        }

        std::wcout << L" (PID: " << dll.pid << L", Processo: " << dll.processName << L")\n";
    }
}

void printMenu() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"===== PHANTOM TOOL DLL =====\n";

    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::wcout << L"1 - Escanear todos os processos\n";

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"2 - Ver resultados\n";

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"3 - Sair\n";

    SetConsoleTextAttribute(hConsole, 7);
}

int main() {
    system("cls");
    SetConsoleTitle(L"Phamtom Tool DLL - Scanner de DLLs");

    std::vector<DllInfo> scanResults;
    int choice = 0;

    do {
        printMenu();
        std::wcout << L"\nEscolha: ";
        std::wcin >> choice;

        switch (choice) {
        case 1:
            scanResults = scanProcesses();
            break;
        case 2:
            if (scanResults.empty()) {
                std::wcout << L"Nenhum resultado. Faça o scan primeiro.\n";
            }
            else {
                showResults(scanResults);
            }
            break;
        case 3:
            std::wcout << L"Saindo...\n";
            break;
        default:
            std::wcout << L"Opção inválida.\n";
            break;
        }
    } while (choice != 3);

    return 0;
}
