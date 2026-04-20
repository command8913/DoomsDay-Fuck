#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>

using namespace std;

struct Proc { DWORD pid; wstring path; };

vector<Proc> getJavaws() {
    vector<Proc> r;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return r;

    PROCESSENTRY32W p{sizeof(p)};
    for (Process32FirstW(s, &p); Process32NextW(s, &p);) {
        if (_wcsicmp(p.szExeFile, L"javaw.exe")) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, p.th32ProcessID);
        if (!h) continue;
        wchar_t buf[MAX_PATH]; DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(h, 0, buf, &sz) && (r.push_back({p.th32ProcessID, buf}), 0);
        CloseHandle(h);
    }
    CloseHandle(s);
    return r;
}

bool weird(string_view s) {
    return any_of(s.begin(), s.end(), [](auto c){ return c<32||c>126; });
}

bool scanMem(DWORD pid, string_view pat) {
    HANDLE h = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, 0, pid);
    if (!h) return 0;

    SYSTEM_INFO si; GetSystemInfo(&si);
    auto a = (UCHAR*)si.lpMinimumApplicationAddress, end = (UCHAR*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION m;
    vector<char> buf;

    while (a < end) {
        if (!VirtualQueryEx(h, a, &m, sizeof(m))) { a += 4096; continue; }
        if (m.State==MEM_COMMIT && !(m.Protect&(PAGE_GUARD|PAGE_NOACCESS))) {
            buf.resize(max(buf.size(), m.RegionSize));
            SIZE_T rd;
            if (ReadProcessMemory(h, a, buf.data(), m.RegionSize, &rd) &&
                string_view(buf.data(), rd).find(pat) != string_view::npos) {
                CloseHandle(h);
                return 1;
            }
        }
        a += m.RegionSize;
    }
    CloseHandle(h);
    return 0;
}

int checkJmap(const Proc& p) {
    auto pos = p.path.find_last_of(L"\\/");
    if (pos == wstring::npos) return 0;
    wstring jmap = p.path.substr(0, pos) + L"\\jmap.exe";
    if (!filesystem::exists(jmap)) return 0;

    FILE* pipe = _wpopen((L'"' + jmap + L"\" -clstats " + to_wstring(p.pid)).c_str(), L"rb");
    if (!pipe) return 0;

    char buf[2048];
    while (fgets(buf, sizeof(buf), pipe)) {
        string_view l(buf);
        if (l.find("not recognized") != string_view::npos ||
            l.find("не является внутренней") != string_view::npos) continue;
        if (l.find('/') != string_view::npos && l.find("0x") != string_view::npos && weird(l)) {
            _pclose(pipe);
            return 1;
        }
    }
    _pclose(pipe);
    return 0;
}

int main() {
    ios::sync_with_stdio(0);
    printf("Scan:\n");

    auto procs = getJavaws();
    if (procs.empty()) return printf("[-] No javaw.exe processes found\n"), 0;

    const char* msg[] = {"Clean", "DoomsDay Fuck #1", "DoomsDay Fuck #2", "DoomsDay Fuck #3", "DoomsDay Fuck #4"};
    string_view sig[] = {"", "", "OgUwQPNl", "CQauDfNVDeQv_xfM`Bn", "IZn]laU"};

    for (auto& p : procs) {
        int d = checkJmap(p) ? 1 : scanMem(p.pid, sig[2]) ? 2 : scanMem(p.pid, sig[3]) ? 3 : scanMem(p.pid, sig[4]) ? 4 : 0;
        printf("[%s] PID: %lu - %s\n", d ? "+" : "-", p.pid, msg[d]);
    }
}
