
#include <string.h>

#include <windows.h>

#include "local_information.h"

#define VER_NT_WORKSTATION 1
#define SM_SERVERR2        89

typedef struct {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  TCHAR szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} OSVERSIONINFOEX_;

bool get_system_version(char* output_buffer) {
    OSVERSIONINFOEX_ system_info={0};
    system_info.dwOSVersionInfoSize=sizeof(system_info);
    if (GetVersionEx((LPOSVERSIONINFO)&system_info)) {
        if (VER_PLATFORM_WIN32_NT==system_info.dwPlatformId) {
            if (VER_NT_WORKSTATION==system_info.wProductType) {
                if (10==system_info.dwMajorVersion && 0==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows 10");
                    return true;
                } else if (6==system_info.dwMajorVersion && 3==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows 8.1");
                    return true;
                } else if (6==system_info.dwMajorVersion && 2==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows 8");
                    return true;
                } else if (6==system_info.dwMajorVersion && 1==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows 7");
                    return true;
                } else if (6==system_info.dwMajorVersion && 0==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows Vista");
                    return true;
                } else if (5==system_info.dwMajorVersion && 2==system_info.dwMinorVersion) {
                    if (GetSystemMetrics(SM_SERVERR2)) {
                        strcpy(output_buffer,"Windows Server 2003 R2");
                        return true;
                    } else {
                        strcpy(output_buffer,"Windows Server 2003");
                        return true;
                    }
                }
            } else {
                if (10==system_info.dwMajorVersion && 0==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows Server Technical Preview");
                    return true;
                } else if (6==system_info.dwMajorVersion && 3==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows Server 2012 R2");
                    return true;
                } else if (6==system_info.dwMajorVersion && 2==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows Server 2012");
                    return true;
                } else if (6==system_info.dwMajorVersion && 1==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows Server 2008 R2");
                    return true;
                } else if (6==system_info.dwMajorVersion && 0==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows Server 2008");
                    return true;
                } else if (5==system_info.dwMajorVersion && 1==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows XP");
                    return true;
                } else if (5==system_info.dwMajorVersion && 0==system_info.dwMinorVersion) {
                    strcpy(output_buffer,"Windows 2008");
                    return true;
                }
            }
        } else;  //  other platform
    }
    return false;
}
