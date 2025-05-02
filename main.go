package main

import (
	"fmt"
	"log"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	EVENTLOG_BACKWARDS_READ     = 0x0008
	EVENTLOG_SEQUENTIAL_READ    = 0x0001
	EVENT_ID_SHUTDOWN_CLEAN     = 6006
	EVENT_ID_SHUTDOWN_NOT_CLEAN = 6008
)

type eventLogRecord struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated       uint32
	TimeWritten         uint32
	EventID             uint32
	EventType           uint16
	NumStrings          uint16
	EventCategory       uint16
	ReservedFlags       uint16
	ClosingRecordNumber uint32
	StringOffset        uint32
	UserSidLength       uint32
	UserSidOffset       uint32
	DataLength          uint32
	DataOffset          uint32
}

func main() {
	setHighPriority()

	lastShutdown, err := getLastShutdownTime()
	if err != nil {
		log.Fatalf("Error getting the last shutdown time: %v", err)
	}
	fmt.Printf("Last shutdown: %s\n", lastShutdown.Format("2006-01-02 15:04:05"))

	if tooLate(lastShutdown) {
		//testActionFunc()
		takeAction()
	}
}

func openEventLog(serverName, sourceName *uint16) (syscall.Handle, error) {
	modadvapi32 := syscall.NewLazyDLL("advapi32.dll")
	procOpenEventLog := modadvapi32.NewProc("OpenEventLogW")

	handle, _, err := procOpenEventLog.Call(
		uintptr(unsafe.Pointer(serverName)),
		uintptr(unsafe.Pointer(sourceName)),
	)
	if handle == 0 {
		return 0, fmt.Errorf("error opening the event log: %w", err)
	}
	return syscall.Handle(handle), nil
}

func readEventLog(handle syscall.Handle, flags, recordOffset uint32, buffer []byte) (uint32, uint32, error) {
	modadvapi32 := syscall.NewLazyDLL("advapi32.dll")
	procReadEventLog := modadvapi32.NewProc("ReadEventLogW")

	var bytesRead, minBytesNeeded uint32
	ret, _, err := procReadEventLog.Call(
		uintptr(handle),
		uintptr(flags),
		uintptr(recordOffset),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&minBytesNeeded)),
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("error reading the event log: %w", err)
	}
	return bytesRead, minBytesNeeded, nil
}

func getLastShutdownTime() (time.Time, error) {
	ptrFmStr, err := syscall.UTF16PtrFromString("System")
	if err != nil {
		return time.Time{}, err
	}

	handle, err := openEventLog(nil, ptrFmStr)
	if err != nil {
		return time.Time{}, err
	}
	//defer syscall.CloseHandle(handle) // this has to be commented when debugging, if not, causes problems

	buffer := make([]byte, 65536)
	for {
		bytesRead, _, err := readEventLog(handle, EVENTLOG_BACKWARDS_READ|EVENTLOG_SEQUENTIAL_READ, 0, buffer)
		if err != nil {
			return time.Time{}, err
		}
		if bytesRead == 0 {
			break
		}

		offset := 0
		for offset < int(bytesRead) {
			record := (*eventLogRecord)(unsafe.Pointer(&buffer[offset]))
			if record.EventID&0xFFFF == EVENT_ID_SHUTDOWN_CLEAN /*|| record.EventID&0xFFFF == EVENT_ID_SHUTDOWN_NOT_CLEAN*/ {
				return time.Unix(int64(record.TimeGenerated), 0), nil
			}
			offset += int(record.Length)
		}
	}

	return time.Time{}, fmt.Errorf("NO events (ID 6006 or 6008) found")
}

// checks if it's too late
func tooLate(loggedTime time.Time) bool {
	currentTime := time.Now()
	control := loggedTime.AddDate(0, 0, 7) // the amount of time you want to set
	//control := loggedTime.AddDate(0, 0, -1)

	if control.Before(currentTime) {
		return true
	} else {
		return false
	}
}

// test dummie function
func testActionFunc() {
	command := "echo \"it's too late!\" > \"C:\\Users\\User\\Desktop\\dummie.txt\""
	c := exec.Command("powershell", command)
	c.Run()
}

// deletes with sdelete all the sensitive directories, backups and etw events
// this is an example of anti-forensic approach
func takeAction() {
	commands := []string{"sdelete -s -p 1 C:\\Users\\User\\Desktop\\",
		"C:\\Users\\User\\AppData\\Roaming\\Code",
		"sdelete -s -p 1 C:\\Users\\User\\Downloads\\",
		"sdelete -s -p 1 C:\\Users\\User\\Pictures\\",
		"vssadmin delete shadows /all /quiet",
		"Get-WinEvent -ListLog * | ForEach-Object { wevtutil.exe cl $_.LogName }"}

	for _, com := range commands {
		c := exec.Command("powershell", com)
		c.Run()
	}
}

func setHighPriority() error {
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	const HIGH_PRIORITY_CLASS = 0x00000080
	err = windows.SetPriorityClass(windows.Handle(handle), HIGH_PRIORITY_CLASS)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}
