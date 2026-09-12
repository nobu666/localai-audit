//go:build !windows

package main

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// termWidth returns the width of the terminal on stdout, COLUMNS if that
// fails (not a tty), and 80 as a last resort.
func termWidth() int {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno == 0 && ws.Col > 0 {
		return int(ws.Col)
	}
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	return 80
}
