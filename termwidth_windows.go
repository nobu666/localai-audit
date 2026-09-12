//go:build windows

package main

import (
	"os"
	"strconv"
)

// ponytail: no console API call on Windows; COLUMNS or 80.
func termWidth() int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	return 80
}
