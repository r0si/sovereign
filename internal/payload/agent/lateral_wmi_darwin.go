//go:build darwin
// +build darwin

package main

import "fmt"

// lateralWMI is unavailable on macOS. Keep the shared task dispatcher
// compilable without pretending the Windows-only WMI path can run here.
func lateralWMI(_, _, _, _ string) (string, error) {
	return "", fmt.Errorf("lateral_wmi is only supported on Windows")
}
