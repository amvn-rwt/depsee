package app

import (
	"os/exec"
	"runtime"
)

// OpenDefaultBrowser opens url in the user's default browser (best effort).
func OpenDefaultBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
