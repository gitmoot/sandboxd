package vm

import "fmt"

// ValidateFirecrackerHostPort checks FirecrackerConfig.HostPort: zero (no
// host port) or one TCP port other than SSH. It builds on every platform so
// flag validation does.
func ValidateFirecrackerHostPort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("Firecracker host port %d is outside 1-65535", port)
	}
	if port == 22 {
		return fmt.Errorf("Firecracker host port must not be SSH (22)")
	}
	return nil
}
