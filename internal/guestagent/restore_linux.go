package guestagent

import (
	"encoding/binary"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ApplyRestore is a real guest's Server.Restore. It credits entropy to the
// kernel's input pool (RNDADDENTROPY), forces the kernel's random number
// generator to reseed from that pool at once (RNDRESEEDCRNG), and sets
// CLOCK_REALTIME to unixNano. A kernel with VMGenID (Linux 5.18+ on ACPI)
// has already reseeded on resume; this closes the window before that
// notification is handled and covers kernels without it. It needs
// CAP_SYS_ADMIN and CAP_SYS_TIME: the agent runs as root.
func ApplyRestore(entropy []byte, unixNano int64) error {
	random, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer random.Close()
	// struct rand_pool_info { int entropy_count; int buf_size; __u32 buf[]; }
	info := make([]byte, 8+len(entropy))
	binary.NativeEndian.PutUint32(info[0:], uint32(len(entropy)*8))
	binary.NativeEndian.PutUint32(info[4:], uint32(len(entropy)))
	copy(info[8:], entropy)
	conn, err := random.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) {
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.RNDADDENTROPY, uintptr(unsafe.Pointer(&info[0]))); errno != 0 {
			ioctlErr = os.NewSyscallError("RNDADDENTROPY", errno)
			return
		}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, unix.RNDRESEEDCRNG, 0); errno != 0 {
			ioctlErr = os.NewSyscallError("RNDRESEEDCRNG", errno)
		}
	}); err != nil {
		return err
	}
	if ioctlErr != nil {
		return ioctlErr
	}
	now := unix.NsecToTimespec(unixNano)
	return os.NewSyscallError("clock_settime", unix.ClockSettime(unix.CLOCK_REALTIME, &now))
}
