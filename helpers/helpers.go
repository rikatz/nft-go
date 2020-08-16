package helpers

import (
	"errors"

	"golang.org/x/sys/unix"
)

// ChainHookIntToStr converts an integer hook into its equivalent string
func ChainHookIntToStr(hook int) (string, error) {
	switch hook {
	case unix.NF_INET_PRE_ROUTING:
		return "prerouting", nil
	case unix.NF_INET_LOCAL_IN:
		return "input", nil
	case unix.NF_INET_FORWARD:
		return "forward", nil
	case unix.NF_INET_LOCAL_OUT:
		return "output", nil
	case unix.NF_INET_POST_ROUTING:
		return "postrouting", nil
	default:
		return "", errors.New("Invalid hook detected")
	}
}

// ChainPolicyIntToStr converts an integer policy into its equivalent string
func ChainPolicyIntToStr(hook int) string {
	if hook == 0 {
		return "drop"
	}
	return "accept"
}
