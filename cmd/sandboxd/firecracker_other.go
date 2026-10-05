//go:build !linux

package main

import (
	"context"
	"errors"
)

func startFirecracker(context.Context, firecrackerFlags, []string, []string) (isolatedDriver, func(context.Context) error, error) {
	return nil, nil, errors.New("the firecracker driver requires Linux with KVM")
}
