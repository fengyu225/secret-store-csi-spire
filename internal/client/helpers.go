package client

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for gRPC status errors
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.Unavailable, codes.Canceled, codes.Aborted:
			return true
		}
	}

	// Check for specific error messages
	errStr := err.Error()
	connectionErrors := []string{
		"context canceled",
		"connection refused",
		"transport is closing",
		"no such file",
		"broken pipe",
		"ENHANCE_YOUR_CALM",
		"too_many_pings",
	}

	for _, pattern := range connectionErrors {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

func isKeepaliveError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "enhance_your_calm") ||
		strings.Contains(errStr, "too_many_pings")
}
