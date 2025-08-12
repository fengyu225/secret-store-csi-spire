package client

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsConnectionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "unavailable status",
			err:      status.Error(codes.Unavailable, "service unavailable"),
			expected: true,
		},
		{
			name:     "canceled status",
			err:      status.Error(codes.Canceled, "operation canceled"),
			expected: true,
		},
		{
			name:     "aborted status",
			err:      status.Error(codes.Aborted, "operation aborted"),
			expected: true,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "transport closing",
			err:      errors.New("transport is closing"),
			expected: true,
		},
		{
			name:     "no such file",
			err:      errors.New("no such file or directory"),
			expected: true,
		},
		{
			name:     "broken pipe",
			err:      errors.New("broken pipe"),
			expected: true,
		},
		{
			name:     "enhance your calm",
			err:      errors.New("ENHANCE_YOUR_CALM"),
			expected: true,
		},
		{
			name:     "too many pings",
			err:      errors.New("too_many_pings"),
			expected: true,
		},
		{
			name:     "permission denied status",
			err:      status.Error(codes.PermissionDenied, "permission denied"),
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some other error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isConnectionError(tt.err)
			if result != tt.expected {
				t.Errorf("isConnectionError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsKeepaliveError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "enhance your calm",
			err:      errors.New("ENHANCE_YOUR_CALM"),
			expected: true,
		},
		{
			name:     "too many pings",
			err:      errors.New("too_many_pings"),
			expected: true,
		},
		{
			name:     "partial enhance your calm",
			err:      errors.New("server said: ENHANCE_YOUR_CALM, please retry"),
			expected: true,
		},
		{
			name:     "partial too many pings",
			err:      errors.New("error: too_many_pings detected"),
			expected: true,
		},
		{
			name:     "generic error",
			err:      errors.New("some other error"),
			expected: false,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isKeepaliveError(tt.err)
			if result != tt.expected {
				t.Errorf("isKeepaliveError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsConnectionError_ComplexErrors(t *testing.T) {
	wrappedErr := status.Error(codes.Unavailable, "wrapped: connection refused")
	if !isConnectionError(wrappedErr) {
		t.Error("Should detect connection error in wrapped gRPC status")
	}

	// Test with multi-line error
	multiLineErr := errors.New("error occurred\ntransport is closing\nplease retry")
	if !isConnectionError(multiLineErr) {
		t.Error("Should detect connection error in multi-line error message")
	}
}

func TestIsKeepaliveError_CaseSensitivity(t *testing.T) {
	// Test case sensitivity
	lowerCaseErr := errors.New("enhance_your_calm")
	if !isKeepaliveError(lowerCaseErr) {
		t.Error("Should detect keepalive error regardless of case")
	}

	mixedCaseErr := errors.New("Too_Many_Pings")
	if !isKeepaliveError(mixedCaseErr) {
		t.Error("Should detect keepalive error with mixed case")
	}
}
