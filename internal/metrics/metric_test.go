package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordMountRequest(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		duration float64
		ctx      PodContext
	}{
		{
			name:     "successful mount",
			status:   "success",
			duration: 0.5,
			ctx: PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
				PodName:        "test-pod",
			},
		},
		{
			name:     "failed mount",
			status:   "error",
			duration: 1.2,
			ctx: PodContext{
				Namespace:      "production",
				ServiceAccount: "admin",
				PodUID:         "456",
				PodName:        "admin-pod",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RecordMountRequestCtx(tt.status, tt.duration, tt.ctx)

			// Verify counter was incremented
			count := testutil.ToFloat64(MountRequestsTotal.WithLabelValues(
				tt.status, tt.ctx.Namespace, tt.ctx.ServiceAccount, tt.ctx.PodUID,
			))
			if count < 1 {
				t.Error("Counter should be incremented")
			}

			// Note: Histogram values are harder to test directly
		})
	}
}

func TestRecordObjectProcessed(t *testing.T) {
	tests := []struct {
		name       string
		objectType string
		status     string
		ctx        PodContext
	}{
		{
			name:       "x509 success",
			objectType: "x509-svid",
			status:     "success",
			ctx: PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
			},
		},
		{
			name:       "jwt error",
			objectType: "jwt-svid",
			status:     "error",
			ctx: PodContext{
				Namespace:      "production",
				ServiceAccount: "api-sa",
				PodUID:         "789",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RecordObjectProcessedCtx(tt.objectType, tt.status, tt.ctx)

			count := testutil.ToFloat64(ObjectsProcessedTotal.WithLabelValues(
				tt.objectType, tt.status, tt.ctx.Namespace, tt.ctx.ServiceAccount, tt.ctx.PodUID,
			))
			if count < 1 {
				t.Error("Counter should be incremented")
			}
		})
	}
}

func TestUpdateSpireConnectionStatus(t *testing.T) {
	tests := []struct {
		name      string
		connected bool
		ctx       PodContext
		expected  float64
	}{
		{
			name:      "connected",
			connected: true,
			ctx: PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
			},
			expected: 1.0,
		},
		{
			name:      "disconnected",
			connected: false,
			ctx: PodContext{
				Namespace:      "kube-system",
				ServiceAccount: "admin",
				PodUID:         "456",
			},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UpdateSpireConnectionStatusCtx(tt.connected, tt.ctx)

			value := testutil.ToFloat64(SpireConnectionStatus.WithLabelValues(
				"agent", tt.ctx.Namespace, tt.ctx.ServiceAccount, tt.ctx.PodUID,
			))
			if value != tt.expected {
				t.Errorf("Expected %f, got %f", tt.expected, value)
			}
		})
	}
}

func TestRecordSpireConnectionAttempt(t *testing.T) {
	ctx := PodContext{
		Namespace:      "default",
		ServiceAccount: "test-sa",
		PodUID:         "123",
	}

	RecordSpireConnectionAttemptCtx(ctx)

	count := testutil.ToFloat64(SpireConnectionAttempts.WithLabelValues(
		"agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID,
	))
	if count < 1 {
		t.Error("Counter should be incremented")
	}
}

func TestRecordSpireSVIDReceived(t *testing.T) {
	tests := []struct {
		name     string
		svidType string
		ctx      PodContext
	}{
		{
			name:     "x509 SVID",
			svidType: "x509",
			ctx: PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
			},
		},
		{
			name:     "JWT SVID",
			svidType: "jwt",
			ctx: PodContext{
				Namespace:      "production",
				ServiceAccount: "api-sa",
				PodUID:         "456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RecordSpireSVIDReceivedCtx(tt.svidType, tt.ctx)

			count := testutil.ToFloat64(SpireSVIDsReceived.WithLabelValues(
				"agent", tt.svidType, tt.ctx.Namespace, tt.ctx.ServiceAccount, tt.ctx.PodUID,
			))
			if count < 1 {
				t.Error("Counter should be incremented")
			}
		})
	}
}

func TestRecordSpireBundleUpdate(t *testing.T) {
	ctx := PodContext{
		Namespace:      "default",
		ServiceAccount: "test-sa",
		PodUID:         "123",
	}

	RecordSpireBundleUpdateCtx(ctx)

	count := testutil.ToFloat64(SpireBundleUpdates.WithLabelValues(
		"agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID,
	))
	if count < 1 {
		t.Error("Counter should be incremented")
	}
}

func TestJWTCacheMetrics(t *testing.T) {
	ctx := PodContext{
		Namespace:      "default",
		ServiceAccount: "test-sa",
		PodUID:         "123",
	}

	// Test cache hit
	RecordJWTCacheHitCtx(ctx)
	hitCount := testutil.ToFloat64(JWTCacheHits.WithLabelValues(
		"agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID,
	))
	if hitCount < 1 {
		t.Error("Cache hit counter should be incremented")
	}

	// Test cache miss
	RecordJWTCacheMissCtx(ctx)
	missCount := testutil.ToFloat64(JWTCacheMisses.WithLabelValues(
		"agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID,
	))
	if missCount < 1 {
		t.Error("Cache miss counter should be incremented")
	}
}

func TestUpdateCacheSizes(t *testing.T) {
	tests := []struct {
		name          string
		jwtCacheSize  int
		svidCacheSize int
		ctx           PodContext
	}{
		{
			name:          "empty caches",
			jwtCacheSize:  0,
			svidCacheSize: 0,
			ctx: PodContext{
				Namespace:      "default",
				ServiceAccount: "test-sa",
				PodUID:         "123",
			},
		},
		{
			name:          "populated caches",
			jwtCacheSize:  5,
			svidCacheSize: 10,
			ctx: PodContext{
				Namespace:      "production",
				ServiceAccount: "api-sa",
				PodUID:         "456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UpdateCacheSizesCtx(tt.jwtCacheSize, tt.svidCacheSize, tt.ctx)

			jwtSize := testutil.ToFloat64(JWTCacheSize.WithLabelValues(
				"agent", tt.ctx.Namespace, tt.ctx.ServiceAccount, tt.ctx.PodUID,
			))
			if jwtSize != float64(tt.jwtCacheSize) {
				t.Errorf("Expected JWT cache size %d, got %f", tt.jwtCacheSize, jwtSize)
			}

			svidSize := testutil.ToFloat64(SVIDCacheSize.WithLabelValues(
				"agent", tt.ctx.Namespace, tt.ctx.ServiceAccount, tt.ctx.PodUID,
			))
			if svidSize != float64(tt.svidCacheSize) {
				t.Errorf("Expected SVID cache size %d, got %f", tt.svidCacheSize, svidSize)
			}
		})
	}
}

func TestProviderPoolMetrics(t *testing.T) {
	// Test pool size update
	UpdateProviderPoolSize("example.org", 5)
	poolSize := testutil.ToFloat64(ProviderPoolSize.WithLabelValues("example.org"))
	if poolSize != 5.0 {
		t.Errorf("Expected pool size 5, got %f", poolSize)
	}

	// Test pool hit
	RecordProviderPoolHitCtx("example.org", "default", "test-sa")
	hitCount := testutil.ToFloat64(ProviderPoolHits.WithLabelValues(
		"example.org", "default", "test-sa",
	))
	if hitCount < 1 {
		t.Error("Pool hit counter should be incremented")
	}

	// Test pool miss
	RecordProviderPoolMissCtx("example.org", "production", "api-sa")
	missCount := testutil.ToFloat64(ProviderPoolMisses.WithLabelValues(
		"example.org", "production", "api-sa",
	))
	if missCount < 1 {
		t.Error("Pool miss counter should be incremented")
	}

	// Test eviction
	RecordProviderEvictionCtx("stale")
	evictionCount := testutil.ToFloat64(ProviderPoolEvictions.WithLabelValues("stale"))
	if evictionCount < 1 {
		t.Error("Eviction counter should be incremented")
	}
}

func TestHealthCheckStatus(t *testing.T) {
	// Set healthy
	HealthCheckStatus.Set(1.0)
	value := testutil.ToFloat64(HealthCheckStatus)
	if value != 1.0 {
		t.Errorf("Expected health status 1.0, got %f", value)
	}

	// Set unhealthy
	HealthCheckStatus.Set(0.0)
	value = testutil.ToFloat64(HealthCheckStatus)
	if value != 0.0 {
		t.Errorf("Expected health status 0.0, got %f", value)
	}
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	ctx := PodContext{
		Namespace:      "concurrent",
		ServiceAccount: "test-sa",
		PodUID:         "999",
	}

	done := make(chan bool, 100)

	// Concurrent metric updates
	for i := 0; i < 20; i++ {
		go func() {
			RecordMountRequestCtx("success", 0.1, ctx)
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		go func() {
			RecordObjectProcessedCtx("x509-svid", "success", ctx)
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		go func() {
			UpdateSpireConnectionStatusCtx(true, ctx)
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		go func() {
			RecordJWTCacheHitCtx(ctx)
			done <- true
		}()
	}

	for i := 0; i < 20; i++ {
		go func() {
			UpdateCacheSizesCtx(5, 10, ctx)
			done <- true
		}()
	}

	// Wait for all operations
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}

	// Verify metrics were recorded
	mountCount := testutil.ToFloat64(MountRequestsTotal.WithLabelValues(
		"success", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID,
	))
	if mountCount < 20 {
		t.Errorf("Expected at least 20 mount requests, got %f", mountCount)
	}
}
