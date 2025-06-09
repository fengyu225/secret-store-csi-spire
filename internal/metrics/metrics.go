package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	MountRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_mount_requests_total",
			Help: "Total number of mount requests",
		},
		[]string{"status", "namespace", "service_account", "pod_uid"},
	)

	MountRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "spire_csi_mount_request_duration_seconds",
			Help:    "Duration of mount requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"status", "namespace", "service_account", "pod_uid"},
	)

	ObjectsProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_objects_processed_total",
			Help: "Total number of objects processed",
		},
		[]string{"type", "status", "namespace", "service_account", "pod_uid"},
	)

	SpireConnectionStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spire_csi_spire_connection_status",
			Help: "SPIRE connection status (1 = connected, 0 = disconnected)",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	SpireConnectionAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_spire_connection_attempts_total",
			Help: "Total number of SPIRE connection attempts",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	SpireSVIDsReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_svids_received_total",
			Help: "Total number of SVIDs received from SPIRE",
		},
		[]string{"type", "namespace", "service_account", "pod_uid"},
	)

	SpireBundleUpdates = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_bundle_updates_total",
			Help: "Total number of trust bundle updates received",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	JWTCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_jwt_cache_hits_total",
			Help: "Total number of JWT cache hits",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	JWTCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_jwt_cache_misses_total",
			Help: "Total number of JWT cache misses",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	JWTCacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spire_csi_jwt_cache_size",
			Help: "Current size of JWT cache",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	SVIDCacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spire_csi_svid_cache_size",
			Help: "Current size of SVID cache",
		},
		[]string{"namespace", "service_account", "pod_uid"},
	)

	HealthCheckStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "spire_csi_health_check_status",
			Help: "Health check status (1 = healthy, 0 = unhealthy)",
		},
	)
)

type PodContext struct {
	Namespace      string
	ServiceAccount string
	PodUID         string
	PodName        string
}

func RecordMountRequest(status string, duration float64, ctx PodContext) {
	MountRequestsTotal.WithLabelValues(status, ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
	MountRequestDuration.WithLabelValues(status, ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Observe(duration)
}

func RecordObjectProcessed(objectType, status string, ctx PodContext) {
	ObjectsProcessedTotal.WithLabelValues(objectType, status, ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
}

func UpdateSpireConnectionStatus(connected bool, ctx PodContext) {
	value := 0.0
	if connected {
		value = 1.0
	}
	SpireConnectionStatus.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Set(value)
}

func RecordSpireConnectionAttempt(ctx PodContext) {
	SpireConnectionAttempts.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
}

func RecordSpireSVIDReceived(svidType string, ctx PodContext) {
	SpireSVIDsReceived.WithLabelValues(svidType, ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
}

func RecordSpireBundleUpdate(ctx PodContext) {
	SpireBundleUpdates.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
}

func RecordJWTCacheHit(ctx PodContext) {
	JWTCacheHits.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
}

func RecordJWTCacheMiss(ctx PodContext) {
	JWTCacheMisses.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Inc()
}

func UpdateCacheSizes(jwtCacheSize, svidCacheSize int, ctx PodContext) {
	JWTCacheSize.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Set(float64(jwtCacheSize))
	SVIDCacheSize.WithLabelValues(ctx.Namespace, ctx.ServiceAccount, ctx.PodUID).Set(float64(svidCacheSize))
}
