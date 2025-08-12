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
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	SpireConnectionAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_spire_connection_attempts_total",
			Help: "Total number of SPIRE connection attempts",
		},
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	SpireSVIDsReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_svids_received_total",
			Help: "Total number of SVIDs received from SPIRE",
		},
		[]string{"agent", "type", "namespace", "service_account", "pod_uid"},
	)

	SpireBundleUpdates = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_bundle_updates_total",
			Help: "Total number of trust bundle updates received",
		},
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	JWTCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_jwt_cache_hits_total",
			Help: "Total number of JWT cache hits",
		},
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	JWTCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_jwt_cache_misses_total",
			Help: "Total number of JWT cache misses",
		},
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	JWTCacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spire_csi_jwt_cache_size",
			Help: "Current size of JWT cache",
		},
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	SVIDCacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spire_csi_svid_cache_size",
			Help: "Current size of SVID cache",
		},
		[]string{"agent", "namespace", "service_account", "pod_uid"},
	)

	HealthCheckStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "spire_csi_health_check_status",
			Help: "Health check status (1 = healthy, 0 = unhealthy)",
		},
	)

	ProviderPoolSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "spire_csi_provider_pool_size",
			Help: "Current size of SPIRE client pool",
		},
		[]string{"trust_domain"},
	)

	ProviderPoolHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_provider_pool_hits_total",
			Help: "Total number of SPIRE client pool hits",
		},
		[]string{"trust_domain", "namespace", "service_account"},
	)

	ProviderPoolMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_provider_pool_misses_total",
			Help: "Total number of SPIRE client pool misses",
		},
		[]string{"trust_domain", "namespace", "service_account"},
	)

	ProviderPoolEvictions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "spire_csi_provider_pool_evictions_total",
			Help: "Total number of SPIRE client evictions from pool",
		},
		[]string{"reason"},
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

func UpdateSpireConnectionStatus(connected bool, agent, namespace, serviceAccount, podUID string) {
	value := 0.0
	if connected {
		value = 1.0
	}
	SpireConnectionStatus.WithLabelValues(agent, namespace, serviceAccount, podUID).Set(value)
}

func RecordSpireConnectionAttempt(agent, namespace, serviceAccount, podUID string) {
	SpireConnectionAttempts.WithLabelValues(agent, namespace, serviceAccount, podUID).Inc()
}

func RecordSpireSVIDReceived(agent, svidType, namespace, serviceAccount, podUID string) {
	SpireSVIDsReceived.WithLabelValues(agent, svidType, namespace, serviceAccount, podUID).Inc()
}

func RecordSpireBundleUpdate(agent, namespace, serviceAccount, podUID string) {
	SpireBundleUpdates.WithLabelValues(agent, namespace, serviceAccount, podUID).Inc()
}

func RecordJWTCacheHit(agent, namespace, serviceAccount, podUID string) {
	JWTCacheHits.WithLabelValues(agent, namespace, serviceAccount, podUID).Inc()
}

func RecordJWTCacheMiss(agent, namespace, serviceAccount, podUID string) {
	JWTCacheMisses.WithLabelValues(agent, namespace, serviceAccount, podUID).Inc()
}

func UpdateCacheSizes(agent, namespace, serviceAccount, podUID string, jwtCacheSize, svidCacheSize int) {
	JWTCacheSize.WithLabelValues(agent, namespace, serviceAccount, podUID).Set(float64(jwtCacheSize))
	SVIDCacheSize.WithLabelValues(agent, namespace, serviceAccount, podUID).Set(float64(svidCacheSize))
}

// Client pool metrics
func UpdateProviderPoolSize(trustDomain string, size int) {
	ProviderPoolSize.WithLabelValues(trustDomain).Set(float64(size))
}

func RecordProviderPoolHit(trustDomain, namespace, serviceAccount string) {
	ProviderPoolHits.WithLabelValues(trustDomain, namespace, serviceAccount).Inc()
}

func RecordProviderPoolMiss(trustDomain, namespace, serviceAccount string) {
	ProviderPoolMisses.WithLabelValues(trustDomain, namespace, serviceAccount).Inc()
}

func RecordProviderEviction(reason string) {
	ProviderPoolEvictions.WithLabelValues(reason).Inc()
}

func UpdateSpireConnectionStatusCtx(connected bool, ctx PodContext) {
	UpdateSpireConnectionStatus(connected, "agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID)
}

func RecordSpireConnectionAttemptCtx(ctx PodContext) {
	RecordSpireConnectionAttempt("agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID)
}

func RecordSpireSVIDReceivedCtx(svidType string, ctx PodContext) {
	RecordSpireSVIDReceived("agent", svidType, ctx.Namespace, ctx.ServiceAccount, ctx.PodUID)
}

func RecordSpireBundleUpdateCtx(ctx PodContext) {
	RecordSpireBundleUpdate("agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID)
}

func RecordJWTCacheHitCtx(ctx PodContext) {
	RecordJWTCacheHit("agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID)
}

func RecordJWTCacheMissCtx(ctx PodContext) {
	RecordJWTCacheMiss("agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID)
}

func UpdateCacheSizesCtx(jwtCacheSize, svidCacheSize int, ctx PodContext) {
	UpdateCacheSizes("agent", ctx.Namespace, ctx.ServiceAccount, ctx.PodUID, jwtCacheSize, svidCacheSize)
}

func RecordMountRequestCtx(status string, duration float64, ctx PodContext) {
	RecordMountRequest(status, duration, ctx)
}

func RecordObjectProcessedCtx(objectType, status string, ctx PodContext) {
	RecordObjectProcessed(objectType, status, ctx)
}

func RecordProviderPoolHitCtx(trustDomain, namespace, serviceAccount string) {
	RecordProviderPoolHit(trustDomain, namespace, serviceAccount)
}

func RecordProviderPoolMissCtx(trustDomain, namespace, serviceAccount string) {
	RecordProviderPoolMiss(trustDomain, namespace, serviceAccount)
}

func RecordProviderEvictionCtx(reason string) {
	RecordProviderEviction(reason)
}
