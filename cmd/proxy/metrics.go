package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kkp_connections_accepted_total",
		Help: "Number of client connections accepted by the proxy.",
	})
	metricAuthFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kkp_upstream_auth_failures_total",
		Help: "Number of upstream (Keycloak-side) SCRAM authentication failures.",
	})
	metricRelayEnded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kkp_relay_ended_total",
		Help: "Number of relay sessions that ended, by outcome.",
	}, []string{"outcome"})
)

func init() {
	prometheus.MustRegister(metricConnections, metricAuthFailures, metricRelayEnded)
}

// startMetricsServer runs a Prometheus /metrics endpoint on addr until the
// process exits. It logs but does not crash the proxy on
// errors. Graceful shutdown is not wired — the proxy is intended to run as a
// k8s Deployment where SIGTERM tears the pod down.
func startMetricsServer(_ context.Context, addr string) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("metrics endpoint listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server: %v", err)
		}
	}()
}
