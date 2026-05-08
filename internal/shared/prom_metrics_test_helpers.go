package shared

// NewPrometheusMetricsForTest is a test helper that wraps NewPrometheusMetrics
// and panics on error. It exists to keep test code terse — production callers
// must check the error return.
func NewPrometheusMetricsForTest(product Product) *PrometheusMetrics {
	pm, err := NewPrometheusMetrics(product)
	if err != nil {
		panic(err)
	}
	return pm
}
