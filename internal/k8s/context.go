package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/madic-creates/claude-alert-analyzer/internal/shared"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PrometheusClient queries a Prometheus instance.
type PrometheusClient struct {
	HTTP *http.Client
	URL  string
}

// NewPrometheusClient creates a client with default 10s timeout.
func NewPrometheusClient(url string) *PrometheusClient {
	return &PrometheusClient{
		HTTP: &http.Client{Timeout: 10 * time.Second},
		URL:  url,
	}
}

// validK8sName matches valid Kubernetes namespace names: lowercase alphanumeric and
// hyphens, starting and ending with an alphanumeric character, max 63 characters.
// Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
var validK8sName = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$`)

// isValidNamespace returns true if s is a valid Kubernetes namespace name.
// This guards against PromQL label-value injection when the namespace is
// interpolated directly into query strings.
func isValidNamespace(s string) bool {
	return validK8sName.MatchString(s)
}

func isNamespaceAllowed(namespace string, allowed []string) bool {
	if len(allowed) == 0 {
		return false // deny by default if no allowlist
	}
	for _, ns := range allowed {
		if ns == namespace || ns == "*" {
			return true
		}
	}
	return false
}

func (p *PrometheusClient) query(ctx context.Context, queryStr string) string {
	u := fmt.Sprintf("%s/api/v1/query?query=%s", p.URL, url.QueryEscape(queryStr))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return fmt.Sprintf("(request error: %v)", err)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return fmt.Sprintf("(query failed: %v)", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("(Prometheus returned %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, shared.MaxResponseBytes))
	if err != nil {
		return "(failed to read response)"
	}

	var result PromQueryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "(failed to parse response)"
	}
	if result.Status != "success" {
		if result.Error != "" {
			return fmt.Sprintf("(query error: %s: %s)", result.ErrorType, result.Error)
		}
		return fmt.Sprintf("(query error: status=%q)", result.Status)
	}
	if len(result.Data.Result) == 0 {
		return "(no data)"
	}

	var lines []string
	for _, r := range result.Data.Result {
		var labels []string
		for k, v := range r.Metric {
			labels = append(labels, fmt.Sprintf("%s=%s", k, v))
		}
		sort.Strings(labels)
		val := fmt.Sprintf("%v", r.Value[1])
		lines = append(lines, fmt.Sprintf("%s: %s", strings.Join(labels, ", "), val))
	}
	return strings.Join(lines, "\n")
}

// GetMetrics queries Prometheus for metrics related to the alert.
func (p *PrometheusClient) GetMetrics(ctx context.Context, alert Alert) string {
	namespace := alert.Labels["namespace"]
	alertname := alert.Labels["alertname"]
	var sections []string

	sections = append(sections, "## Active Firing Alerts")
	sections = append(sections, p.query(ctx, `ALERTS{alertstate="firing"}`))

	if namespace != "" && !isValidNamespace(namespace) {
		slog.Warn("dropping namespace-scoped Prometheus queries: invalid namespace label", "namespace", namespace)
		namespace = ""
	}

	if namespace != "" {
		sections = append(sections,
			fmt.Sprintf("\n## CPU Usage (%s)", namespace),
			p.query(ctx,
				fmt.Sprintf(`sum(rate(container_cpu_usage_seconds_total{namespace="%s"}[5m])) by (pod)`, namespace)),
			fmt.Sprintf("\n## Memory Usage (%s)", namespace),
			p.query(ctx,
				fmt.Sprintf(`sum(container_memory_working_set_bytes{namespace="%s"}) by (pod)`, namespace)),
			fmt.Sprintf("\n## Pod Restarts (%s)", namespace),
			p.query(ctx,
				fmt.Sprintf(`sum(kube_pod_container_status_restarts_total{namespace="%s"}) by (pod)`, namespace)),
		)
	}

	lower := strings.ToLower(alertname)
	switch {
	case strings.Contains(lower, "crashloop"):
		sections = append(sections, "\n## CrashLoop Details",
			p.query(ctx, `kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff"}`))
	case strings.Contains(lower, "memory") || strings.Contains(lower, "oom"):
		sections = append(sections, "\n## Top Memory Consumers",
			p.query(ctx, `topk(5, sum(container_memory_working_set_bytes) by (namespace, pod))`))
	case strings.Contains(lower, "cpu"):
		sections = append(sections, "\n## Top CPU Consumers",
			p.query(ctx, `topk(5, sum(rate(container_cpu_usage_seconds_total[5m])) by (namespace, pod))`))
	case strings.Contains(lower, "disk") || strings.Contains(lower, "volume") || strings.Contains(lower, "storage"):
		sections = append(sections, "\n## PVC Usage",
			p.query(ctx, `(kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes) > 0.8`))
	case strings.Contains(lower, "node"):
		sections = append(sections, "\n## Node Conditions",
			p.query(ctx, `kube_node_status_condition{condition="Ready"}`))
	}

	return strings.Join(sections, "\n")
}

func getEvents(ctx context.Context, clientset kubernetes.Interface, namespace string) string {
	// Limit the API response to 20 events to prevent fetching thousands of
	// warning events into memory for busy namespaces (e.g. a CrashLoopBackOff
	// pod generating rapid-fire events). The API applies the limit server-side,
	// so we never download more than we need — matching the approach taken for
	// pod log fetches (LimitBytes).
	const maxEvents = 20
	eventList, err := clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "type!=Normal",
		Limit:         maxEvents,
	})
	if err != nil {
		return fmt.Sprintf("(failed: %v)", err)
	}
	var lines []string
	items := eventList.Items
	start := 0
	if len(items) > maxEvents {
		start = len(items) - maxEvents
	}
	for _, e := range items[start:] {
		ts := ""
		if !e.LastTimestamp.Time.IsZero() {
			ts = e.LastTimestamp.Format(time.RFC3339)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s: %s",
			ts, e.Type, e.Reason, e.InvolvedObject.Name, e.Message))
	}
	if len(lines) == 0 {
		return "(no warning events)"
	}
	return strings.Join(lines, "\n")
}

// maxPods is the maximum number of pods fetched per namespace for status reporting.
// Mirrors the server-side Limit applied to Events and pod log fetches to prevent
// OOM on namespaces with large deployments.
const maxPods = 50

func getPodStatus(ctx context.Context, clientset kubernetes.Interface, namespace string) string {
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		Limit: maxPods,
	})
	if err != nil {
		return fmt.Sprintf("(failed: %v)", err)
	}
	// Post-fetch backstop: cap at maxPods in case the API returned more
	// than requested (e.g. the fake client in tests ignores Limit).
	items := podList.Items
	if len(items) > maxPods {
		items = items[len(items)-maxPods:]
	}
	var lines []string
	for _, p := range items {
		phase := string(p.Status.Phase)
		restarts := 0
		ready := 0
		total := len(p.Status.ContainerStatuses)
		for _, cs := range p.Status.ContainerStatuses {
			restarts += int(cs.RestartCount)
			if cs.Ready {
				ready++
			}
		}
		lines = append(lines, fmt.Sprintf("%s %s %d/%d restarts=%d",
			p.Name, phase, ready, total, restarts))
	}
	if len(lines) == 0 {
		return "(no pods)"
	}
	return strings.Join(lines, "\n")
}

func getPodLogs(ctx context.Context, clientset kubernetes.Interface, namespace string, cfg Config) string {
	if !isNamespaceAllowed(namespace, cfg.AllowedNamespaces) {
		return fmt.Sprintf("(namespace %q not in log allowlist)", namespace)
	}

	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase!=Running,status.phase!=Succeeded",
	})
	if err != nil {
		slog.Warn("failed to list failing pods", "namespace", namespace, "error", err)
		return fmt.Sprintf("(failed to list failing pods: %v)", err)
	}
	if len(podList.Items) == 0 {
		return "(no failing pods)"
	}

	var logLines []string
	limit := 3
	if len(podList.Items) < limit {
		limit = len(podList.Items)
	}
	for _, p := range podList.Items[:limit] {
		tailLines := int64(30)
		limitBytes := int64(cfg.MaxLogBytes)
		logResp := clientset.CoreV1().Pods(namespace).GetLogs(p.Name, &corev1.PodLogOptions{
			TailLines:  &tailLines,
			LimitBytes: &limitBytes,
		})
		raw, err := logResp.DoRaw(ctx)
		if err != nil {
			logLines = append(logLines, fmt.Sprintf("--- %s --- (no logs)", p.Name))
		} else {
			redacted := shared.RedactSecrets(string(raw))
			truncated := shared.Truncate(redacted, cfg.MaxLogBytes)
			logLines = append(logLines, fmt.Sprintf("--- %s ---\n%s", p.Name, truncated))
		}
	}
	return strings.Join(logLines, "\n\n")
}

// GetKubeContext retrieves Kubernetes events, pod status, and pod logs for the alert namespace.
func GetKubeContext(ctx context.Context, clientset kubernetes.Interface, alert Alert, cfg Config) (events, pods, logs string) {
	namespace := alert.Labels["namespace"]
	if namespace == "" {
		return "(no namespace in alert)", "(no namespace)", "(no namespace)"
	}
	if !isValidNamespace(namespace) {
		slog.Warn("dropping Kubernetes context queries: invalid namespace label", "namespace", namespace)
		return "(invalid namespace label)", "(invalid namespace label)", "(invalid namespace label)"
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); events = getEvents(ctx, clientset, namespace) }()
	go func() { defer wg.Done(); pods = getPodStatus(ctx, clientset, namespace) }()
	go func() { defer wg.Done(); logs = getPodLogs(ctx, clientset, namespace, cfg) }()
	wg.Wait()
	return
}

// GatherContext collects Prometheus metrics and Kubernetes context for the given alert.
func GatherContext(ctx context.Context, prom *PrometheusClient, clientset kubernetes.Interface, alert Alert, cfg Config) shared.AnalysisContext {
	slog.Info("gathering context",
		"alertname", alert.Labels["alertname"],
		"namespace", alert.Labels["namespace"])

	promCh := make(chan string, 1)
	go func() {
		promCh <- prom.GetMetrics(ctx, alert)
	}()

	events, podStatus, podLogs := GetKubeContext(ctx, clientset, alert, cfg)

	return shared.AnalysisContext{
		Sections: []shared.ContextSection{
			{Name: "Prometheus Metrics", Content: <-promCh},
			{Name: "Kubernetes Events", Content: events},
			{Name: "Pod Status", Content: podStatus},
			{Name: "Pod Logs", Content: podLogs},
		},
	}
}
