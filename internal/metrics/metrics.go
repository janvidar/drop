// Package metrics exposes a small Prometheus text endpoint.
//
// It is hand-rolled rather than using client_golang. The whole surface is a
// handful of counters and a few runtime gauges, the text format is trivial,
// and on a 458 MB single-core host it is worth not carrying a large dependency
// and its transitive tree for that.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds the process's counters.
type Registry struct {
	start time.Time

	mu       sync.RWMutex
	counters map[string]*counter
	gauges   map[string]*gauge
}

type counter struct {
	name   string
	help   string
	labels map[string]*atomic.Int64 // serialised label set -> value
	mu     sync.RWMutex
}

type gauge struct {
	help   string
	sample func() float64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{
		start:    time.Now(),
		counters: map[string]*counter{},
		gauges:   map[string]*gauge{},
	}
}

// Count increments a counter, creating it if needed. Labels are given as
// alternating key and value strings.
func (r *Registry) Count(name, help string, labels ...string) {
	r.CountBy(1, name, help, labels...)
}

// CountBy increments a counter by n.
func (r *Registry) CountBy(n int64, name, help string, labels ...string) {
	r.mu.Lock()
	c, ok := r.counters[name]
	if !ok {
		c = &counter{name: name, help: help, labels: map[string]*atomic.Int64{}}
		r.counters[name] = c
	}
	r.mu.Unlock()

	key := labelKey(labels)
	c.mu.RLock()
	v, ok := c.labels[key]
	c.mu.RUnlock()
	if !ok {
		c.mu.Lock()
		if v, ok = c.labels[key]; !ok {
			v = &atomic.Int64{}
			c.labels[key] = v
		}
		c.mu.Unlock()
	}
	v.Add(n)
}

// Gauge registers a function sampled at scrape time. Sampling on scrape avoids
// keeping a running counter in sync with the thing it describes.
func (r *Registry) Gauge(name, help string, f func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = &gauge{help: help, sample: f}
}

func labelKey(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	var pairs []string
	for i := 0; i+1 < len(labels); i += 2 {
		pairs = append(pairs, fmt.Sprintf("%s=%q", labels[i], escapeLabel(labels[i+1])))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// Handler serves the Prometheus text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var sb strings.Builder

		r.mu.RLock()
		names := make([]string, 0, len(r.counters))
		for name := range r.counters {
			names = append(names, name)
		}
		gaugeNames := make([]string, 0, len(r.gauges))
		for name := range r.gauges {
			gaugeNames = append(gaugeNames, name)
		}
		counters := r.counters
		gauges := r.gauges
		r.mu.RUnlock()

		sort.Strings(names)
		sort.Strings(gaugeNames)

		for _, name := range names {
			c := counters[name]
			if c.help != "" {
				fmt.Fprintf(&sb, "# HELP %s %s\n", name, c.help)
			}
			fmt.Fprintf(&sb, "# TYPE %s counter\n", name)

			c.mu.RLock()
			keys := make([]string, 0, len(c.labels))
			for k := range c.labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := c.labels[k].Load()
				if k == "" {
					fmt.Fprintf(&sb, "%s %d\n", name, v)
				} else {
					fmt.Fprintf(&sb, "%s{%s} %d\n", name, k, v)
				}
			}
			c.mu.RUnlock()
		}

		for _, name := range gaugeNames {
			g := gauges[name]
			if g.help != "" {
				fmt.Fprintf(&sb, "# HELP %s %s\n", name, g.help)
			}
			fmt.Fprintf(&sb, "# TYPE %s gauge\n", name)
			fmt.Fprintf(&sb, "%s %s\n", name,
				strconv.FormatFloat(g.sample(), 'g', -1, 64))
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(sb.String()))
	})
}

// RegisterRuntime adds the process gauges. Memory is the one that matters
// here: the daemon runs under a hard MemoryMax on a small host, and a slow
// leak would otherwise be discovered by the OOM killer.
func (r *Registry) RegisterRuntime() {
	r.Gauge("drop_uptime_seconds", "Seconds since start.", func() float64 {
		return time.Since(r.start).Seconds()
	})
	r.Gauge("drop_goroutines", "Number of goroutines.", func() float64 {
		return float64(runtime.NumGoroutine())
	})
	r.Gauge("drop_memory_heap_bytes", "Heap bytes in use.", func() float64 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc)
	})
	r.Gauge("drop_memory_sys_bytes", "Total bytes obtained from the OS.", func() float64 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.Sys)
	})
}
