// Package ratelimit implements the per-address and per-prefix token buckets
// the DROP specification requires.
//
// Two things shape this design. First, limits apply per prefix as well as per
// address: behind carrier-grade NAT one subscriber must not be able to walk
// the shared address's port space, and an IPv6 client has a whole /64 to
// itself and could otherwise rotate addresses for free. Second, the bucket
// table is bounded, because an unbounded map keyed by attacker-chosen
// addresses is itself a denial-of-service vector -- and this runs on a host
// with 458 MB of RAM.
package ratelimit

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// Rule is one token bucket's shape.
type Rule struct {
	// Every is the interval at which one token is replenished. A
	// non-positive value means no limit.
	Every time.Duration
	// Burst is the maximum number of tokens held at once, and therefore the
	// size of a burst allowed after an idle period. Zero denies everything.
	Burst int
}

func (r Rule) unlimited() bool { return r.Every <= 0 }

// bucket is a plain token bucket. It is deliberately hand-rolled rather than
// pulled from a dependency: the whole implementation is shorter than the
// reserve-and-cancel dance needed to consult two buckets atomically, and
// "check both, then spend both" is obviously correct in a way that partial
// reservations are not.
type bucket struct {
	tokens float64
	last   time.Time
}

// advance replenishes the bucket up to now.
func (b *bucket) advance(now time.Time, rule Rule) {
	if b.last.IsZero() {
		b.tokens = float64(rule.Burst)
		b.last = now
		return
	}
	if !now.After(b.last) {
		return
	}
	b.tokens += float64(now.Sub(b.last)) / float64(rule.Every)
	if max := float64(rule.Burst); b.tokens > max {
		b.tokens = max
	}
	b.last = now
}

// wait reports how long until one token is available. It assumes the caller
// has already advanced the bucket and found it short.
func (b *bucket) wait(rule Rule) time.Duration {
	if rule.Burst < 1 {
		// The rule forbids everything; there is no honest retry time, so
		// report something long enough to be an obvious "stop".
		return time.Hour
	}
	return time.Duration((1 - b.tokens) * float64(rule.Every))
}

// Config configures a Limiter.
type Config struct {
	// Host applies to a single address: a /32 for IPv4, a /128 for IPv6.
	Host Rule
	// Prefix applies to the enclosing /24 or /64.
	Prefix Rule
	// MaxEntries bounds the bucket table. Least-recently-used entries are
	// evicted beyond it. Evicting a throttled entry forgives it, so this
	// should comfortably exceed the number of legitimate concurrent clients.
	MaxEntries int
}

// DefaultConfig derives limits from the specification's sessions-per-hour
// figure. The prefix allowance is deliberately more than the host allowance
// but far less than the number of addresses a prefix contains, so that a
// shared address stays usable while a single subscriber cannot monopolise it.
func DefaultConfig(sessionsPerHour int) Config {
	if sessionsPerHour < 1 {
		sessionsPerHour = 1
	}
	per := time.Hour / time.Duration(sessionsPerHour)
	return Config{
		Host:       Rule{Every: per, Burst: 3},
		Prefix:     Rule{Every: per / 8, Burst: 12},
		MaxEntries: 8192,
	}
}

// Limiter is a bounded set of token buckets. It is safe for concurrent use.
type Limiter struct {
	cfg Config

	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List // front is most recently used
}

type entry struct {
	key    string
	bucket *bucket
}

// New returns a Limiter. A MaxEntries below 1 is treated as unbounded-ish by
// falling back to a sane cap rather than growing without limit.
func New(cfg Config) *Limiter {
	if cfg.MaxEntries < 1 {
		cfg.MaxEntries = 8192
	}
	return &Limiter{
		cfg:     cfg,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// Allow reports whether addr may consume one unit now. When it may not, the
// returned duration is how long the caller should tell the client to wait,
// suitable for a Retry-After header.
func (l *Limiter) Allow(addr netip.Addr) (bool, time.Duration) {
	return l.AllowAt(time.Now(), addr)
}

// AllowAt is Allow at an explicit instant, so that tests need no sleeping.
func (l *Limiter) AllowAt(now time.Time, addr netip.Addr) (bool, time.Duration) {
	hostKey, prefixKey := Keys(addr)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Both buckets must permit the request, and neither may be charged unless
	// both do. Charging a bucket for a request the other one rejected would
	// punish a client twice for traffic that was not its own -- once by its
	// neighbours' prefix usage, and again in its own budget.
	hostRule, prefixRule := l.cfg.Host, l.cfg.Prefix
	host := l.bucketLocked("h" + hostKey)
	prefix := l.bucketLocked("p" + prefixKey)

	hostOK := true
	if !hostRule.unlimited() {
		host.advance(now, hostRule)
		hostOK = host.tokens >= 1
	}
	prefixOK := true
	if !prefixRule.unlimited() {
		prefix.advance(now, prefixRule)
		prefixOK = prefix.tokens >= 1
	}

	if hostOK && prefixOK {
		if !hostRule.unlimited() {
			host.tokens--
		}
		if !prefixRule.unlimited() {
			prefix.tokens--
		}
		return true, 0
	}

	var wait time.Duration
	if !hostOK {
		wait = host.wait(hostRule)
	}
	if !prefixOK {
		if w := prefix.wait(prefixRule); w > wait {
			wait = w
		}
	}
	return false, wait
}

func (l *Limiter) bucketLocked(key string) *bucket {
	if el, ok := l.entries[key]; ok {
		l.lru.MoveToFront(el)
		return el.Value.(*entry).bucket
	}

	b := &bucket{}
	el := l.lru.PushFront(&entry{key: key, bucket: b})
	l.entries[key] = el

	for l.lru.Len() > l.cfg.MaxEntries {
		oldest := l.lru.Back()
		if oldest == nil {
			break
		}
		l.lru.Remove(oldest)
		delete(l.entries, oldest.Value.(*entry).key)
	}
	return b
}

// Len reports how many buckets are currently held, for metrics and tests.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}

// Keys returns the host and prefix bucket keys for addr.
//
// IPv4 aggregates at /24 and IPv6 at /64, which is the smallest block a site
// is normally assigned. Aggregating IPv6 at /128 alone would be useless: a
// client with a /64 can pick a new source address for every request.
func Keys(addr netip.Addr) (host, prefix string) {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return "invalid", "invalid"
	}
	bits := 24
	if addr.Is6() {
		bits = 64
	}
	host = addr.String()
	if p, err := addr.Prefix(bits); err == nil {
		prefix = p.String()
	} else {
		prefix = host
	}
	return host, prefix
}
