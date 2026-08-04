package testkit

import (
	"sync"
	"time"
)

// FixedClock is a manually advanced, concurrency-safe test clock.
type FixedClock struct {
	mu  sync.RWMutex
	now time.Time
}

// NewFixedClock returns a clock initialized to now.
func NewFixedClock(now time.Time) *FixedClock {
	return &FixedClock{now: now}
}

// Now returns the clock's current instant.
func (c *FixedClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Advance moves the clock by delta.
func (c *FixedClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}
