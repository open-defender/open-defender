package banpool

import (
	"context"
	"testing"
	"time"
)

func TestUnbanSchedulerUpdatesDeadlineAndStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := &banPool{}
	now := time.Now()
	first := Ban{ID: 1, IP: "192.0.2.1", BannedUntil: now.Add(time.Hour)}
	second := Ban{ID: 2, IP: "192.0.2.2", BannedUntil: now.Add(2 * time.Hour)}

	pool.mutex.Lock()
	pool.scheduleUnban(ctx, &first)
	pool.scheduleUnban(ctx, &second)
	first.BannedUntil = now.Add(3 * time.Hour)
	pool.scheduleUnban(ctx, &first)
	scheduler := pool.expirations
	n := len(scheduler.queue)
	next := scheduler.queue[0].id
	due := scheduler.byIP[first.IP].due
	pool.mutex.Unlock()

	if n != 2 || next != second.ID || !due.Equal(first.BannedUntil) {
		t.Fatalf("queue len = %d, next ID = %d, extended deadline = %v", n, next, due)
	}
	cancel()
	select {
	case <-scheduler.done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
}
