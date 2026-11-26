package banpool

import (
	"container/heap"
	"context"
	"errors"
	"log"
	"time"
)

type unbanEntry struct {
	ip      string
	id      int64
	ctx     context.Context
	due     time.Time
	retryAt time.Time
	retries int
	index   int
}

type unbanQueue []*unbanEntry

func (q unbanQueue) Len() int           { return len(q) }
func (q unbanQueue) Less(i, j int) bool { return q[i].due.Before(q[j].due) }
func (q unbanQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index, q[j].index = i, j
}

func (q *unbanQueue) Push(value any) {
	entry := value.(*unbanEntry)
	entry.index = len(*q)
	*q = append(*q, entry)
}

func (q *unbanQueue) Pop() any {
	last := len(*q) - 1
	entry := (*q)[last]
	(*q)[last] = nil
	*q = (*q)[:last]
	return entry
}

type unbanContext struct {
	count int
	stop  func() bool
}

type unbanScheduler struct {
	queue    unbanQueue
	byIP     map[string]*unbanEntry
	contexts map[<-chan struct{}]*unbanContext
	wake     chan struct{}
	done     chan struct{}
}

func (bp *banPool) scheduleUnban(ctx context.Context, ban *Ban) {
	scheduler := bp.expirations
	if scheduler != nil {
		if entry := scheduler.byIP[ban.IP]; entry != nil {
			if entry.id == ban.ID && entry.ctx.Err() == nil {
				due := ban.BannedUntil
				if entry.retryAt.After(due) {
					due = entry.retryAt
				}
				if !due.Equal(entry.due) {
					entry.due = due
					heap.Fix(&scheduler.queue, entry.index)
					scheduler.signal()
				}
				return
			}
			scheduler.remove(entry)
		}
	}
	if ctx.Err() != nil {
		if scheduler != nil {
			scheduler.signal()
		}
		return
	}
	if scheduler == nil {
		scheduler = &unbanScheduler{
			byIP:     make(map[string]*unbanEntry),
			contexts: make(map[<-chan struct{}]*unbanContext),
			wake:     make(chan struct{}, 1),
			done:     make(chan struct{}),
		}
		bp.expirations = scheduler
		go bp.runUnbanScheduler(scheduler)
	}
	entry := &unbanEntry{ip: ban.IP, id: ban.ID, ctx: ctx, due: ban.BannedUntil}
	scheduler.byIP[entry.ip] = entry
	heap.Push(&scheduler.queue, entry)
	bp.watchUnbanContext(scheduler, ctx)
	scheduler.signal()
}

func (bp *banPool) watchUnbanContext(scheduler *unbanScheduler, ctx context.Context) {
	done := ctx.Done()
	if done == nil {
		return
	}
	group := scheduler.contexts[done]
	if group == nil {
		group = &unbanContext{}
		scheduler.contexts[done] = group
		group.stop = context.AfterFunc(ctx, func() {
			bp.mutex.Lock()
			defer bp.mutex.Unlock()
			if scheduler.contexts[done] != group {
				return
			}
			for _, entry := range scheduler.byIP {
				if entry.ctx.Done() == done {
					scheduler.remove(entry)
				}
			}
			scheduler.signal()
		})
	}
	group.count++
}

func (bp *banPool) unscheduleUnban(ip string) {
	if scheduler := bp.expirations; scheduler != nil {
		if entry := scheduler.byIP[ip]; entry != nil {
			scheduler.remove(entry)
			scheduler.signal()
		}
	}
}

func (s *unbanScheduler) remove(entry *unbanEntry) {
	heap.Remove(&s.queue, entry.index)
	delete(s.byIP, entry.ip)
	done := entry.ctx.Done()
	if group := s.contexts[done]; group != nil {
		group.count--
		if group.count == 0 {
			group.stop()
			delete(s.contexts, done)
		}
	}
}

func (s *unbanScheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (bp *banPool) runUnbanScheduler(scheduler *unbanScheduler) {
	defer close(scheduler.done)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		bp.mutex.Lock()
		if len(scheduler.queue) == 0 {
			bp.expirations = nil
			bp.mutex.Unlock()
			return
		}
		entry := scheduler.queue[0]
		delay := time.Until(entry.due)
		if delay <= 0 {
			bp.expireBan(scheduler, entry)
			bp.mutex.Unlock()
			continue
		}
		timer.Reset(delay)
		bp.mutex.Unlock()
		select {
		case <-timer.C:
		case <-scheduler.wake:
			timer.Stop()
		}
	}
}

func (bp *banPool) expireBan(scheduler *unbanScheduler, entry *unbanEntry) {
	if entry.ctx.Err() != nil {
		scheduler.remove(entry)
		return
	}
	current, err := bp.repository.Get(entry.ip)
	if err != nil {
		if !errors.Is(err, ErrBanNotFound) {
			log.Println(err)
		}
		scheduler.remove(entry)
		return
	}
	if current.ID != entry.id {
		scheduler.remove(entry)
		return
	}
	if current.BannedUntil.After(time.Now()) {
		entry.due = current.BannedUntil
		heap.Fix(&scheduler.queue, entry.index)
		return
	}

	if err := bp.removeBan(current); err != nil {
		log.Println(err)
		if entry.retries < maxUnbanRetries {
			entry.retries++
			entry.retryAt = time.Now().Add(unbanRetryInterval)
			entry.due = entry.retryAt
			heap.Fix(&scheduler.queue, entry.index)
			return
		}
	}
	scheduler.remove(entry)
}
