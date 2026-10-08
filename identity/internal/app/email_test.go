package app

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
)

type blockedDelivery struct {
	started chan struct{}
	release chan struct{}
	active  atomic.Int32
	maximum atomic.Int32
}

func (d *blockedDelivery) DeliverOne(ctx context.Context) (bool, error) {
	active := d.active.Add(1)
	defer d.active.Add(-1)
	for {
		previous := d.maximum.Load()
		if previous >= active || d.maximum.CompareAndSwap(previous, active) {
			break
		}
	}
	d.started <- struct{}{}
	<-ctx.Done()
	<-d.release
	return true, ctx.Err()
}

func TestEmailWorkerLifecycle(t *testing.T) {
	for _, count := range []int{1, 2, 4} {
		t.Run(strconv.Itoa(count)+" workers", func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				delivery := &blockedDelivery{
					started: make(chan struct{}, count+1),
					release: make(chan struct{}),
				}
				release := sync.OnceFunc(func() { close(delivery.release) })
				defer release()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				application := &App{
					email:        delivery,
					emailWorkers: count,
					log:          zap.NewNop(),
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					application.runEmailDelivery(ctx)
				}()
				for range count {
					select {
					case <-delivery.started:
					case <-time.After(2 * time.Second):
						t.Fatal("workers did not start concurrently")
					}
				}
				cancel()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("shutdown returned before active workers")
				default:
				}
				release()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("workers did not stop")
				}
				if delivery.maximum.Load() != int32(count) || delivery.active.Load() != 0 {
					t.Fatalf("maximum=%d active=%d", delivery.maximum.Load(), delivery.active.Load())
				}
			})
		})
	}
}
