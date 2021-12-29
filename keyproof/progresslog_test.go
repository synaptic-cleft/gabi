package keyproof

import "sync/atomic"

// Running keyproof takes a long time (standard 2048 bits key results in a ~700 mb proof).
// The terminal will give feedback on how far the proof is.
// This information is provided by the TestFollower's Tick method.
type TestFollower struct {
	count int64
}

func (_ *TestFollower) StepStart(desc string, intermediates int) {}

func (t *TestFollower) Tick() {
	atomic.AddInt64(&t.count, 1)
}

func (t *TestFollower) StepDone() {}

func init() {
	Follower = &TestFollower{}
}
