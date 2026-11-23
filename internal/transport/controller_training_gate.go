package transport

import "sync"

// controllerTrainingGate bounds concurrent classifier training requests per
// controller. Requests rejected at capacity never read a sample or mutate Bayes.
// A zero-value gate is ready for use, including in directly constructed servers.
type controllerTrainingGate struct {
 once sync.Once
 slots chan struct{}
}

const controllerMaxConcurrentTraining = 2

func (g *controllerTrainingGate) acquire() bool {
 g.once.Do(func() { g.slots = make(chan struct{}, controllerMaxConcurrentTraining) })
 select {
 case g.slots <- struct{}{}:
  return true
 default:
  return false
 }
}

func (g *controllerTrainingGate) release() {
 <-g.slots
}
