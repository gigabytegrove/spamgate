package transport

import (
 "sync"
 "testing"
)

func TestControllerTrainingGateCapacityAndRecovery(t *testing.T) {
 var gate controllerTrainingGate
 for i:=0;i<controllerMaxConcurrentTraining;i++ {
  if !gate.acquire() { t.Fatalf("slot %d unexpectedly refused",i) }
 }
 if gate.acquire() { t.Fatal("accepted training above configured capacity") }
 gate.release()
 if !gate.acquire() { t.Fatal("released capacity was not reusable") }
 for i:=0;i<controllerMaxConcurrentTraining;i++ { gate.release() }
 if !gate.acquire() { t.Fatal("gate did not recover after draining") }
 gate.release()
}

func TestControllerTrainingGateConcurrentAdmission(t *testing.T) {
 var gate controllerTrainingGate
 const contenders=128
 start:=make(chan struct{})
 results:=make(chan bool,contenders)
 var wg sync.WaitGroup
 for i:=0;i<contenders;i++ {
  wg.Add(1)
  go func(){
   defer wg.Done()
   <-start
   results<-gate.acquire()
  }()
 }
 close(start)
 wg.Wait()
 close(results)
 accepted:=0
 for ok:=range results { if ok { accepted++ } }
 if accepted!=controllerMaxConcurrentTraining {
  t.Fatalf("accepted %d concurrent requests; limit %d",accepted,controllerMaxConcurrentTraining)
 }
 for i:=0;i<accepted;i++ { gate.release() }
 if !gate.acquire() { t.Fatal("gate stayed saturated after releasing requests") }
 gate.release()
}

func TestControllerTrainingGatesIndependent(t *testing.T) {
 var a,b controllerTrainingGate
 for i:=0;i<controllerMaxConcurrentTraining;i++ {
  if !a.acquire() { t.Fatal("first controller unexpectedly full") }
 }
 if !b.acquire() { t.Fatal("second controller shared first controller capacity") }
 b.release()
 for i:=0;i<controllerMaxConcurrentTraining;i++ { a.release() }
}
