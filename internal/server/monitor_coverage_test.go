package server

import (
    "strings"
    "testing"
    "time"
)

func TestMonitorCoverageAlertsRequireSameBootAndPersist(t *testing.T) {
    dir:=t.TempDir()
    m:=newOperationsMonitor(dir)
    at:=time.Date(2026,10,30,21,0,0,0,time.UTC)
    first:=monitorSample{At:at,BootID:m.bootID,MIMECoverageIncomplete:10,PhishingCoverageIncomplete:10}
    if err:=m.record(first);err!=nil{t.Fatal(err)}
    state,err:=m.snapshot();if err!=nil{t.Fatal(err)}
    if len(state.Alerts)!=0{t.Fatal("first sample must not invent a rate")}
    second:=first
    second.At=at.Add(time.Minute)
    second.MIMECoverageIncomplete+=6
    second.PhishingCoverageIncomplete+=7
    if err:=m.record(second);err!=nil{t.Fatal(err)}
    state,err=m.snapshot();if err!=nil{t.Fatal(err)}
    if len(state.Alerts)!=2{t.Fatalf("missing coverage alerts: %+v",state.Alerts)}
    for _,a:=range state.Alerts{
        if a.State!="open"||a.Severity!="warning"||strings.Contains(a.Summary,"@"){
            t.Fatalf("invalid coverage alert: %+v",a)
        }
    }
    restarted:=newOperationsMonitor(dir)
    next:=second
    next.At=second.At.Add(time.Minute)
    next.BootID=restarted.bootID
    next.MIMECoverageIncomplete=0
    next.PhishingCoverageIncomplete=0
    if err:=restarted.record(next);err!=nil{t.Fatal(err)}
    state,err=restarted.snapshot();if err!=nil{t.Fatal(err)}
    for _,a:=range state.Alerts{
        if a.State!="open"{t.Fatal("restart incorrectly resolved a rate alert")}
    }
    next.At=next.At.Add(time.Minute)
    if err:=restarted.record(next);err!=nil{t.Fatal(err)}
    state,err=restarted.snapshot();if err!=nil{t.Fatal(err)}
    for _,a:=range state.Alerts{
        if a.State!="resolved"||a.ResolvedAt==nil{t.Fatalf("alert did not resolve after clean same-boot interval: %+v",a)}
    }
}

func TestMonitorCoverageThresholdsAreBounded(t *testing.T) {
    t.Setenv("SPAMGATE_MONITOR_MIME_COVERAGE_THRESHOLD","not-a-number")
    if monitorThreshold("SPAMGATE_MONITOR_MIME_COVERAGE_THRESHOLD",5)!=5{t.Fatal("invalid threshold accepted")}
    t.Setenv("SPAMGATE_MONITOR_MIME_COVERAGE_THRESHOLD","0")
    if monitorThreshold("SPAMGATE_MONITOR_MIME_COVERAGE_THRESHOLD",5)!=5{t.Fatal("zero threshold accepted")}
    t.Setenv("SPAMGATE_MONITOR_MIME_COVERAGE_THRESHOLD","3")
    if monitorThreshold("SPAMGATE_MONITOR_MIME_COVERAGE_THRESHOLD",5)!=3{t.Fatal("valid threshold ignored")}
}
