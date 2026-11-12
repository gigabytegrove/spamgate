package smtpprobe

import "testing"

func TestTrustworthyStartTLS(t *testing.T) {
 cases := []struct{name string; lines []string; want bool}{
  {"bare",[]string{"mx.example","STARTTLS"},true},
  {"identity is not extension",[]string{"STARTTLS"},false},
  {"case insensitive",[]string{"mx.example","starttls"},true},
  {"missing",[]string{"mx.example","PIPELINING"},false},
  {"parameterized",[]string{"mx.example","STARTTLS unsupported"},false},
  {"duplicate",[]string{"mx.example","STARTTLS","STARTTLS"},false},
  {"valid then malformed",[]string{"mx.example","STARTTLS","STARTTLS unexpected"},false},
  {"malformed then valid",[]string{"mx.example","STARTTLS unexpected","STARTTLS"},false},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  if got:=trustworthyStartTLS(tc.lines);got!=tc.want {t.Fatalf("trustworthyStartTLS=%v want %v",got,tc.want)}
 })}
}

func TestCapabilityParserAmbiguousSTARTTLS(t *testing.T) {
 cases:=[][]string{
  {"mx.example","STARTTLS","STARTTLS"},
  {"mx.example","STARTTLS","STARTTLS unexpected"},
  {"mx.example","STARTTLS unexpected","STARTTLS"},
 }
 for _,lines:=range cases {
  advertised,_:=capabilities(lines)
  if advertised {t.Fatalf("ambiguous STARTTLS was accepted: %v",lines)}
 }
}
