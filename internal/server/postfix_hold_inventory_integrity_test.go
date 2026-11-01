package server

import (
    "strings"
    "testing"
)

// The Postfix queue inventory is not just telemetry: its fields authorize
// a privileged postsuper -H on an exact held message. The parser must reject
// ambiguous JSON before any queue ID, sender, recipient or timestamp can
// participate in that decision.
func TestPostfixHoldInventoryRejectsAmbiguousOwnershipJSON(t *testing.T) {
    valid := `{"queue_name":"hold","queue_id":"AB12CD","sender":"sender@example.org","arrival_time":1793100000,"message_size":1234,"recipients":[{"address":"first@example.org"},{"address":"second@example.org"}]}`
    cases := []struct {
        name string
        raw string
    }{
        {"duplicate queue ID", `{"queue_name":"hold","queue_id":"SAFE12","queue_id":"OTHER12","sender":"sender@example.org","arrival_time":1793100000,"recipients":[{"address":"a@example.org"}]}`},
        {"case folded queue ID", `{"queue_name":"hold","queue_id":"SAFE12","QUEUE_ID":"OTHER12","arrival_time":1793100000,"recipients":[{"address":"a@example.org"}]}`},
        {"escaped duplicate queue ID", `{"queue_name":"hold","queue_id":"SAFE12","queue_\\u0069d":"OTHER12","arrival_time":1793100000,"recipients":[{"address":"a@example.org"}]}`},
        {"duplicate sender", `{"queue_name":"hold","queue_id":"SAFE12","sender":"first@example.org","sender":"second@example.org","arrival_time":1793100000,"recipients":[{"address":"a@example.org"}]}`},
        {"duplicate recipient array", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"recipients":[{"address":"a@example.org"}],"recipients":[{"address":"b@example.org"}]}`},
        {"nested duplicate recipient address", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"recipients":[{"address":"a@example.org","address":"b@example.org"}]}`},
        {"duplicate timestamp", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"arrival_time":1793109999,"recipients":[{"address":"a@example.org"}]}`},
        {"trailing JSON", valid+` {"queue_name":"hold"}`},
        {"invalid UTF8", valid+string([]byte{0xff})},
        {"zero arrival", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":0,"recipients":[{"address":"a@example.org"}]}`},
        {"missing arrival", `{"queue_name":"hold","queue_id":"SAFE12","recipients":[{"address":"a@example.org"}]}`},
        {"negative size", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"message_size":-1,"recipients":[{"address":"a@example.org"}]}`},
        {"empty recipients", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"recipients":[]}`},
        {"empty recipient address", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"recipients":[{"address":""}]}`},
        {"wrong recipient type", `{"queue_name":"hold","queue_id":"SAFE12","arrival_time":1793100000,"recipients":["a@example.org"]}`},
        {"truncated JSON", strings.TrimSuffix(valid,"}")},
    }
    for _, tc := range cases {
        t.Run(tc.name,func(t *testing.T){
            if got,err:=parsePostfixHold([]byte(tc.raw+"\n"));err==nil{
                t.Fatalf("unsafe inventory accepted: %+v",got)
            }
        })
    }
}

func TestPostfixHoldInventoryAllowsRealPostqueueOptionalFields(t *testing.T) {
    payload:=`{"queue_name":"active","queue_id":"AAAA12","sender":"sender@example.org","arrival_time":1793100000,"message_size":20,"recipients":[{"address":"a@example.org"}]}
{"queue_name":"hold","queue_id":"BEEF12","sender":"","arrival_time":1793100001,"message_size":234,"recipients":[{"address":"bob@example.org","delay_reason":"temporary destination failure"},{"address":"alice@example.org"}],"forced_expire":false}
`
    held,err:=parsePostfixHold([]byte(payload))
    if err!=nil{t.Fatal(err)}
    if len(held)!=1||held[0].QueueID!="BEEF12"||held[0].Sender!=""||held[0].RecipientCount!=2||held[0].Recipients[0]!="bob@example.org"||held[0].Recipients[1]!="alice@example.org"{
        t.Fatalf("valid Postfix HOLD inventory rejected or changed: %+v",held)
    }
}
