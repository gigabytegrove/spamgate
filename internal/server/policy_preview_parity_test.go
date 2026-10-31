package server

import (
	"testing"
	"github.com/gigabytegrove/spamgate/internal/core"
)
func TestPolicyPreviewScannerParityForUniformAndConflictingRecipients(t *testing.T) {
	p:=policyPreviewRequest{TagThreshold:5,QuarantineThreshold:10,RejectThreshold:20,Limit:20}
	policies:=[]core.RecipientPolicy{
		{Mailbox:"alice@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3},
		{Mailbox:"bob@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3},
		{Mailbox:"carol@example.org",TagThreshold:2,QuarantineThreshold:4,RejectThreshold:6},
	}
	for _,tc:=range []struct{recipients []string;source,action string}{
		{[]string{"alice@example.org"},"mailbox","reject"},
		{[]string{"alice@example.org","ALICE@example.org"},"mailbox","reject"},
		{[]string{"alice@example.org","bob@example.org"},"mailbox_shared","reject"},
		{[]string{"alice@example.org","carol@example.org"},"global_multi_recipient","accept"},
		{[]string{"alice@example.org","unknown@example.org"},"global_multi_recipient","accept"},
		{[]string{"unknown@example.org"},"global","accept"},
	}{
		got:=previewOne(core.Message{ID:"preview",Recipients:tc.recipients,Score:4,Action:"accept"},p,policies)
		if got.PolicySource!=tc.source||got.HypotheticalAction!=tc.action{t.Fatalf("preview parity: %+v",got)}
	}
}
