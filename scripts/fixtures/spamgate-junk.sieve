# SpamGate reference rule for a trusted Postfix Milter -> Dovecot LDA
# pipeline. Inbound X-SpamGate-* headers MUST be removed by the Milter.
# The destination Junk mailbox must already exist.
require ["fileinto"];
if allof (
    header :matches "X-SpamGate-ID" "?*",
    header :is "X-SpamGate-Action" ["tag", "quarantine"]
) {
    fileinto "Junk";
    stop;
}
