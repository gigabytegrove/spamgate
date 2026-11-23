# SMTP overload acceptance safety — 2026-11-23

Issue #3 / #6 availability boundary. The listener previously performed a synchronous write of the 421 response on its accept goroutine when all 64 handler slots were occupied. A connected peer that did not read could block that write indefinitely, preventing the listener from accepting any other connection. The overload path now closes the excess connection without attempting to write a greeting or response. SMTP peers must treat disconnect-before-greeting as a transient transport failure; this does not alter an accepted transaction or durable queue state.

The change deliberately avoids an unbounded goroutine per rejected connection and preserves the 64-slot cap. The tradeoff is that an overloaded peer receives a disconnect rather than an SMTP 421 status.

Tests exercise a non-reading net.Pipe peer, concurrent rejection, and nil handling. Tests were committed but NOT EXECUTED: the available local Go toolchain is 1.23.2 and GitHub DNS checkout failed; no owner-controlled native Linux builder was available. Real Postfix retry behavior and production-host acceptance remain NOT EXECUTED. No Actions or production deployment were used.
