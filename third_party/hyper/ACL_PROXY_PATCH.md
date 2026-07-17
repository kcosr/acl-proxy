# acl-proxy Hyper Patch

This directory is the crates.io source for Hyper 0.14.32, retained under its
upstream MIT license. acl-proxy uses it until the planned transport dependency
modernization removes the Hyper 0.14 server.

The product's downstream server selects this tree as an exact direct path
dependency. The shared runtime's private upstream client remains on the exact
crates.io Hyper 0.14.32 package; no Cargo source override couples the two.

The sole behavioral patch is in `src/proto/h2/server.rs`: dropping an
unfinished server `H2Stream` explicitly sends `RST_STREAM(CANCEL)`. Upstream
Hyper delegates response bytes to h2 before flow control has necessarily sent
the complete `Buf`. Dropping the stream future after a partial send otherwise
leaves that queued remainder referenced, so h2 cannot infer cancellation and
the stream remains open indefinitely.

The added `finished` bit distinguishes normal future completion from
cancellation. A pinned drop sends `CANCEL` only when the future has not reached
`Poll::Ready`; normal responses retain upstream behavior.

The product wire regressions in `src/proxy/ingress.rs` cover zero-window empty
and nonempty responses, partial final-chunk delivery, exact-window final-chunk
delivery, stream-local reset, sibling progress, origin closure, and admission
release.
