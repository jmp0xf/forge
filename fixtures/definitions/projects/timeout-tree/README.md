# Timeout-tree seed

The fixture test exposes the host `sleep` binary under the unique `forge-fixture-sleep` name to
verify the public CLI timeout/Receipt boundary without shell expansion. The runtime process-tree
tests separately create a parent and descendant and prove that both are terminated.
