# Huge-output seed

The fixture test supplies a tracked payload and exposes the host `cat` binary under the unique
`forge-fixture-cat` name. Forge invokes that argv-only command and must record the complete byte
count while bounding retained output.
