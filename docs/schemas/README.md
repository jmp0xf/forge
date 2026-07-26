# Machine-readable Schemas

M0 will export versioned JSON Schemas here from `forge-schema` using `schemars`. Generated Schema files are checked
in because Forge's output is a behavior interface consumed by agents, scripts, and CI. `xtask check-schemas` will
fail when code and checked-in schemas differ without an explicit version or compatibility decision.
