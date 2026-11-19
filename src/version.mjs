// CivSwitchFS-kaihen payload version.
//
// Bump this whenever the chain's SD contract changes (manifest shape,
// file list, staging protocol) or behavior a kaiHEN release must
// distinguish. kaiHEN releases declare which payload versions they
// support in /kaihen/kaihen-civswitch.json, keyed "v" + this number
// ({"support": {"v3": {...}}, "skip_version_check": false}) — the chain
// reads that file at startup and refuses to run against a kaiHEN
// release that does not list its version.
export const PAYLOAD_VERSION = 3;
