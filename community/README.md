# Community

## Join the CCS Ecosystem

CCS is an open standard for cryptographically verifiable agent runtime receipts. We're building a network of framework adapters, conformance test suites, and production deployments.

## How to Get Involved

### Build an Adapter

Pick a framework you use and build a CCS adapter. Each adapter lives in `adapters/<framework-name>/` and must:

1. Use the framework's native interception API (no forking)
2. Produce 30-field L1 receipts compatible with `ccs-verifier==1.3.0`
3. Support in-process and sidecar key modes
4. Include tamper detection tests
5. Pass reference conformance vectors

Open a PR with your adapter and we'll list it in the README.

### Run Conformance Tests

Clone the [conformance vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors) and run them against your CCS implementation. If all 26 checks pass, you're CCS-conformant.

### Report Spec Gaps

Found something the spec doesn't cover? Open an issue with:
- The scenario
- What the current spec says
- What you think should happen

### Framework Maintainers

If you maintain an agent framework and want CCS support natively:
- The core receipt format is stable (30 fields, Ed25519, JCS)
- Adapters are MIT-licensed and can be vendored
- `ccs-verifier` is ELv2 but pip-installable for verification
- We're happy to help with architecture review

## Ecosystem Projects

| Project | Relationship | Link |
|---------|-------------|------|
| ccs-verifier | Core verification engine (ELv2) | [PyPI](https://pypi.org/project/ccs-verifier/) |
| ccs-conformance-vectors | Reference test vectors (CC0) | [GitHub](https://github.com/DSHCorrectover/ccs-conformance-vectors) |
| IETF draft | Specification | [draft-correctover-ccs-08](https://www.ietf.org/archive/id/draft-correctover-ccs-08.txt) |
| RootSign/PDR | Paired vectors + crosswalk | [rootsign#37](https://github.com/Providex-AI/rootsign/issues/37) |

## Communication

- GitHub Issues: bug reports, feature requests, adapter proposals
- IETF mailing list: standardization discussions
