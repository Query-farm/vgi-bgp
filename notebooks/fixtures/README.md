# Synthetic MRT examples

Copied unchanged from this repository’s deterministic `data/` fixtures at
commit `9e605a3c60138c83ccd2e60e8f16faa610cf789c`. These are generated examples, not observed RouteViews or RIPE traffic.
The generator is [data/generate_fixtures.rs](https://github.com/Query-farm/vgi-bgp/blob/9e605a3c60138c83ccd2e60e8f16faa610cf789c/data/generate_fixtures.rs).

Fixture timestamps begin at 2025-06-29 00:00:00 UTC. The truncated RIB is
a deliberately damaged copy used only to demonstrate error rows.

SHA256:

```text
4c0e728c68134852514e1bdfdf3c36071751943f006f12f5f8ae370819a2ec8a  updates.mrt
a4e386b86c4aff7b7c5fd01c3aca5867b9b344314792cd890148fea71f0dc31f  rib.mrt
1fb160e037f0061fd127fdbc0fbf361132bd4b761fd7160624f46f7f3bea7d08  truncated.mrt
```
