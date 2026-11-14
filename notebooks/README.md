# BGP notebooks

[01 · A withdrawal belongs to a peer](01_a_withdrawal_belongs_to_a_peer.ipynb)
reconstructs peer-specific routing observations from a synthetic MRT RIB and
update stream. Visible SQL decodes the files through the released VGI worker,
checks ordering assumptions and computes state at each cutoff. Two charts compare
active observations, distinct prefixes and AS-path lengths. The end experiment
includes a withdrawal without treating its absent path as zero hops.

## Run from this directory

Install [uv](https://docs.astral.sh/uv/), then:

```sh
cd notebooks
uv sync --locked
uv run --locked python execute.py
```

In a notebook editor select this directory's `.venv/bin/python` kernel and run
all cells. Python 3.13–3.14 is supported; `uv` can provision the interpreter. The
complete notebook directory works outside the worker checkout. No Rust compiler,
local worker build, API credentials or root virtual environment is needed.

The visible connection uses the published native release:

```sql
INSTALL vgi FROM community;
LOAD vgi;
INSTALL inet FROM core;
LOAD inet;
ATTACH 'bgp' (TYPE vgi,
  LOCATION 'github-auto://Query-farm/vgi-bgp@v0.4.0');
```

VGI downloads the platform archive, verifies its SHA256 sidecar and caches it.
The notebook locks Haybarn 2.0.0rc11 and its Python dependencies. Initial setup
needs network access; the analysis reads only bundled local MRT fixtures. Change
the literal release tag and rerun both parameter settings when adopting a newer
worker. The INET extension handles IPv4/IPv6 casts and native address operations.

Parameters, connection SQL, analytical SQL and useful outputs stay visible.
Imports, styling, plotting, prose-generation source and cleanup are folded.

## One-parameter experiment

```sh
uv run --locked python execute.py --parameters '{"UPDATES_THROUGH_SECOND":2}' \
  --output-dir validation/through-2
```

The parameter is an inclusive offset in seconds from the fixture timestamp
2025-06-29 00:00:00 UTC. It accepts 0, 1 and 2; default 1, experiment 2. The
full reference timeline is always calculated. The parameter selects the shaded
stage, interpretation and path comparison. Reset to 1 afterward.

The runner uses a fresh kernel, rejects unknown parameters and source-directory
overwrites, and replaces saved notebooks only after a successful execution.
Overrides require a separate output directory. Copies include this guide,
fixtures, branding, helpers and the locked environment. Logs, extracted charts
and experimental copies are ignored under `validation/`; the main notebook keeps
its successful outputs and embedded charts.

## Provenance and reconstruction contract

All three MRT files are unchanged deterministic repository fixtures, with source
revision and SHA256 checksums in [fixtures/README.md](fixtures/README.md). They
are generated examples, not captured Internet traffic. No addresses or ASN
labels should be interpreted as evidence about real routing incidents.

The complete RIB seeds three peer-prefix paths. Two announcements change paths;
a withdrawal later removes one peer's IPv4 path. The truncated RIB is diagnostic
only. Its error row shows why a partial decode must not be mistaken for an absent
route. The reconstruction scans use `strict => true` to reject malformed input.

Within this single synthetic collector, state is keyed by peer IP, peer ASN and
prefix. The seed is applied before the updates, including the announcement that
shares the seed's timestamp. Internal stage -1 denotes that ordering; it is not
an earlier observed timestamp. Updates are included through the selected second.
Checks reject duplicate seed keys and same-key, same-time updates before the
latest-event window runs. Withdrawals are filtered only after choosing the latest
event, preventing older announcements from being resurrected.

The synthetic sequence contains no session resets, ADD-PATH or AS_SET ambiguity.
Production replay needs collector/session identity, stable record ordering,
snapshot/update alignment and reset handling. A prefix observed through another
peer is not proof of global or data-plane reachability. This notebook does not
perform best-path selection, RPKI validation or hijack detection.

AS-path length counts entries, including adjacent prepends; it is not a count of
unique networks or a latency measure. A withdrawal has no current path length,
and its chart row is explicitly labeled instead of plotted as zero.

The official Strata Sun and VGI media-kit assets are unchanged. Linked Strata Sun
branding appears at the top and final bottom of the notebook.

References: [worker documentation](https://github.com/Query-farm/vgi-bgp),
[pinned release](https://github.com/Query-farm/vgi-bgp/releases/tag/v0.4.0).
