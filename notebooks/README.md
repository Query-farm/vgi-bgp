# MRT observations and community labels

| Notebook | Question | Run |
|---|---|---|
| [01 · A withdrawal belongs to a peer](01_a_withdrawal_belongs_to_a_peer.ipynb) | Which peer-specific route observations survive an update and withdrawal? | [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-bgp/blob/main/notebooks/01_a_withdrawal_belongs_to_a_peer.ipynb) |
| [02 · Community shape comes before policy](02_community_shape_comes_before_policy.ipynb) | Would parsing only standard communities miss labels attached to a route? | [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-bgp/blob/main/notebooks/02_community_shape_comes_before_policy.ipynb) |

Both notebooks attach the published native **v0.4.0** worker through a visible
`github-auto://Query-farm/vgi-bgp@v0.4.0` location. VGI checks the platform archive's
SHA256 sidecar and starts it locally. Initial setup requires network access; all
routing inputs are **synthetic MRT fixtures**, not captured Internet traffic.
No worker checkout, Rust build, API account or live routing feed is required.

In Colab choose **Runtime → Run all**. The bootstrap installs only the base shared
package and retrieves immutable hash-verified companions. Compatible preinstalled
kernel and plotting libraries remain installed. Use the `[runner]` extra only in
the local locked publication environment:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks 01_a_withdrawal_belongs_to_a_peer.ipynb --parameters '{"UPDATES_THROUGH_SECOND":2}' --output-dir artifacts/through-2
uv run --locked vgi-notebooks 02_community_shape_comes_before_policy.ipynb --parameters '{"SELECTED_ADMIN":65002}' --output-dir artifacts/admin-65002
```

For local interactive Jupyter select `notebooks/.venv/bin/python`; the runner
creates its own temporary kernel. Overrides require a separate destination.
Failed executions preserve saved defaults. If an older Colab bootstrap replaced
kernel libraries, save your work, choose **Runtime → Disconnect and delete runtime**,
and reopen this current example.

Canonical branding, isolated SQL secrets, SVG output and execution protections
come from [vgi-example-notebooks](https://github.com/Query-farm/vgi-example-notebooks).
The [shared v0.3.5 standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.5/docs/standard.md) replaces duplicated notebook infrastructure. `bgp_example.py`
validates parameters and presents returned results; worker calls and analytical
transformations stay in visible SQL. Keep committed `charts/` SVGs with saved
notebooks for GitHub rendering. Colab/Jupyter reruns emit native SVG; PNG review
exports remain ignored under `artifacts/review/`.

The two stories cover **all ten public named SQL surfaces**, with overloads and
relation aliases counted once. `coverage.json` binds full released/current runtime
catalogs, successful execution receipts and reviewed SQL/result/interpretation
mappings. Both catalogs contain nine functions and the `example_rib` view. **Current
main adds `peer_ip` to that view and changes its column order.** Full `DESCRIBE`
exports and view signatures record this drift. Notebook 02 projects only named
columns shared by both interfaces; notebook 01 gets the complete peer key from
`read_rib` and `peers`. The actual notebook runtime is v0.4.0; current-interface
compatibility is not a claim of current-main notebook execution.

The unchanged [fixture files](fixtures/README.md) retain their generator revision
and SHA256 provenance. Their timestamps start at **2025-06-29 00:00:00 UTC**.
Notebook 01 materializes each scan, checks the peer index, and reconstructs state
by **peer IP + peer ASN + prefix**. The seed precedes same-timestamp updates;
internal stage -1 is an ordering label, not an earlier observed time. Withdrawals
are removed only after selecting the latest event, so an old announcement cannot
be resurrected. A damaged RIB is diagnostic only. Missing paths retain NULL length
and ASN membership instead of becoming zero hops or a current nonmember path.

The first experiment changes only `UPDATES_THROUGH_SECOND` from **1 to 2**, an
inclusive UTC-second offset. The input population and complete timeline stay
fixed. This fixture omits session resets, ADD-PATH, AS_SET ambiguity and ties.
Production reconstruction needs collector/session identity, stable record order,
snapshot alignment and completeness checks. Origin-AS equality, ASN membership,
path length and surviving observations do not establish address ownership, route
authorization, hijacking, policy rationale or data-plane reachability.

Notebook 02 uses the worker's built-in decoded sample view. It keeps the three
route observations separate from their four community labels and from authored
parser diagnostics. The second experiment changes only `SELECTED_ADMIN` from
**65001 to 65002**, retaining the full route population. An absent administrator
produces an empty selection. A NULL standard parse may represent a valid large
community. The worker's two-part parser accepts unsigned 32-bit fields; parsing
`65536:1` therefore does not enforce standard-community 16-bit field widths.
[RFC 1997](https://www.rfc-editor.org/rfc/rfc1997) and
[RFC 8092](https://www.rfc-editor.org/rfc/rfc8092) specify the formats and their
semantics. This example has no operator policy dictionary, router configuration
or observed export behavior, so it does not demonstrate policy enforcement.

Default runs, one separate experiment per notebook, an empty community selection,
runner guards and already-imported Colab-compatible libraries are checked. A Colab
link is not a claim of manually operating a hosted Colab session. Worker checks
remain those in `CLAUDE.md`; notebook changes preserve source and root locks.
