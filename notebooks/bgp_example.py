"""Present synthetic MRT route observations and community structure; domain SQL stays visible."""

import matplotlib.pyplot as plt
import numpy as np
from IPython.display import display
from matplotlib.ticker import MaxNLocator
from matplotlib.colors import ListedColormap
from vgi_notebooks import finish, prose

SOURCE = (
    "Source: synthetic MRT fixtures · native VGI BGP v0.4.0 · fixture timestamps in UTC"
)


def validate_stage(value):
    if isinstance(value, bool) or not isinstance(value, int) or value not in {0, 1, 2}:
        raise ValueError(
            "UPDATES_THROUGH_SECOND must be 0, 1 or 2 (inclusive UTC seconds)."
        )


def validate_admin(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 4294967295
    ):
        raise ValueError("SELECTED_ADMIN must be an unsigned 32-bit integer.")


def quality_finding(quality):
    display(quality)
    used = quality[quality.source.str.endswith("(used)")]
    assert (used.error_rows == 0).all() and (used.decoded_rows > 0).all()
    broken = quality[quality.source.str.startswith("Truncated")].iloc[0]
    prose(
        f"The damaged file returns **{int(broken.decoded_rows)} decoded row(s)** plus **{int(broken.error_rows)} error row(s)**. That is a partial decode, not evidence that the missing routes were withdrawn. Reconstruction uses only the two complete inputs."
    )


def peer_finding(peer_frame):
    display(peer_frame)
    assert peer_frame.seed_paths.eq(1).all() and peer_frame.collector.isna().all()
    prose(
        f"The peer index contains **{len(peer_frame)} IP/ASN pairs** but only "
        f"**{peer_frame.peer_asn.nunique()} distinct ASNs**. Joining on ASN alone could "
        "merge separate peer observations. Every indexed peer has one path in this fixture. "
        "The collector field is missing here and stays missing; it is not a known collector identifier."
    )


def seed_finding(seed_paths):
    display(seed_paths)
    assert (seed_paths.origin_asn == seed_paths.path_origin).all()
    prose(
        f"**{int(seed_paths.via_64500.sum())} of {len(seed_paths)} seed paths include AS64500**. "
        "Adjacent repeated occurrences increase path length and prepend count, but membership stays boolean. "
        "The origin helper returns each sequence's last ASN and agrees with the decoded origin column; "
        "that agreement does not establish authorization or identify who operates an address block."
    )


def checks_finding(checks):
    display(checks)
    assert (checks.violations == 0).all(), (
        "The fixture no longer meets the reconstruction assumptions."
    )
    prose(
        f"All **{len(checks)} checks pass**. Within these explicit assumptions, the latest event for each key determines the observed state; a withdrawal retains the key but removes its active path."
    )


def timeline_chart(timeline, UPDATES_THROUGH_SECOND):
    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    for column, label, color, marker in (
        ("active_paths", "Active peer-prefix paths", "#456fba", "o"),
        ("visible_prefixes", "Distinct prefixes with a path", "#267358", "s"),
    ):
        ax.plot(
            timeline.asof_second,
            timeline[column],
            color=color,
            marker=marker,
            label=label,
            linewidth=2,
            drawstyle="steps-post",
        )
        for row in timeline.itertuples():
            ax.annotate(
                str(int(getattr(row, column))),
                (row.asof_second, getattr(row, column)),
                xytext=(0, 10 if column == "active_paths" else -18),
                textcoords="offset points",
                ha="center",
                color=color,
                weight="bold",
            )
    ax.axvspan(
        UPDATES_THROUGH_SECOND - 0.12,
        UPDATES_THROUGH_SECOND + 0.12,
        color="#c57b40",
        alpha=0.15,
    )
    ax.set(
        xticks=[-1, 0, 1, 2],
        xticklabels=["Seed RIB", "+0 s", "+1 s", "+2 s"],
        xlabel="Ordered fixture stages · update offsets from 2025-06-29 00:00:00 UTC",
        ylabel="Count",
        ylim=(0, max(timeline.active_paths.max(), timeline.visible_prefixes.max()) + 1),
    )
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(loc="lower left", frameon=True)
    finish(
        fig,
        "One peer's withdrawal need not erase the prefix",
        f"Complete reference stream · shaded selection: through +{UPDATES_THROUGH_SECOND} s inclusive",
        SOURCE,
        name="01-peer-state",
    )
    chosen = timeline[timeline.asof_second == UPDATES_THROUGH_SECOND].iloc[0]
    prose(
        f"Through **+{UPDATES_THROUGH_SECOND} seconds**, the reconstructed view contains **{int(chosen.active_paths)} active peer-prefix paths** covering **{int(chosen.visible_prefixes)} distinct prefixes**. A count of prefixes deliberately collapses multiple peer observations; retain the peer key when studying individual paths."
    )


def paths_chart(differences, UPDATES_THROUGH_SECOND):
    display(differences)
    y = np.arange(len(differences))
    fig, ax = plt.subplots(figsize=(12, 5.6))
    for offset, column, label, color in (
        (-0.18, "seed_hops", "Seed RIB", "#aab8b0"),
        (0.18, "selected_hops", f"Through +{UPDATES_THROUGH_SECOND} s", "#456fba"),
    ):
        present = differences[column].notna().to_numpy()
        values = differences.loc[present, column].to_numpy(dtype=float)
        bars = ax.barh(
            y[present] + offset, values, height=0.31, color=color, label=label
        )
        ax.bar_label(bars, fmt="%.0f", padding=4)
        for index in y[~present]:
            ax.text(
                0.08,
                index + offset,
                "withdrawn — no active path"
                if column == "selected_hops"
                else "no seed path",
                va="center",
                color="#a85337",
                fontsize=10,
            )
    labels = [
        f"{r.prefix}\nAS{r.peer_asn} · {r.peer_ip}" for r in differences.itertuples()
    ]
    ax.set(
        yticks=y,
        yticklabels=labels,
        xlabel="AS-path entries (including adjacent prepends)",
        ylabel="",
    )
    ax.invert_yaxis()
    ax.set_xlim(0, float(differences[["seed_hops", "selected_hops"]].max().max()) + 1.2)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right", frameon=True)
    finish(
        fig,
        "Keep withdrawn paths separate from shorter paths",
        f"Seed versus selected state · through +{UPDATES_THROUGH_SECOND} s inclusive",
        SOURCE,
        name="02-path-comparison",
    )
    changed = int((differences.status == "Changed").sum())
    withdrawn = int((differences.status == "Withdrawn").sum())
    prose(
        f"At this cutoff, **{changed} path(s) have changed** and **{withdrawn} path(s) are withdrawn** relative to the seed. The table preserves the individual ASN lists and prepend counts, so a changed length can be interpreted without treating a withdrawal as a zero-length route."
    )
    prose(
        f"The seed has **{int(differences.seed_via_64500.sum())} paths containing AS64500**; "
        f"the selected state has **{int(differences.selected_via_64500.eq(True).sum())}**. "
        "A withdrawn path has NULL membership, not a false claim about a current route. "
        "This records sequence membership, not an explanation of transit policy."
    )


def community_preview(routes):
    display(routes)
    prose(
        f"The built-in view returns **{len(routes)} synthetic route observations** with "
        f"**{sum(len(x) for x in routes.communities)} community strings**. "
        "The release view lacks peer IP, so this story uses only its shared ASN/prefix/path/communities projection. "
        "The paired notebook reads MRT files directly when it needs the full peer IP + ASN key."
    )


def community_finding(annotations, selected, summary, admin):
    display(annotations)
    display(selected)
    r = summary.iloc[0]
    prose(
        f"Selecting first numeric component **{admin}** retains **{int(r.selected_labels)} labels** "
        f"on **{int(r.selected_routes)} of {int(r.all_routes)} route observations**. "
        f"Only **{int(r.standard_only_routes)}** of those observations would be found by parsing standard "
        "two-part communities alone. A NULL standard parse can mean a valid large community; it does not "
        "mean the annotation is absent. The numeric fields are not an operator's policy dictionary."
    )


def community_chart(matrix_frame, admin):
    matrix = matrix_frame.pivot(
        index="route_label", columns="shape", values="label_count"
    ).reindex(columns=["Standard", "Large"])
    fig, ax = plt.subplots(figsize=(11.8, 5.8))
    ax.imshow(
        matrix.values,
        cmap=ListedColormap(["#e5ebe7", "#267358"]),
        vmin=0,
        vmax=1,
        aspect="auto",
    )
    ax.set_xticks(range(2), matrix.columns)
    ax.set_yticks(range(len(matrix)), [x.replace(" · ", "\n") for x in matrix.index])
    ax.tick_params(axis="y", labelsize=10)
    ax.set_xlabel("Community shape returned by the worker")
    ax.set_ylabel("")
    ax.grid(False)
    ax.set_xticks(np.arange(-0.5, 2, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(matrix), 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=3)
    ax.tick_params(which="minor", bottom=False, left=False)
    for y, row in enumerate(matrix.values):
        for x, value in enumerate(row):
            ax.text(
                x,
                y,
                str(int(value)),
                ha="center",
                va="center",
                fontsize=15,
                color="white" if value else "#253d31",
            )
    finish(
        fig,
        "One route may carry both community shapes",
        "Cells count decoded labels · full fixture remains fixed when the selected administrator changes",
        SOURCE,
        name="03-community-shapes",
    )


def diagnostics_finding(diagnostics):
    display(diagnostics)
    r = diagnostics.set_index("raw")
    assert r.loc["65536:1", "standard"] is not None
    prose(
        "`NO_EXPORT` is not a two-part numeric community and is not a large community; its "
        "NULL parse does not erase its well-known meaning. The malformed control also stays unparsed. "
        "The worker accepts `65536:1` as two unsigned 32-bit numbers: this parser alone does not enforce "
        "the 16-bit field widths of a standard wire community. These controls are authored strings, "
        "not additional MRT observations, and none proves that an export policy was applied."
    )


def community_checks(checks):
    display(checks)
    assert checks.passed.notna().all() and checks.passed.astype(bool).all()
    prose(
        f"**All {len(checks)} population and classification checks passed.** Routes with no selected "
        "labels remain in the denominator. The example describes annotation shape and membership, not policy enforcement."
    )
