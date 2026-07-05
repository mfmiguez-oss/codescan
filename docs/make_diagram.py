"""Render the codescan architecture diagram to PNG (for the Word doc / repo).

Standalone: `python docs/make_diagram.py` -> docs/architecture.png
Mirrors docs/architecture.svg. Uses only matplotlib.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

NEUTRAL = dict(fc="#eef2f7", ec="#64748b", tc="#0f172a", sc="#64748b")
IO = dict(fc="#f1f5f9", ec="#475569", tc="#0f172a", sc="#64748b")
AI = dict(fc="#e8f0ff", ec="#3b6fe0", tc="#1d4ed8", sc="#3b6fe0")
GRAY, BLUE = "#94a3b8", "#3b6fe0"


def box(ax, x, y, w, h, title, sub, style):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0,rounding_size=8",
        linewidth=1.3, edgecolor=style["ec"], facecolor=style["fc"], zorder=2))
    cx = x + w / 2
    ax.text(cx, y + h * 0.40, title, ha="center", va="center",
            fontsize=11.5, fontweight="bold", color=style["tc"], zorder=3)
    if sub:
        ax.text(cx, y + h * 0.72, sub, ha="center", va="center",
                fontsize=8.6, color=style["sc"], zorder=3)


def arrow(ax, p0, p1, color=GRAY, dashed=False, head=True):
    ax.add_patch(FancyArrowPatch(
        p0, p1, arrowstyle="-|>" if head else "-", mutation_scale=12,
        linewidth=1.8, color=color, zorder=1,
        linestyle=(0, (5, 4)) if dashed else "solid"))


def main() -> None:
    fig, ax = plt.subplots(figsize=(10, 6.6))
    ax.set_xlim(0, 1000)
    ax.set_ylim(0, 660)
    ax.invert_yaxis()          # SVG-style: y grows downward
    ax.axis("off")

    ax.text(40, 30, "codescan — architecture", fontsize=19, fontweight="bold", color="#0f172a")
    ax.text(40, 54, "Scanner aggregation  →  AI exploitability & vulnerability chaining  →  ServiceNow VR",
            fontsize=11, color="#64748b")

    def label(x, y, t):
        ax.text(x, y, t, fontsize=9.5, fontweight="bold", color="#94a3b8")

    # sources
    label(40, 92, "SOURCES")
    box(ax, 110, 100, 180, 52, "Bitbucket", "repo inventory", IO)
    box(ax, 410, 100, 180, 52, "Snyk", "SCA / SAST findings", IO)
    box(ax, 710, 100, 180, 52, "JFrog Xray", "artifacts / CVEs", IO)
    for sx in (200, 500, 800):
        arrow(ax, (sx, 152), (sx, 196))

    # pipeline panel
    ax.add_patch(FancyBboxPatch((40, 180), 920, 264, boxstyle="round,pad=0,rounding_size=12",
                                linewidth=1.2, edgecolor="#cbd5e1", facecolor="#f8fafc", zorder=0))
    label(56, 196, "PIPELINE")

    box(ax, 64, 196, 872, 42, "Ingest & Normalize  →  canonical Finding", "", NEUTRAL)

    # row A
    box(ax, 64, 262, 270, 58, "Deterministic dedup", "fingerprint merge", NEUTRAL)
    box(ax, 350, 262, 270, 58, "Semantic dedup", "AI · Haiku 4.5", AI)
    box(ax, 636, 262, 270, 58, "Enrich (pluggable)", "KEV · EPSS · reach · AI", NEUTRAL)
    # row B
    box(ax, 64, 352, 270, 58, "Exploitability + chaining", "AI · Opus 4.8 / Fable 5", AI)
    box(ax, 350, 352, 270, 58, "Composite score", "severity·exploit·exposure·chain", NEUTRAL)
    box(ax, 636, 352, 270, 58, "Validation states", "proposed · analyst-confirmed", NEUTRAL)

    arrow(ax, (199, 238), (199, 262))
    arrow(ax, (334, 291), (350, 291))
    arrow(ax, (620, 291), (636, 291))
    arrow(ax, (334, 381), (350, 381))
    arrow(ax, (620, 381), (636, 381))
    # enrich -> exploitability elbow
    ax.plot([771, 771, 199], [320, 338, 338], color=GRAY, linewidth=1.8, zorder=1)
    arrow(ax, (199, 338), (199, 352))

    # outputs
    label(40, 480, "OUTPUTS")
    box(ax, 70, 490, 190, 58, "ServiceNow VR", "JSON / CSV · idempotent", IO)
    box(ax, 285, 490, 140, 58, "Web UI / API", "analyst triage", IO)
    box(ax, 445, 490, 135, 58, "State store", "sticky decisions", NEUTRAL)
    box(ax, 690, 490, 220, 58, "Threat models", "STRIDE · per-service (AI)", AI)

    arrow(ax, (730, 410), (170, 488))    # -> ServiceNow
    arrow(ax, (752, 410), (350, 488))    # -> Web UI
    arrow(ax, (788, 410), (800, 488))    # -> Threat models (AI)
    # sticky feedback loop: Web UI -> state store -> validation
    arrow(ax, (425, 517), (445, 517), color=BLUE, dashed=True)
    ax.plot([512, 512, 700], [490, 442, 414], color=BLUE, linewidth=1.8,
            linestyle=(0, (5, 4)), zorder=1)
    arrow(ax, (690, 416), (702, 412), color=BLUE, dashed=True)
    ax.text(520, 470, "state changes", fontsize=9, color=BLUE)

    # legend
    ax.add_patch(FancyBboxPatch((40, 600), 16, 16, boxstyle="round,pad=0,rounding_size=3",
                                facecolor="#eef2f7", edgecolor="#64748b", linewidth=1))
    ax.text(64, 608, "Deterministic (no API key)", fontsize=10, va="center", color="#334155")
    ax.add_patch(FancyBboxPatch((420, 600), 16, 16, boxstyle="round,pad=0,rounding_size=3",
                                facecolor="#e8f0ff", edgecolor="#3b6fe0", linewidth=1))
    ax.text(444, 608, "AI stage (LLM) — optional, task-routed by tier", fontsize=10, va="center", color="#334155")

    out = Path(__file__).with_name("architecture.png")
    fig.savefig(out, dpi=200, bbox_inches="tight", facecolor="white")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
