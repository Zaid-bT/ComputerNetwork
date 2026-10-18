"""Regenerate gbn_vs_sr.png from results.csv. Requires matplotlib."""
import csv
from pathlib import Path
import matplotlib.pyplot as plt

root = Path(__file__).resolve().parent
with (root / "results.csv").open(newline="") as f:
    rows = list(csv.DictReader(f))
experiments = ["A_Reliable", "B_Loss", "C_Mixed"]
labels = ["A: Reliable", "B: Packet loss", "C: Mixed errors"]
gbn = [int(next(r["retransmissions"] for r in rows if r["experiment"] == e and r["protocol"] == "GBN")) for e in experiments]
sr = [int(next(r["retransmissions"] for r in rows if r["experiment"] == e and r["protocol"] == "SR")) for e in experiments]
x = list(range(len(labels)))
width = 0.34
fig, ax = plt.subplots(figsize=(8.5, 5.2))
a = ax.bar([i-width/2 for i in x], gbn, width, label="GBN")
b = ax.bar([i+width/2 for i in x], sr, width, label="SR")
ax.set_ylabel("Data-packet retransmissions")
ax.set_title("GBN vs SR: Retransmissions Across Channel Conditions")
ax.set_xticks(x, labels)
ax.grid(axis="y", alpha=0.25)
ax.set_axisbelow(True)
ax.legend()
ax.bar_label(a, padding=3)
ax.bar_label(b, padding=3)
fig.tight_layout()
fig.savefig(root / "gbn_vs_sr.png", dpi=180)
