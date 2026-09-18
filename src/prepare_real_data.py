"""
prepare_real_data.py
----------------------
Adapts the real Edge-IIoTset CSV (Ferrag et al., 2022) to the input
format the rest of the pipeline (train_trust_model.py, explain_shap.py,
policy_engine.py) expects. Run this ONCE after downloading the raw
CSV from Kaggle; everything downstream stays unchanged.

Usage:
    python src/prepare_real_data.py

Expects:  ./data/edge_iiotset_raw.csv
Produces: ./data/iiot_traffic.csv   (same filename the rest of the
          pipeline already reads -- so no other script needs editing)

Design notes
------------
Unlike the synthetic generator, real Edge-IIoTset ships raw per-packet
fields (tcp.srcport, mqtt.topic, arp.opcode, ...), not pre-aggregated
flow statistics. We therefore do NOT try to force-fit these into the
synthetic schema (pkt_rate, byte_rate, ...) -- that would be a lossy,
dishonest mapping. Instead we:
  1. Drop known identifier / high-cardinality / leakage-prone columns
     (documented in prior Edge-IIoTset preprocessing pipelines, e.g.
     raw payload bytes, source/destination IP, timestamps).
  2. Keep every remaining numeric and low-cardinality categorical
     column as-is -- these ARE the real features, whatever they are.
  3. Encode categoricals, impute missing values.
  4. Rename Attack_label -> label_binary, Attack_type -> label_attack_type,
     and synthesize device_id from ip.src_host BEFORE dropping it
     (so downstream device-level trust tracking still works).

train_trust_model.py has been made schema-agnostic (see the updated
`load_and_encode`): it now auto-detects numeric vs. categorical
columns from whatever CSV it is given, instead of relying on the
hardcoded synthetic feature list. So this adapter is the only new
piece of code required.
"""

import hashlib

import numpy as np
import pandas as pd

RAW_PATH = "./data/edge_iiotset_raw.csv"
OUT_PATH = "./data/iiot_traffic.csv"

# Columns known (from published Edge-IIoTset preprocessing recipes) to be
# identifiers, raw payload blobs, or near-constant/leakage-prone fields.
# Dropped before modeling -- same rationale as the dataset's own authors
# and follow-up papers use.
DROP_COLUMNS = [
    "frame.time", "arp.dst.proto_ipv4", "arp.src.proto_ipv4",
    "http.file_data", "http.request.full_uri", "icmp.transmit_timestamp",
    "http.request.uri.query", "tcp.options", "tcp.payload",
    "tcp.srcport", "tcp.dstport", "udp.port", "mqtt.msg",
    "dns.qry.name", "dns.qry.name.len", "mqtt.topic",
]

# Kept aside as device identifier, then dropped from the feature matrix
ID_COLUMNS = ["ip.src_host", "ip.dst_host"]

LABEL_BINARY_COL = "Attack_label"
LABEL_TYPE_COL = "Attack_type"


def pseudonymize(series: pd.Series) -> pd.Series:
    """Hash raw IPs into short device_id strings (dev_xxxxxxxx)."""
    return series.astype(str).apply(
        lambda v: "dev_" + hashlib.sha256(v.encode()).hexdigest()[:8])


def main():
    print(f"Loading raw file: {RAW_PATH}  (this can take a minute, it's a large CSV)")
    df = pd.read_csv(RAW_PATH, low_memory=False)
    print(f"Loaded {len(df):,} rows, {df.shape[1]} columns")

    if LABEL_BINARY_COL not in df.columns or LABEL_TYPE_COL not in df.columns:
        raise SystemExit(
            f"Expected label columns '{LABEL_BINARY_COL}' / '{LABEL_TYPE_COL}' "
            f"not found. Actual columns:\n{list(df.columns)}\n"
            "-> send me this column list and I'll adjust the adapter."
        )

    # device_id from source IP, computed before we drop the IP column
    if "ip.src_host" in df.columns:
        df["device_id"] = pseudonymize(df["ip.src_host"])
    else:
        df["device_id"] = ["dev_%08d" % i for i in range(len(df))]

    drop_existing = [c for c in DROP_COLUMNS + ID_COLUMNS if c in df.columns]
    df = df.drop(columns=drop_existing)
    print(f"Dropped {len(drop_existing)} identifier/leakage columns")

    df = df.rename(columns={LABEL_BINARY_COL: "label_binary",
                             LABEL_TYPE_COL: "label_attack_type"})

    # basic cleaning: replace inf, drop fully-empty columns, impute the rest.
    # Some columns come in as pandas "string" dtype even though they're
    # numeric (mixed formatting in the raw CSV) -- coerce first, then decide
    # numeric vs. categorical based on how well that coercion worked.
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(axis=1, how="all")
    for col in df.columns:
        if col in ("label_binary", "label_attack_type", "device_id"):
            continue
        coerced = pd.to_numeric(df[col], errors="coerce")
        is_mostly_numeric = coerced.notna().mean() >= 0.7
        if is_mostly_numeric:
            df[col] = coerced.fillna(coerced.median())
        else:
            df[col] = df[col].astype(str).fillna("missing")

    df = df.drop_duplicates()
    print(f"Final shape after cleaning: {df.shape}")
    print("Label distribution:")
    print(df["label_attack_type"].value_counts())

    df.to_csv(OUT_PATH, index=False)
    print(f"\nSaved -> {OUT_PATH}")
    print("Now re-run: python src/train_trust_model.py")


if __name__ == "__main__":
    main()
