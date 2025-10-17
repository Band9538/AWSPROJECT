"""
analyze_badges.py
AWS Badge Access Security Career Pathway Activity
-------------------------------------------------
Analyzes simulator output to detect:
  1. Impossible travelers (cloned badges)
  2. Curious users (unauthorized access attempts)
  3. Room type classification (based on dwell time)
"""

import json, sys
from datetime import timezone
from dateutil import parser
import pandas as pd

FOUR_HOURS_SECS = 4 * 60 * 60


def read_jsonl(path):
    """Read newline-delimited JSON into a DataFrame."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return pd.DataFrame(rows)


def iso_to_epoch(ts):
    dt = parser.isoparse(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def load_allowed_rooms(profile_path):
    """Load user permissions from userprofile.json."""
    with open(profile_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    allowed = {}
    if isinstance(data, list):
        for rec in data:
            uid = rec.get("user_id")
            allowed[uid] = set(rec.get("allowed_rooms", []))
    elif isinstance(data, dict):
        for uid, rec in data.items():
            allowed[uid] = set(rec.get("allowed_rooms", []))
    return allowed


def detect_impossible_travel(df):
    """Detect users appearing in two locations <4 hours apart."""
    d = df.copy()
    d["epoch"] = d["timestamp"].apply(iso_to_epoch)
    d = d.sort_values(["user_id", "epoch"])
    d["prev_loc"] = d.groupby("user_id")["location_id"].shift(1)
    d["prev_epoch"] = d.groupby("user_id")["epoch"].shift(1)

    mask = (
        d["prev_loc"].notna()
        & (d["location_id"] != d["prev_loc"])
        & ((d["epoch"] - d["prev_epoch"]) < FOUR_HOURS_SECS)
    )

    res = d.loc[mask, ["user_id", "prev_loc", "location_id", "prev_epoch", "epoch"]].copy()
    res["delta_secs"] = res["epoch"] - res["prev_epoch"]
    res = res.rename(
        columns={
            "prev_loc": "first_location",
            "location_id": "second_location",
            "prev_epoch": "first_ts",
            "epoch": "second_ts",
        }
    )
    return res


def detect_curious_users(df, allowed_map):
    """Detect users attempting unauthorized access."""
    def is_unauth(row):
        rooms = allowed_map.get(row["user_id"], set())
        return (row.get("success", True) is False) and (row["room_id"] not in rooms)

    d = df.copy()
    d["curious"] = d.apply(is_unauth, axis=1)
    cur = (
        d[d["curious"]]
        .groupby("user_id")
        .agg(attempts=("curious", "sum"))
        .reset_index()
        .sort_values("attempts", ascending=False)
    )

    return cur


def room_typing(df):
    """Estimate room dwell time and label probable room type."""
    d = df.copy()
    d["epoch"] = d["timestamp"].apply(iso_to_epoch)
    d = d.sort_values(["user_id", "epoch"])
    d["next_epoch"] = d.groupby("user_id")["epoch"].shift(-1)
    d["dwell_mins"] = (d["next_epoch"] - d["epoch"]) / 60.0
    d = d[d["next_epoch"].notna()]
    d["dwell_mins"] = d["dwell_mins"].clip(lower=0, upper=240)
    d["hour"] = pd.to_datetime(d["timestamp"], format='mixed', errors='coerce').dt.hour

    agg = (
        d.groupby("room_id")
        .agg(visits=("room_id", "count"), median_dwell_mins=("dwell_mins", "median"))
        .reset_index()
    )

    hour_counts = d.groupby(["room_id", "hour"]).size().reset_index(name="count")
    piv = hour_counts.pivot(index="room_id", columns="hour", values="count").fillna(0)
    piv = piv.reindex(columns=list(range(24)), fill_value=0)
    agg = agg.merge(piv, on="room_id", how="left")

    def label_row(r):
        med = r["median_dwell_mins"]
        morning = sum(r.get(h, 0) for h in [7, 8, 9])
        lunch = sum(r.get(h, 0) for h in [11, 12, 13])
        eve = sum(r.get(h, 0) for h in [16, 17, 18, 19])
        night = sum(r.get(h, 0) for h in [0, 1, 2, 3, 4, 5, 21, 22, 23])
        label = "Other/Office"
        if morning > lunch and med < 15:
            label = "Lobby/Entry"
        if 25 <= med <= 150 and lunch > morning and lunch > eve:
            label = "Conference/Meeting"
        if med < 10 and (morning + lunch + eve) > 50 and night == 0:
            label = "Hallway/Break"
        if 40 <= med <= 90 and lunch > (morning + eve) and lunch > 20:
            label = "Cafeteria"
        if night > (morning + lunch + eve) and med >= 60:
            label = "Security/Overnight/Server"
        return label

    for h in range(24):
        if h not in agg.columns:
            agg[h] = 0

    agg["label"] = agg.apply(label_row, axis=1)
    return agg[["room_id", "visits", "median_dwell_mins", "label"]].sort_values(
        "visits", ascending=False
    )


def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_badges.py events.jsonl userprofile.json")
        sys.exit(1)

    events_path = sys.argv[1]
    profile_path = sys.argv[2]

    df = read_jsonl(events_path)
    allowed = load_allowed_rooms(profile_path)

    imp = detect_impossible_travel(df)
    imp.to_json("cloned_findings.json", orient="records", indent=2)

    curious = detect_curious_users(df, allowed)
    curious.to_json("curious_users.json", orient="records", indent=2)

    rooms = room_typing(df)
    rooms.to_json("room_types.json", orient="records", indent=2)

    print("== Done ==")
    print(f"Impossible traveler flags: {len(imp)}")
    print(f"Curious users found: {len(curious)}")
    print(f"Labeled rooms: {len(rooms)}")


if __name__ == "__main__":
    main()
