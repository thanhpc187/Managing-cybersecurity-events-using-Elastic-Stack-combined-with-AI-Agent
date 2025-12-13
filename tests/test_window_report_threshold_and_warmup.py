from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from pipeline.window_report import classify_scores, slice_time_range


def test_fixed_threshold_classification_normal():
    df = pd.DataFrame(
        {
            "@timestamp": [
                datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc),
                datetime(2025, 1, 1, 0, 1, tzinfo=timezone.utc),
            ],
            "anom.score": [0.10, 0.11],
        }
    )
    classification, alerts = classify_scores(df, baseline_threshold=0.50)
    assert classification == "NORMAL"
    assert len(alerts) == 0


def test_warmup_slicing_keeps_only_window_rows():
    window_start = datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc)
    window_end = datetime(2025, 1, 1, 10, 15, tzinfo=timezone.utc)
    warmup_start = window_start - timedelta(minutes=60)

    df = pd.DataFrame(
        {
            "@timestamp": [
                warmup_start + timedelta(minutes=1),
                window_start - timedelta(minutes=1),
                window_start,
                window_end,
                window_end + timedelta(minutes=1),
            ],
            "x": [1, 2, 3, 4, 5],
        }
    )
    out = slice_time_range(df, window_start, window_end, ts_col="@timestamp")
    assert out["@timestamp"].min() == pd.Timestamp(window_start)
    assert out["@timestamp"].max() == pd.Timestamp(window_end)
    assert out["x"].tolist() == [3, 4]


