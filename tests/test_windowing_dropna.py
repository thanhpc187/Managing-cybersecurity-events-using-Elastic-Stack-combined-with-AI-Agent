import pandas as pd


def test_add_time_window_counts_dropna_false_keeps_length_and_counts():
    from features.windowing import add_time_window_counts

    df = pd.DataFrame(
        [
            {"@timestamp": "2025-12-12T00:00:00Z", "source.ip": "10.0.0.1", "flag": 1},
            {"@timestamp": "2025-12-12T00:00:30Z", "source.ip": None, "flag": 1},
            {"@timestamp": "2025-12-12T00:01:00Z", "source.ip": "10.0.0.1", "flag": 0},
        ]
    )
    out = add_time_window_counts(df, ["source.ip"], "@timestamp", "flag", [1], col_suffix=None)
    assert len(out) == len(df)
    # window includes current row, so first row should be >= 1
    assert out["flag_count_1m"].iloc[0] >= 1.0


