from typing import List
import pandas as pd

def add_time_window_counts(
    df: pd.DataFrame,
    group_cols: List[str],
    ts_col: str,
    value_col: str,
    windows_min: List[int],
) -> pd.DataFrame:
    """
    Tính rolling sum cho cờ nhị phân value_col theo group_cols, cửa sổ phút.
    Tạo cột: <value_col>_count_<w>m. An toàn với dữ liệu rỗng/thiếu group.
    """
    if df.empty:
        return df

    out = df.copy()
    out[ts_col] = pd.to_datetime(out[ts_col], utc=True, errors="coerce")
    out = out.dropna(subset=[ts_col]).sort_values(ts_col)
    out[value_col] = pd.to_numeric(out[value_col], errors="coerce").fillna(0).astype(int)

    for w in windows_min:
        colname = f"{value_col}_count_{w}m"
        try:
            rolled = (
                out.groupby(group_cols)
                .rolling(f"{w}min", on=ts_col)[value_col]
                .sum()
                .reset_index()
            )
            # Align back to original rows via join on group_cols + ts_col
            out = out.merge(
                rolled.rename(columns={value_col: colname}),
                on=group_cols + [ts_col],
                how="left",
            )
            out[colname] = out[colname].fillna(0.0).astype("float64")
        except Exception:
            out[colname] = 0.0
    return out