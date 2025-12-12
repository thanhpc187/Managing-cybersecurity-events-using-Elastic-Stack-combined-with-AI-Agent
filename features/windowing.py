from typing import List, Optional
import pandas as pd


def add_time_window_counts(
    df: pd.DataFrame,
    group_cols: List[str],
    ts_col: str,
    value_col: str,
    windows_min: List[int],
    col_suffix: Optional[str] = None,
) -> pd.DataFrame:
    """
    Tính rolling sum cho cờ nhị phân value_col theo group_cols, cửa sổ phút.
    Tạo cột: <value_col>_count_<w>m. An toàn với dữ liệu rỗng/thiếu group.

    Lưu ý: đảm bảo cột thời gian ts_col vẫn còn trong kết quả rolling để merge
    lại về DataFrame gốc theo khóa group_cols + ts_col.
    """
    if df.empty:
        return df

    out = df.copy()
    out[ts_col] = pd.to_datetime(out[ts_col], utc=True, errors="coerce")
    out = out.dropna(subset=[ts_col]).sort_values(ts_col)
    out[value_col] = pd.to_numeric(out[value_col], errors="coerce").fillna(0).astype(int)

    idx = out.set_index(ts_col)
    for w in windows_min:
        # Giữ tương thích ngược: nếu không truyền suffix -> <value_col>_count_<w>m
        colname = f"{value_col}_count_{w}m" if not col_suffix else f"{value_col}_count_{col_suffix}_{w}m"
        try:
            rolled = (
                # dropna=False để không làm giảm kích thước khi group key bị thiếu (NaN)
                idx.groupby(group_cols, dropna=False)[value_col]
                .rolling(f"{w}min")
                .sum()
            )
            # rolled là Series cùng kích thước với idx; gán trực tiếp theo thứ tự
            out[colname] = rolled.values.astype("float64")
        except Exception:
            # Fallback an toàn nếu schema lạ để không làm hỏng pipeline
            out[colname] = 0.0
    return out