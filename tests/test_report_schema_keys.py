from pipeline.window_report import REQUIRED_REPORT_KEYS, assert_report_schema


def test_report_schema_keys_exist():
    # Minimal valid report object skeleton
    obj = {k: None for k in REQUIRED_REPORT_KEYS}
    # Some keys must be present even if None; assert_report_schema should pass
    assert_report_schema(obj)


