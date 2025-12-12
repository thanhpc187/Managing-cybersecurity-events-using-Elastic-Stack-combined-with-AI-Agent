import pandas as pd


def test_flatten_ecs_columns_extracts_nested_fields():
    from features.build_features import flatten_ecs_columns

    df = pd.DataFrame(
        [
            {
                "@timestamp": "2025-12-12T00:00:00Z",
                "event": {"action": "accept", "outcome": "failure", "dataset": "ubuntu.auth", "module": "system"},
                "source": {"ip": "10.10.10.50", "port": "52000"},
                "destination": {"ip": "10.10.10.11", "port": 22},
                "network": {"transport": "tcp", "bytes": 1234},
                "message": "Failed password for invalid user test from 10.10.10.50 port 52000 ssh2",
            }
        ]
    )
    out = flatten_ecs_columns(df.copy())
    assert out.loc[0, "event.action"] == "accept"
    assert out.loc[0, "event.outcome"] == "failure"
    assert out.loc[0, "source.ip"] == "10.10.10.50"
    assert float(out.loc[0, "source.port"]) == 52000.0
    assert float(out.loc[0, "destination.port"]) == 22.0


def test_login_failed_from_ssh_message_without_event_outcome():
    from features.build_features import add_basic_security_flags

    df = pd.DataFrame(
        [
            {
                "@timestamp": "2025-12-12T00:00:00Z",
                "event.code": None,
                "event.outcome": None,
                "message": "Failed password for invalid user admin from 10.10.10.50 port 52000 ssh2",
            }
        ]
    )
    out = add_basic_security_flags(df.copy())
    assert int(out.loc[0, "login_failed"]) == 1


def test_login_failed_from_windows_4625():
    from features.build_features import add_basic_security_flags

    df = pd.DataFrame(
        [
            {
                "@timestamp": "2025-12-12T00:00:00Z",
                "event.code": "4625",
                "event.outcome": "Failure",
                "message": "An account failed to log on",
            }
        ]
    )
    out = add_basic_security_flags(df.copy())
    assert int(out.loc[0, "login_failed"]) == 1


