from pathlib import Path

from models.utils import get_paths
from parsers.evtx_parser import parse_evtx
from parsers.sysmon_parser import parse_sysmon
from parsers.zeek_parser import parse_zeek_conn
from parsers.syslog_parser import parse_auth_log
from parsers.fortigate_parser import parse_fortigate
from parsers.ips_parser import parse_ips
from parsers.beats_parser import parse_beats


def run_ingest() -> Path:
    # Run all parsers
    parse_evtx()
    parse_sysmon()
    parse_zeek_conn()
    parse_auth_log()
    parse_fortigate()
    parse_ips()
    parse_beats()
    return Path(get_paths()["ecs_parquet_dir"])  


if __name__ == "__main__":
    run_ingest()
