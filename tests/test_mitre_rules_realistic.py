from ai.mitre_mapper import load_mitre_mapping, map_to_mitre


def test_mitre_t1021_accept_on_remote_ports():
    cfg = load_mitre_mapping()
    rec = {"destination.port": 22, "event.action": "accept"}
    hits = map_to_mitre(rec, rec, cfg)
    techs = {h.get("technique") for h in hits}
    assert "T1021" in techs


def test_mitre_t1046_port_scan_like_features():
    cfg = load_mitre_mapping()
    rec = {"uniq_dport_per_src_1m": 5, "conn_suspicious": 1}
    hits = map_to_mitre(rec, rec, cfg)
    techs = {h.get("technique") for h in hits}
    assert "T1046" in techs


