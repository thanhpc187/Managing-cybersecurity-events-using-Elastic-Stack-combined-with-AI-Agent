"""
AI agent phân tích alert bằng LLM (tiếng Việt).
Ưu tiên: DeepSeek -> Gemini -> Offline stub.

Copyright (c) 2024 thanhpc187
See LICENSE file for license information.
Original repository: https://github.com/thanhpc187/Managing-cybersecurity-events-using-Elastic-Stack-combined-with-AI-Agent
"""

from __future__ import annotations
import os
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import pandas as pd

from .mitre_mapper import load_mitre_mapping, map_to_mitre
from .nist_mapper import load_nist_mapping, map_to_nist

logger = logging.getLogger(__name__)

# --------- Chuẩn hóa đầu vào ---------
def _as_records(obj: Any) -> List[Dict[str, Any]]:
    """Chuyển đổi object thành danh sách records (dict)."""
    try:
        import pandas as pd  # type: ignore
        if isinstance(obj, pd.DataFrame):
            return obj.to_dict("records")
    except (ImportError, AttributeError) as e:
        logger.debug(f"Không thể convert DataFrame: {e}")
        pass
    if isinstance(obj, (list, tuple)):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for k in ("records", "rows", "data", "items"):
            v = obj.get(k)
            if isinstance(v, (list, tuple)):
                return [x for x in v if isinstance(x, dict)]
        vals = list(obj.values())
        if vals and isinstance(vals[0], dict):
            return [x for x in vals if isinstance(x, dict)]
    return []

def _as_list(obj: Any) -> List[Any]:
    if obj is None:
        return []
    if isinstance(obj, (list, tuple)):
        return list(obj)
    if isinstance(obj, dict):
        for k in ("items", "rows", "data", "values"):
            v = obj.get(k)
            if isinstance(v, (list, tuple)):
                return list(v)
        return list(obj.values())
    return [obj]

# --------- Tạo prompt ---------
def _truncate(s: Optional[str], n: int) -> str:
    """Cắt chuỗi về độ dài tối đa n ký tự."""
    if s is None:
        return ""
    s = str(s)
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."

def _render_prompt(
    alert: Dict[str, Any],
    shap_items: List[Dict[str, Any]],
    context_rows: List[Dict[str, Any]],
    max_ctx_lines: int = 20,
    max_ctx_chars: int = 200,
) -> str:
    """Tạo prompt cho LLM từ alert, SHAP values và context rows."""
    if not isinstance(alert, dict):
        logger.warning("Alert không phải dict, sử dụng dict rỗng")
        alert = {}
    
    shap_list = _as_list(shap_items)
    ctx_list = _as_records(context_rows)

    parts: List[str] = []
    parts.append("Bạn là chuyên gia SOC. Hãy phân tích NGẮN GỌN, RÕ RÀNG, BẰNG TIẾNG VIỆT.")
    
    timestamp = alert.get('@timestamp', 'N/A')
    score = alert.get('anom.score', 'N/A')
    parts.append(f"Thời điểm cảnh báo: {timestamp}, điểm bất thường: {score}")
    
    host = alert.get('host.name', 'N/A')
    user = alert.get('user.name', 'N/A')
    src_ip = alert.get('source.ip', 'N/A')
    dst_ip = alert.get('destination.ip', 'N/A')
    parts.append(f"Thực thể: host={host}, user={user}, src={src_ip}, dst={dst_ip}")

    if shap_list:
        items = []
        for x in shap_list[:5]:
            if not isinstance(x, dict):
                continue
            feature = x.get('feature', 'unknown')
            try:
                value = float(x.get('value', 0.0))
                items.append(f"{feature}({value:+.3f})")
            except (ValueError, TypeError):
                logger.debug(f"Không thể parse SHAP value: {x}")
                continue
        if items:
            parts.append(f"Đặc trưng nổi bật: {', '.join(items)}")

    if ctx_list:
        msgs = []
        for r in ctx_list[:max_ctx_lines]:
            if not isinstance(r, dict):
                continue
            msg = str(r.get("message") or "")
            ts = str(r.get("@timestamp") or "")
            mod = str(r.get("event.module") or "")
            ds = str(r.get("event.dataset") or "")
            msgs.append(f"[{ts}][{mod}.{ds}] {_truncate(msg, max_ctx_chars)}")
        if msgs:
            parts.append("Ngữ cảnh (rút gọn):\n- " + "\n- ".join(msgs))

    parts.append(
        "Đầu ra yêu cầu: 1) Mức rủi ro (LOW/MEDIUM/HIGH); "
        "2) Lý do ngắn gọn; 3) Ba hành động khuyến nghị cụ thể (có thể kèm script PowerShell). "
        "Chỉ trả lời bằng tiếng Việt."
    )
    return "\n".join(parts)

# --------- Suy diễn mức rủi ro ---------
_RISK_PATTERNS = [
    (r"\b(thấp|low)\b", "LOW"),
    (r"\b(trung\s*bình|vừa|medium|med|moderate)\b", "MEDIUM"),
    (r"\b(cao|nghiêm\s*trọng|critical|high)\b", "HIGH"),
]

def _infer_risk_from_text(text: str, default: str = "LOW") -> str:
    """Suy diễn mức rủi ro từ text response của LLM."""
    if not text or not isinstance(text, str):
        return default
    t = text.lower()
    # Ưu tiên HIGH trước, sau đó MEDIUM, cuối cùng LOW
    for pat, level in sorted(_RISK_PATTERNS, key=lambda x: x[1] == "HIGH", reverse=True):
        if re.search(pat, t, flags=re.IGNORECASE):
            return level
    return default

# --------- Gợi ý hành động có script (Windows) ---------
def _dedup_keep_order(items: List[str]) -> List[str]:
    """Loại bỏ phần tử trùng lặp nhưng giữ nguyên thứ tự."""
    seen: set[str] = set()
    out: List[str] = []
    for it in items:
        if it and it not in seen:
            out.append(it)
            seen.add(it)
    return out

def _suggest_actions(alert: Dict[str, Any]) -> List[str]:
    """
    Sinh danh sách bước khuyến nghị ngắn gọn, có kèm script PowerShell khi phù hợp.
    Lưu ý: nhiều lệnh cần quyền Admin; kiểm tra trước khi áp dụng trong môi trường thật.
    """
    if not isinstance(alert, dict):
        logger.warning("Alert không phải dict trong _suggest_actions")
        return []
    
    actions: List[str] = []

    ip = str(alert.get("source.ip") or "").strip()
    user = str(alert.get("user.name") or "").strip()
    host = str(alert.get("host.name") or "").strip()
    proc = str(alert.get("process.name") or alert.get("process.executable") or "").strip()

    # 1) Chặn IP nguồn (nếu có và hợp lệ)
    if ip and ip not in ("N/A", "None", ""):
        # Validate IP format cơ bản
        if "." in ip or ":" in ip:
            actions.append(
                f"Chặn IP nguồn tạm thời (PowerShell/Administrator): "
                f"New-NetFirewallRule -DisplayName \"Block inbound {ip}\" -Direction Inbound "
                f"-RemoteAddress {ip} -Action Block; "
                f"New-NetFirewallRule -DisplayName \"Block outbound {ip}\" -Direction Outbound "
                f"-RemoteAddress {ip} -Action Block"
            )

    # 2) Bảo vệ tài khoản người dùng (nếu có và hợp lệ)
    if user and user not in ("N/A", "None", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        actions.append(
            f"Tạm khóa tài khoản cục bộ: net user {user} /active:no  "
            f"(Domain: Disable-ADAccount -Identity {user})"
        )
        actions.append(
            f"Buộc đổi mật khẩu: Set-ADAccountPassword -Identity {user} -Reset "
            f"-NewPassword (Read-Host -AsSecureString)  (nếu là tài khoản AD)"
        )

    # 3) Cách ly endpoint (nếu biết host) – giữ RDP để điều tra
    if host and host not in ("N/A", "None", ""):
        actions.append(
            "Cách ly endpoint bằng Firewall (chạy tại máy hoặc qua RMM): "
            "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block "
            "-DefaultOutboundAction Block; "
            "New-NetFirewallRule -DisplayName \"Allow RDP\" -Direction Inbound -Protocol TCP "
            "-LocalPort 3389 -Action Allow"
        )

    # 4) Quét AV và thu thập log chứng cứ
    actions.append("Kích hoạt quét Defender: Start-MpScan -ScanType QuickScan  (FullScan nếu cần)")
    actions.append("Thu thập log sự kiện: wevtutil epl Security C:\\Temp\\Security.evtx /ow:true; wevtutil epl System C:\\Temp\\System.evtx /ow:true")

    # 5) Xử lý tiến trình nghi ngờ (nếu có tên/đường dẫn)
    if proc and proc not in ("N/A", "None", ""):
        actions.append(
            f"Dừng tiến trình nghi ngờ: Stop-Process -Name \"{proc}\" -Force  "
            f"(xem xét trước với tiến trình hệ thống)"
        )
        actions.append(
            "Lấy hash file để tra cứu IOC: Get-FileHash -Algorithm SHA256 \"<path_to_exe>\""
        )

    # 6) Khôi phục/khoanh vùng quyền truy cập
    if user and user not in ("N/A", "None", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        actions.append(
            "Rút quyền admin tạm thời khỏi user nghi vấn (Local Administrators/Groups)."
        )

    # 7) Theo dõi và đóng sự cố
    actions.append("Theo dõi log ±5 phút quanh thời điểm và các đăng nhập/tiến trình bất thường liên quan; đóng rule chặn khi đã xác minh an toàn.")

    return _dedup_keep_order([a for a in actions if a])


# --------- MITRE & correlation helpers ---------
MITRE_RULES = [
    ("brute force", "T1110 Brute Force"),
    ("port scan", "T1046 Network Service Discovery"),
    ("lateral", "T1021 Remote Services"),
    ("powershell", "T1059.001 PowerShell"),
    ("rundll32", "T1218 Signed Binary Proxy Execution"),
    ("beacon", "TA0011 Command and Control"),
]


def _extract_entities(alert: Dict[str, Any], context_rows: List[Dict[str, Any]]) -> Dict[str, set]:
    entities = {
        "src": set(),
        "dst": set(),
        "user": set(),
        "host": set(),
        "actions": [],
        "modules": [],
    }
    for rec in [alert] + _as_records(context_rows):
        if not isinstance(rec, dict):
            continue
        if rec.get("source.ip"):
            entities["src"].add(str(rec.get("source.ip")))
        if rec.get("destination.ip"):
            entities["dst"].add(str(rec.get("destination.ip")))
        if rec.get("user.name"):
            entities["user"].add(str(rec.get("user.name")))
        if rec.get("host.name"):
            entities["host"].add(str(rec.get("host.name")))
        if rec.get("event.action"):
            entities["actions"].append(str(rec.get("event.action")))
        if rec.get("event.module"):
            entities["modules"].append(str(rec.get("event.module")))
    return entities


def _correlate_multisource(alert: Dict[str, Any], context_rows: List[Dict[str, Any]], window_min: int = 10) -> List[str]:
    out: List[str] = []
    try:
        t0 = pd.to_datetime(alert.get("@timestamp"), utc=True, errors="coerce")  # type: ignore
    except Exception:
        t0 = None
    for rec in _as_records(context_rows):
        if not isinstance(rec, dict):
            continue
        ts = rec.get("@timestamp")
        if t0 is not None and ts is not None:
            try:
                ts_dt = pd.to_datetime(ts, utc=True, errors="coerce")  # type: ignore
                if pd.isna(ts_dt):
                    continue
                if abs((ts_dt - t0).total_seconds()) > window_min * 60:
                    continue
            except Exception:
                pass
        same_src = alert.get("source.ip") and rec.get("source.ip") == alert.get("source.ip")
        same_dst = alert.get("destination.ip") and rec.get("destination.ip") == alert.get("destination.ip")
        same_user = alert.get("user.name") and rec.get("user.name") == alert.get("user.name")
        if same_src or same_dst or same_user:
            mod = rec.get("event.module") or "unknown"
            act = rec.get("event.action") or "n/a"
            out.append(f"{mod}::{act} liên quan cùng IP/user trong {window_min} phút.")
    return _dedup_keep_order(out)


def _map_mitre(alert: Dict[str, Any], shap_items: List[Dict[str, Any]]) -> List[str]:
    text_blob = " ".join(
        [
            str(alert.get("message") or ""),
            str(alert.get("event.action") or ""),
            str(alert.get("event.dataset") or ""),
            str(alert.get("rule.name") or ""),
            " ".join([str(x.get("feature")) for x in shap_items if isinstance(x, dict)]),
        ]
    ).lower()
    hits = []
    for pat, tid in MITRE_RULES:
        if pat in text_blob:
            hits.append(tid)
    # Heuristics: port 3389/445 -> lateral movement
    dport = str(alert.get("destination.port") or "")
    if dport in ("3389", "445") and "T1021 Remote Services" not in hits:
        hits.append("T1021 Remote Services")
    return _dedup_keep_order(hits)

# --------- Gọi LLM ---------
def _call_deepseek(prompt: str, timeout: int = 30) -> Optional[str]:
    """Gọi DeepSeek API để phân tích alert."""
    ds_key = os.getenv("DEEPSEEK_API_KEY")
    if not ds_key:
        logger.debug("DEEPSEEK_API_KEY không được cấu hình")
        return None
    
    if not prompt or not isinstance(prompt, str):
        logger.warning("Prompt không hợp lệ cho DeepSeek")
        return None
    
    try:
        from openai import OpenAI  # pip install openai
        base = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com")
        model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        client = OpenAI(api_key=ds_key, base_url=base, timeout=timeout)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "Bạn là chuyên gia SOC. Luôn trả lời bằng tiếng Việt, ngắn gọn và hành động được."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=700,
        )
        result = (resp.choices[0].message.content or "").strip()
        if result:
            logger.debug(f"DeepSeek response nhận được ({len(result)} chars)")
        return result
    except (ImportError, AttributeError) as e:
        logger.warning(f"Không thể import OpenAI hoặc lỗi cấu hình: {e}")
        return None
    except (OSError, TimeoutError, ConnectionError) as e:
        logger.warning(f"Lỗi kết nối DeepSeek: {e}")
        return None
    except Exception as e:
        logger.exception(f"DeepSeek call failed: {e}")
        return None

def _call_gemini(prompt: str) -> Optional[str]:
    """Gọi Gemini API để phân tích alert (fallback nếu DeepSeek không khả dụng)."""
    gkey = os.getenv("GEMINI_API_KEY")
    if not gkey:
        logger.debug("GEMINI_API_KEY không được cấu hình")
        return None
    
    if not prompt or not isinstance(prompt, str):
        logger.warning("Prompt không hợp lệ cho Gemini")
        return None
    
    try:
        import google.generativeai as genai  # pip install google-generativeai
        genai.configure(api_key=gkey)
        model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
        full_prompt = "Trả lời bằng tiếng Việt, ngắn gọn, hành động được.\n\n" + prompt
        res = model.generate_content(full_prompt)
        result = (getattr(res, "text", None) or "").strip()
        if result:
            logger.debug(f"Gemini response nhận được ({len(result)} chars)")
        return result
    except ImportError as e:
        logger.warning(f"Không thể import google.generativeai: {e}")
        return None
    except (OSError, ConnectionError) as e:
        logger.warning(f"Lỗi kết nối Gemini: {e}")
        return None
    except Exception as e:
        logger.exception(f"Gemini call failed: {e}")
        return None

# --------- API chính ---------
def analyze_alert_with_llm(
    alert: Dict[str, Any],
    shap_items: List[Dict[str, Any]],
    context_rows: List[Dict[str, Any]],
    features_row: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Phân tích alert bằng LLM với fallback: DeepSeek -> Gemini -> Stub.
    
    Args:
        alert: Dict chứa thông tin alert (phải có @timestamp, anom.score)
        shap_items: Danh sách SHAP values để giải thích
        context_rows: Danh sách context rows liên quan
        
    Returns:
        Dict chứa risk_level, score, reason, iocs, actions, raw_text, provider, alert_time
    """
    if not isinstance(alert, dict):
        logger.error("Alert phải là dict")
        alert = {}
    
    try:
        prompt = _render_prompt(alert, shap_items, context_rows)
    except Exception as e:
        logger.error(f"Lỗi khi tạo prompt: {e}")
        prompt = "Phân tích alert bất thường."

    # Thử DeepSeek trước
    text = _call_deepseek(prompt)
    provider = "deepseek"

    # Fallback sang Gemini nếu DeepSeek không khả dụng
    if text is None:
        text = _call_gemini(prompt)
        provider = "gemini" if text is not None else "stub"

    entities = _extract_entities(alert, context_rows)
    correlations = _correlate_multisource(alert, context_rows)
    mitre_hits = _map_mitre(alert, shap_items)
    mapping_config = load_mitre_mapping()
    mitre_auto = map_to_mitre(alert, features_row, mapping_config)
    nist_config = load_nist_mapping()
    nist_auto = map_to_nist(alert, mitre_auto, nist_config)
    actions = _suggest_actions(alert)

    # Helper để lấy giá trị an toàn
    def safe_get(key: str, default: Any = None) -> Any:
        return alert.get(key, default) if isinstance(alert, dict) else default
    
    def safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    # Tạo IOC list
    iocs = [
        {"type": "host.name", "value": safe_get("host.name")},
        {"type": "user.name", "value": safe_get("user.name")},
        {"type": "source.ip", "value": safe_get("source.ip")},
        {"type": "destination.ip", "value": safe_get("destination.ip")},
    ]

    if not text:
        return {
            "risk_level": "LOW",
            "score": safe_float(safe_get("anom.score")),
            "reason": "Chế độ offline: chưa cấu hình LLM, không thể sinh phân tích tự động.",
            "iocs": iocs,
            "actions": actions,
            "raw_text": "",
            "provider": provider,
            "alert_time": str(safe_get("@timestamp", "N/A")),
        }

    risk = _infer_risk_from_text(text, default="LOW")
    # Escalate risk nếu có IPS/C2 hoặc nhiều deny
    priority = safe_get("event.severity")
    try:
        priority_int = int(priority)
    except Exception:
        priority_int = None
    action = str(safe_get("event.action", "")).lower()
    deny_like = action in ("deny", "drop", "blocked", "reset")
    if priority_int is not None and priority_int <= 2:
        risk = "HIGH"
    elif mitre_hits:
        risk = "MEDIUM" if risk == "LOW" else risk
    elif deny_like:
        risk = "MEDIUM" if risk == "LOW" else risk

    markdown_lines = [
        f"# Alert tại {safe_get('@timestamp', 'N/A')}",
        f"- Điểm bất thường: **{safe_float(safe_get('anom.score')):.3f}**",
        f"- Risk: **{risk}** (provider: {provider})",
    ]
    all_mitre = mitre_hits.copy()
    if mitre_auto:
        auto_labels = [m.get("technique") for m in mitre_auto if m.get("technique")]
        all_mitre.extend([a for a in auto_labels if a])
    if all_mitre:
        markdown_lines.append("- MITRE: " + ", ".join(_dedup_keep_order(all_mitre)))
    if nist_auto:
        nist_tags = [f"{n.get('function')} ({n.get('category')})" for n in nist_auto if n.get("function")]
        if nist_tags:
            markdown_lines.append("- NIST CSF: " + ", ".join(_dedup_keep_order(nist_tags)))
    if correlations:
        markdown_lines.append("- Tương quan:")
        for c in correlations[:5]:
            markdown_lines.append(f"  - {c}")
    if entities["src"] or entities["dst"]:
        markdown_lines.append(f"- Src IP: {', '.join(entities['src']) or 'N/A'}; Dst IP: {', '.join(entities['dst']) or 'N/A'}")
    if actions:
        markdown_lines.append("- Hành động đề xuất:")
        for a in actions[:3]:
            markdown_lines.append(f"  - {a}")

    mitre_payload = []
    for m in (mitre_auto or []):
        mitre_payload.append(
            {
                "rule_id": m.get("rule_id"),
                "tactic": m.get("tactic"),
                "technique": m.get("technique"),
                "subtechnique": m.get("subtechnique"),
                "description": m.get("description"),
            }
        )

    result = {
        "risk_level": risk,
        "score": safe_float(safe_get("anom.score")),
        "reason": _truncate(text, 1200),
        "iocs": iocs,
        "actions": actions,
        "raw_text": text,
        "provider": provider,
        "alert_time": str(safe_get("@timestamp", "N/A")),
        "mitre": mitre_hits,
        "mitre_attack": mitre_payload,
        "nist_csf": nist_auto,
        "correlations": correlations,
        "markdown": "\n".join(markdown_lines),
    }
    # ECS threat fields (first match if available)
    if mitre_payload:
        first = mitre_payload[0]
        if first.get("tactic"):
            result["threat.tactic.name"] = first["tactic"]
        if first.get("technique"):
            result["threat.technique.name"] = first["technique"]
            result["threat.technique.id"] = first["technique"]
        if first.get("subtechnique"):
            result["threat.technique.subtechnique"] = first["subtechnique"]
    return result

# Alias tương thích
def analyze_alert(
    alert: Dict[str, Any],
    shap_items: List[Dict[str, Any]],
    context_rows: List[Dict[str, Any]],
    features_row: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return analyze_alert_with_llm(alert, shap_items, context_rows, features_row)