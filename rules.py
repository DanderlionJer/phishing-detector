# -*- coding: utf-8 -*-
"""Deterministic rules + heuristics. Outputs evidence separate from LLM."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "adf.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "short.link",
        "cli.gs",
        "bc.co",
        "s.id",
    }
)

URGENCY_PATTERNS = [
    (
        r"\u7acb\u5373|\u9a6c\u4e0a|\u5c3d\u5feb|24\s*\u5c0f\u65f6\u5185|\u4eca\u65e5\u5185|\u9650\u65f6|\u903e\u671f|\u5c06\u88ab\u51bb\u7ed3|\u6c38\u4e45\u505c\u7528|\u5c01\u53f7",
        "urgency_threat_zh",
    ),
    (
        r"verify your account|act now|urgent|immediately|suspend|locked",
        "urgency_threat_en",
    ),
]
CREDENTIAL_PATTERNS = [
    (
        r"\u5bc6\u7801|\u53e3\u4ee4|\u9a8c\u8bc1\u7801|\u52a8\u6001\u7801|\u94f6\u884c\u5361|\u4fe1\u7528\u5361|\u8eab\u4efd\u8bc1\u53f7|\u793e\u4fdd\u5361|\u8f6c\u8d26|\u6c47\u6b3e|\u6536\u6b3e\u8d26\u6237",
        "credential_payment_zh",
    ),
    (
        r"password|otp|verification code|ssn|wire transfer|confirm your identity",
        "credential_payment_en",
    ),
]

ATTACH_PATTERN = re.compile(
    r"\.(exe|scr|bat|cmd|com|pif|vbs|js|jar|ps1|hta|msi|dll|zip|rar|7z|html?|docm|xlsm)\b",
    re.I,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\]\[\"'`,;)]+", re.I)
LOOSE_URL_PATTERN = re.compile(
    r"(?<![\w/])(www\.[a-z0-9.-]+\.[a-z]{2,}[^\s<>\]\[\"'`,;)]*)",
    re.I,
)

FROM_MISMATCH = re.compile(r"^(.+?)\s*<([^>]+)>$")


def _severity_rank(s: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(s, 0)


def _max_severity(a: str, b: str) -> str:
    order = ["low", "medium", "high"]
    return a if order.index(a) >= order.index(b) else b


def extract_urls(text: str) -> list[str]:
    found = list(URL_PATTERN.findall(text or ""))
    for m in LOOSE_URL_PATTERN.findall(text or ""):
        u = m if m.lower().startswith("http") else "http://" + m
        if u not in found:
            found.append(u)
    seen: set[str] = set()
    out: list[str] = []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _is_shortener_host(host: str) -> bool:
    h = host.lower()
    for s in SHORTENER_HOSTS:
        sl = s.lower()
        if h == sl or h.endswith("." + sl):
            return True
    return False


def _analyze_single_url(url: str) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return [
            {
                "type": "\u53ef\u7591\u94fe\u63a5",
                "detail": "\u65e0\u6cd5\u89e3\u6790\u7684 URL\uff1a" + url[:80],
                "severity": "medium",
            }
        ]

    host = (parsed.hostname or "").lower()
    if not host:
        return indicators

    if _is_shortener_host(host):
        indicators.append(
            {
                "type": "\u77ed\u94fe\u63a5",
                "detail": "\u4f7f\u7528\u77ed\u94fe/\u8df3\u8f6c\u57df\u540d\uff1a"
                + host
                + "\uff0c\u771f\u5b9e\u76ee\u6807\u88ab\u9690\u85cf\u3002",
                "severity": "medium",
            }
        )

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        indicators.append(
            {
                "type": "IP \u76f4\u8fde\u94fe\u63a5",
                "detail": "\u94fe\u63a5\u6307\u5411 IP \u800c\u975e\u5e38\u89c1\u57df\u540d\uff1a" + host,
                "severity": "high",
            }
        )

    if parsed.username or "@" in (parsed.path or ""):
        indicators.append(
            {
                "type": "URL \u4e2d\u7684 @ \u6280\u5de7",
                "detail": "\u5305\u542b userinfo \u6216\u8def\u5f84\u4e2d\u7684 @\uff0c\u5e38\u7528\u4e8e\u4f2a\u88c5\u663e\u793a\u57df\u540d\u3002",
                "severity": "high",
            }
        )

    if (parsed.port is not None and parsed.port not in (80, 443)) or (
        parsed.scheme == "http" and host and not host.startswith("127.")
    ):
        indicators.append(
            {
                "type": "\u975e\u6807\u51c6\u7aef\u53e3\u6216 HTTP",
                "detail": f"scheme={parsed.scheme}, port={parsed.port}\uff0c\u9700\u8b66\u60d5\u3002",
                "severity": "low",
            }
        )

    if host.startswith("xn--"):
        indicators.append(
            {
                "type": "Punycode \u57df\u540d",
                "detail": "\u4e3b\u673a\uff1a"
                + host
                + "\uff0c\u53ef\u80fd\u4e0e\u540c\u5f62\u5b57\u4eff\u5192\u6709\u5173\u3002",
                "severity": "medium",
            }
        )

    return indicators


def _keyword_indicators(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    t = text or ""
    for pat, _key in URGENCY_PATTERNS:
        if re.search(pat, t, re.I):
            out.append(
                {
                    "type": "\u7d27\u8feb/\u6050\u5413\u8bdd\u672f",
                    "detail": "\u6b63\u6587\u51fa\u73b0\u5236\u9020\u7d27\u8feb\u611f\u6216\u5a01\u80c1\u7684\u7528\u8bed\u3002",
                    "severity": "medium",
                }
            )
            break
    for pat, _key in CREDENTIAL_PATTERNS:
        if re.search(pat, t, re.I):
            out.append(
                {
                    "type": "\u7d22\u53d6\u654f\u611f\u4fe1\u606f",
                    "detail": "\u6b63\u6587\u51fa\u73b0\u7d22\u53d6\u5bc6\u7801\u3001\u9a8c\u8bc1\u7801\u3001\u8d26\u6237\u6216\u8f6c\u8d26\u76f8\u5173\u8868\u8ff0\u3002",
                    "severity": "high",
                }
            )
            break
    return out


def _attachment_indicators(text: str) -> list[dict[str, Any]]:
    if not text:
        return []
    m = ATTACH_PATTERN.search(text)
    if m:
        return [
            {
                "type": "\u53ef\u7591\u9644\u4ef6\u7c7b\u578b",
                "detail": "\u6b63\u6587\u63d0\u53ca\u53ef\u7591\u6269\u5c55\u540d\uff1a" + m.group(0),
                "severity": "medium",
            }
        ]
    return []


def _from_header_indicators(from_line: str | None) -> list[dict[str, Any]]:
    if not from_line or not from_line.strip():
        return []
    line = from_line.strip()
    m = FROM_MISMATCH.match(line)
    if not m:
        return []
    display, addr = m.group(1).strip(), m.group(2).strip()
    email_in_name = re.search(r"[\w.+-]+@[\w.-]+\.\w+", display)
    if email_in_name:
        inner = email_in_name.group(0).lower()
        if inner != addr.lower():
            return [
                {
                    "type": "\u53d1\u4ef6\u4eba\u5c55\u793a\u4e0e\u5730\u5740\u4e0d\u4e00\u81f4",
                    "detail": f"\u5c55\u793a\u540d\u4e2d\u542b {inner}\uff0c\u4f46 From \u4e3a {addr}",
                    "severity": "high",
                }
            ]
    return []


def collect_missing_info(
    full_text: str,
    *,
    has_ocr: bool,
    from_addr: str | None,
    subject: str | None,
) -> list[str]:
    hints: list[str] = []
    t = (full_text or "").strip()
    if len(t) < 40:
        hints.append(
            "\u6b63\u6587\u8fc7\u77ed\uff0c\u5efa\u8bae\u7c98\u8d34\u5b8c\u6574\u90ae\u4ef6\u6216\u66f4\u957f\u7684\u622a\u56fe\u8bc6\u522b\u7ed3\u679c\u3002"
        )
    if not from_addr and "\u53d1\u4ef6\u4eba" not in t and "from:" not in t.lower():
        hints.append(
            "\u672a\u63d0\u4f9b\u53d1\u4ef6\u4eba\u5730\u5740\uff0c\u4eff\u5192\u57df\u540d\u96be\u4ee5\u6838\u5bf9\uff1b\u5efa\u8bae\u8865\u5145\u539f\u59cb\u4fe1\u5934\u6216\u53d1\u4ef6\u4eba\u3002"
        )
    if not subject and "\u4e3b\u9898" not in t:
        hints.append(
            "\u672a\u63d0\u4f9b\u90ae\u4ef6\u4e3b\u9898\uff0c\u90e8\u5206\u9493\u9c7c\u4f1a\u5728\u4e3b\u9898\u4e2d\u5236\u9020\u7d27\u8feb\u611f\u3002"
        )
    if not extract_urls(t) and "http" not in t.lower() and "www." not in t.lower():
        hints.append(
            "\u672a\u68c0\u6d4b\u5230\u94fe\u63a5\u3002\u82e5\u6709\u6309\u94ae/\u4e8c\u7ef4\u7801\uff0c\u8bf7\u8865\u5145\u6587\u5b57\u8bf4\u660e\u6216\u66f4\u6e05\u6670\u622a\u56fe\u3002"
        )
    if has_ocr and len(t) < 80:
        hints.append(
            "\u622a\u56fe\u8bc6\u522b\u6587\u5b57\u8f83\u5c11\uff0c\u53ef\u80fd\u4e0d\u5168\uff1b\u53ef\u624b\u52a8\u8865\u5145\u5173\u952e\u53e5\u6216\u53d1\u4ef6\u4eba\u3002"
        )
    return hints


def run_rule_engine(
    text: str,
    *,
    from_addr: str | None = None,
    subject: str | None = None,
    has_ocr: bool = False,
) -> dict[str, Any]:
    parts: list[str] = []
    if from_addr:
        parts.append("\u53d1\u4ef6\u4eba: " + from_addr.strip())
    if subject:
        parts.append("\u4e3b\u9898: " + subject.strip())
    parts.append(text or "")
    combined = "\n".join(parts)

    indicators: list[dict[str, Any]] = []
    url_list = extract_urls(combined)
    url_meta: list[dict[str, Any]] = []

    for u in url_list[:30]:
        flags = _analyze_single_url(u)
        for f in flags:
            indicators.append(f)
        url_meta.append({"url": u[:500], "hits": [f["type"] for f in flags]})

    indicators.extend(_keyword_indicators(combined))
    indicators.extend(_attachment_indicators(combined))
    indicators.extend(_from_header_indicators(from_addr))

    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for ind in indicators:
        key = (ind.get("type", ""), (ind.get("detail", "") or "")[:120])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ind)

    max_sev = "low"
    for ind in deduped:
        max_sev = _max_severity(max_sev, ind.get("severity", "low"))

    rule_risk_hint = "none"
    if _severity_rank(max_sev) >= 3:
        rule_risk_hint = "high"
    elif _severity_rank(max_sev) == 2:
        rule_risk_hint = "medium"
    elif deduped:
        rule_risk_hint = "low"

    missing = collect_missing_info(
        combined,
        has_ocr=has_ocr,
        from_addr=from_addr,
        subject=subject,
    )

    return {
        "indicators": deduped,
        "missing_info": missing,
        "urls": url_meta,
        "rule_risk_hint": rule_risk_hint,
        "url_count": len(url_list),
    }


def reconcile_display_risk(llm_level: str, rule_hint: str) -> tuple[str, str | None]:
    order = {"\u5b89\u5168": 0, "\u53ef\u7591": 1, "\u9ad8\u5371": 2}
    rl = order.get(llm_level, 1)
    rh = {"none": 0, "low": 0, "medium": 1, "high": 2}.get(rule_hint, 0)

    if rh >= 2 and rl <= 0:
        return (
            "\u53ef\u7591",
            "\u89c4\u5219\u5f15\u64ce\u53d1\u73b0\u8f83\u5f3a\u5ba2\u89c2\u98ce\u9669\u4fe1\u53f7\uff0c\u4e0e\u300c\u5b89\u5168\u300d\u7ed3\u8bba\u4e0d\u4e00\u81f4\uff0c\u5efa\u8bae\u4eba\u5de5\u590d\u6838\u3002",
        )
    if rh >= 2 and rl == 1:
        return (
            "\u9ad8\u5371",
            "\u89c4\u5219\u4e0e\u4e0a\u4e0b\u6587\u5747\u6307\u5411\u8f83\u9ad8\u98ce\u9669\uff0c\u5df2\u5c06\u7efc\u5408\u8bc4\u7ea7\u4e0a\u8c03\u4e3a\u9ad8\u5371\u4ee5\u4fbf\u8c28\u614e\u5904\u7f6e\u3002",
        )
    if rh == 1 and rl == 0:
        return (
            "\u53ef\u7591",
            "\u5b58\u5728\u4e2d\u7b49\u89c4\u5219\u4fe1\u53f7\uff0c\u5efa\u8bae\u5728\u300c\u5b89\u5168\u300d\u7ed3\u8bba\u4e0b\u4ecd\u4fdd\u6301\u8b66\u60d5\u6216\u8865\u5145\u4fe1\u5934\u540e\u518d\u6d4b\u3002",
        )
    return llm_level, None
