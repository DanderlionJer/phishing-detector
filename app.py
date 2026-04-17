import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Body, FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from rapidocr_onnxruntime import RapidOCR

import rules

load_dotenv()

_BASE = Path(__file__).resolve().parent
with (_BASE / "locale_zh.json").open(encoding="utf-8") as _f:
    ZH = json.load(_f)

app = FastAPI(title=ZH["app_title"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ocr_engine = RapidOCR()

client = OpenAI(
    api_key=os.getenv("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
)

MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

DATA_DIR = _BASE / "data"
FEEDBACK_LOG = DATA_DIR / "feedback.jsonl"

SYSTEM_PROMPT = ZH["system_prompt"]
USER_PROMPT_TEMPLATE = ZH["user_prompt_template"]


def extract_text_from_image(image_bytes: bytes) -> str:
    result, _ = ocr_engine(image_bytes)
    if not result:
        return ""
    return "\n".join([line[1] for line in result])


def _strip_json_block(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
        raw = raw.rsplit("```", 1)[0]
    return raw.strip()


def analyze_with_llm(content: str, rule_pack: dict) -> dict:
    rule_json = json.dumps(rule_pack, ensure_ascii=False, indent=2)
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": USER_PROMPT_TEMPLATE.format(
                    rule_json=rule_json,
                    content=content,
                ),
            },
        ],
        temperature=0.1,
        max_tokens=2000,
    )
    raw = response.choices[0].message.content.strip()
    return json.loads(_strip_json_block(raw))


def _merge_missing(rule_list: list[str], llm_list: list | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in (rule_list or []) + (llm_list or []):
        s = (x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _tag_rule_indicators(items: list[dict]) -> list[dict]:
    return [{**i, "source": "rule"} for i in items]


def _tag_ai_indicators(items: list[dict]) -> list[dict]:
    return [{**i, "source": "ai"} for i in (items or [])]


def _normalize_risk_level(raw: str | None, fallback: str) -> str:
    s = (raw or "").strip()
    for k in ("\u9ad8\u5371", "\u53ef\u7591", "\u5b89\u5168"):
        if k in s:
            return k
    return fallback


def build_email_blob(
    *,
    text: str | None,
    body: str | None,
    from_addr: str | None,
    subject: str | None,
    ocr_prefix: str,
) -> str:
    parts: list[str] = []
    if ocr_prefix:
        parts.append(ocr_prefix)
    if from_addr and from_addr.strip():
        parts.append(f'{ZH["label_from"]}: {from_addr.strip()}')
    if subject and subject.strip():
        parts.append(f'{ZH["label_subject"]}: {subject.strip()}')
    main = (body if body and body.strip() else text) or ""
    if main.strip():
        parts.append(f'{ZH["label_body"]}:\n{main.strip()}')
    return "\n".join(parts).strip()


@app.post("/api/analyze")
async def analyze(
    text: str = Form(default=None),
    body: str = Form(default=None),
    from_addr: str = Form(default=None),
    subject: str = Form(default=None),
    image: UploadFile = File(default=None),
):
    ocr_prefix = ""
    has_ocr = False
    if image and image.filename:
        try:
            img_bytes = await image.read()
            ocr_text = extract_text_from_image(img_bytes)
            if ocr_text:
                has_ocr = True
                ocr_prefix = f'{ZH["ocr_prefix"]}\n{ocr_text}\n'
        except Exception as e:
            return JSONResponse(
                status_code=400,
                content={"error": f'{ZH["err_image"]}: {str(e)}'},
            )

    email_blob = build_email_blob(
        text=text,
        body=body,
        from_addr=from_addr,
        subject=subject,
        ocr_prefix=ocr_prefix,
    )

    if not email_blob:
        return JSONResponse(
            status_code=400,
            content={"error": ZH["err_input"]},
        )

    main_for_rules = (body if body and body.strip() else text) or ""
    if ocr_prefix and not main_for_rules.strip():
        main_for_rules = ocr_prefix

    rule_pack = rules.run_rule_engine(
        main_for_rules,
        from_addr=from_addr.strip() if from_addr else None,
        subject=subject.strip() if subject else None,
        has_ocr=has_ocr,
    )

    try:
        llm = analyze_with_llm(email_blob, rule_pack)
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=500,
            content={"error": ZH["err_json"]},
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f'{ZH["err_analyze"]}: {str(e)}'},
        )

    llm_level = _normalize_risk_level(
        llm.get("risk_level"),
        ZH.get("llm_default_risk", "\u53ef\u7591"),
    )
    display_level, recon_note = rules.reconcile_display_risk(
        llm_level,
        rule_pack["rule_risk_hint"],
        legitimacy_hints=rule_pack.get("legitimacy_hints"),
    )

    merged_indicators = _tag_rule_indicators(
        rule_pack.get("indicators") or []
    ) + _tag_ai_indicators(llm.get("indicators") or [])

    missing = _merge_missing(
        rule_pack.get("missing_info") or [],
        llm.get("missing_info"),
    )

    payload = {
        "risk_level": display_level,
        "llm_risk_level": llm_level,
        "confidence": llm.get("confidence"),
        "summary": llm.get("summary"),
        "recommendation": llm.get("recommendation"),
        "indicators": merged_indicators,
        "rule_summary": {
            "rule_risk_hint": rule_pack["rule_risk_hint"],
            "url_count": rule_pack["url_count"],
            "urls": rule_pack["urls"][:15],
        },
        "missing_info": missing,
        "reconciliation_note": recon_note,
        "legitimacy_hints": rule_pack.get("legitimacy_hints") or [],
    }

    return {
        "success": True,
        "data": payload,
        "disclaimer": ZH["disclaimer"],
    }


@app.post("/api/feedback")
async def feedback(payload: dict = Body(...)):
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with FEEDBACK_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": str(e)},
        )
    return {"ok": True}


app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn

    print("\n  ", ZH["app_title"], " OK")
    print("  http://localhost:8000\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
