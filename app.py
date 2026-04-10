import json
import os
from io import BytesIO

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from rapidocr_onnxruntime import RapidOCR

load_dotenv()

# ---------- 初始化 ----------
app = FastAPI(title="钓鱼邮件检测系统")
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

# ---------- 提示词 ----------
SYSTEM_PROMPT = """你是企业内部的邮件安全分析专家。你的任务是分析用户提交的邮件内容，判断是否为钓鱼邮件。

请从以下维度全面分析：
1. 发件人地址 — 是否存在域名伪造、相似域名（如 shokz.com → sh0kz.com）
2. 紧迫感/恐惧感 — 是否用"立即"、"账号将被冻结"等话术施压
3. 可疑链接 — URL 与显示文字是否一致、是否使用短链接或非官方域名
4. 索取敏感信息 — 是否要求提供密码、银行卡号、验证码、个人证件等
5. 身份冒充 — 是否冒充公司领导、IT 部门、HR、已知品牌或合作伙伴
6. 语言质量 — 语法错误、机翻痕迹、中英文混杂不自然
7. 附件风险 — 是否提及可疑附件（.exe, .scr, .zip, .html 等）
8. 社会工程学 — 利用好奇心、贪婪、同情等心理操控手段

请严格以下面的 JSON 格式返回分析结果（不要返回任何其他文本）：

{
  "risk_level": "高危 或 可疑 或 安全",
  "confidence": 85,
  "summary": "一句话总结判断理由",
  "indicators": [
    {
      "type": "指标名称",
      "detail": "具体描述",
      "severity": "high 或 medium 或 low"
    }
  ],
  "recommendation": "给用户的下一步操作建议"
}"""

USER_PROMPT_TEMPLATE = """请分析以下邮件内容是否为钓鱼邮件：

---邮件内容开始---
{content}
---邮件内容结束---"""


# ---------- OCR 辅助 ----------
def extract_text_from_image(image_bytes: bytes) -> str:
    """用 RapidOCR 从图片中提取文字"""
    result, _ = ocr_engine(image_bytes)
    if not result:
        return ""
    return "\n".join([line[1] for line in result])


# ---------- LLM 分析 ----------
def analyze_with_llm(content: str) -> dict:
    """调用 DeepSeek 分析邮件内容"""
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(content=content)},
        ],
        temperature=0.1,
        max_tokens=2000,
    )

    raw = response.choices[0].message.content.strip()

    # 尝试解析 JSON（兼容 markdown 代码块包裹的情况）
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]  # 去掉 ```json
        raw = raw.rsplit("```", 1)[0]  # 去掉结尾 ```

    return json.loads(raw)


# ---------- API 路由 ----------
@app.post("/api/analyze")
async def analyze(
    text: str = Form(default=None),
    image: UploadFile = File(default=None),
):
    """分析邮件内容或截图"""
    email_content = ""

    # 处理图片输入
    if image and image.filename:
        try:
            img_bytes = await image.read()
            ocr_text = extract_text_from_image(img_bytes)
            if ocr_text:
                email_content += f"[从截图中识别的文字]\n{ocr_text}\n"
        except Exception as e:
            return JSONResponse(
                status_code=400,
                content={"error": f"图片识别失败: {str(e)}"},
            )

    # 处理文字输入
    if text and text.strip():
        email_content += text.strip()

    if not email_content.strip():
        return JSONResponse(
            status_code=400,
            content={"error": "请提供邮件文字内容或截图"},
        )

    # 调用 LLM 分析
    try:
        result = analyze_with_llm(email_content)
        return {"success": True, "data": result}
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=500,
            content={"error": "分析结果解析失败，请重试"},
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"分析失败: {str(e)}"},
        )


# ---------- 静态文件 ----------
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn

    print("\n  钓鱼邮件检测系统已启动")
    print("  打开浏览器访问: http://localhost:8000\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
