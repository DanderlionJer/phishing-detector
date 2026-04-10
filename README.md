# 钓鱼邮件检测系统

基于 LLM 的钓鱼邮件智能检测工具，供企业内部员工快速判断可疑邮件。

## 功能

- **文字检测** — 粘贴邮件全文，AI 分析是否为钓鱼邮件
- **截图检测** — 上传邮件截图或 Ctrl+V 粘贴，OCR 识别后自动分析
- **风险评级** — 高危 / 可疑 / 安全 三级评估，附带详细风险指标和操作建议

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 API Key

```bash
cp .env.example .env
```

编辑 `.env` 文件，填入你的 DeepSeek API Key（从 https://platform.deepseek.com/api_keys 获取）。

### 3. 启动服务

```bash
python app.py
```

浏览器打开 http://localhost:8000 即可使用。

## 技术栈

- **后端**: Python + FastAPI
- **前端**: 原生 HTML/CSS/JS（无框架依赖）
- **LLM**: DeepSeek API（OpenAI 兼容格式）
- **OCR**: RapidOCR（图片文字识别）

## 项目结构

```
phishing-detector/
├── app.py              # 后端服务
├── requirements.txt    # Python 依赖
├── .env.example        # API Key 配置模板
├── .gitignore          # Git 忽略规则
└── static/
    └── index.html      # 前端页面
```

## 注意事项

- `.env` 文件包含 API Key，已在 `.gitignore` 中排除，不会上传到 GitHub
- 邮件内容会发送至 DeepSeek API 进行分析，请注意数据合规
- 本工具为辅助研判，不能替代专业安全人员的判断
