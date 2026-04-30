# 钓鱼邮件检测系统

基于 **规则引擎 + LLM** 的钓鱼邮件辅助研判工具：可复现的客观信号与自然语言解读并存，适合内部员工自助与后续迭代。

## 功能

- **快速粘贴** — 整封邮件一键分析
- **结构化输入** — 单独填写发件人、主题、正文，便于核对仿冒域名与主题话术
- **截图 / OCR** — 上传或 Ctrl+V 粘贴截图
- **规则层证据** — URL（短链、IP 主机、HTTP、Punycode 等）、紧迫话术、索密、可疑附件、展示名与 From 不一致等
- **AI 综合** — 在规则结果之上补充社工与上下文分析（提示词要求不重复规则已列要点）
- **冲突提示** — 规则强烈信号与 AI 结论不一致时自动提示并调整展示评级
- **信息不足提示** — 列出建议补充的字段，减少「硬猜」
- **复制报告 / 反馈** — 一键复制结构化结论；简单反馈写入本地 `data/feedback.jsonl`（需自行纳入运维与隐私策略）

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
├── app.py              # FastAPI：/api/analyze、/api/feedback、静态页
├── rules.py            # 确定性规则与启发式
├── locale_zh.json      # 中文文案与系统提示（UTF-8）
├── skills/             # 可选：附加 LLM 研判框架（见 security-awareness）
│   ├── THIRD_PARTY.txt
│   └── security-awareness/SKILL.md
├── requirements.txt
├── .env.example
├── .gitignore          # 含 data/
└── static/
    └── index.html
```

`skills/security-awareness/SKILL.md` 来自 [1Password SCAM](https://github.com/1Password/SCAM)（MIT），启动时若文件存在，会去掉 YAML 头后追加到 DeepSeek 的 system 提示词中。删除该文件即恢复为仅使用 `locale_zh.json` 内的 `system_prompt`。

## 注意事项

- `.env` 文件包含 API Key，已在 `.gitignore` 中排除，不会上传到 GitHub
- 邮件内容会发送至 DeepSeek API 进行分析，请注意数据合规
- 本工具为辅助研判，不能替代专业安全人员的判断
