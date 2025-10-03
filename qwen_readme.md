# Qwen + Gemini 智能识别系统

这是一个部署在 Cloudflare Workers 上的多功能智能识别与对话系统。它利用了阿里巴巴的 **通义千问（Qwen）** 和谷歌的 **Gemini** 两大先进模型，为您提供强大的文本对话、多模态识别、图片生成和图片编辑等功能。

该项目前端界面简洁易用，后端API兼容OpenAI格式，方便开发者快速集成。

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange)](https://workers.cloudflare.com/)
[![Qwen API](https://img.shields.io/badge/Qwen-API%20v2-blue)](https://qwen.ai/)
[![Gemini API](https://img.shields.io/badge/Gemini-2.5%20Flash-green)](https://ai.google.dev/)

---

## ✨ 主要功能

*   **双模型支持**：自由切换使用通义千问或Gemini 2.5 Flash模型进行图片识别。
*   **多功能Web界面**：
    *   支持拖拽、粘贴、URL或Base64等多种方式上传图片。
    *   实时显示识别结果，并支持LaTeX数学公式渲染。
    *   提供历史记录功能，方便回顾和管理识别结果（数据安全存储于Cloudflare KV）。
    *   支持高级模式，可自定义Prompt以适应不同场景（如公式识别、验证码识别等）。
*   **OpenAI兼容API**：
    *   提供与OpenAI `v1/chat/completions` 完全兼容的API端点。
    *   通过简单的模型名称后缀（如 `-image`、`-search`），即可实现**文本对话**、**图片生成**、**图片编辑**、**视频生成**和**搜索增强**等多种功能。
    *   支持多模态输入，可在对话中直接传递图片进行理解。
*   **独立的图片识别API**：
    *   为图片URL和Base64提供专门的识别API端点，方便集成到现有工作流中。
*   **安全可靠**：
    *   支持密码保护访问Web界面。
    *   API通过Bearer Token进行认证。
    *   Cookie等敏感信息加密存储在Cloudflare KV中。


---
## 🚀 部署指南

### 准备工作

1.  一个 Cloudflare 账户。
2.  开通 Cloudflare Workers 和 KV 存储服务。
3.  获取通义千问的Cookie。
    *   登录 [通义千问官网](https://chat.qwen.ai/)。
    *   打开浏览器开发者工具（按F12），切换到“网络(Network)”标签页。
    *   随便发送一条消息，在请求头中找到 `Cookie` 字段，并复制其完整内容。

### 部署步骤

1.  **创建 Worker**
    *   登录 Cloudflare 控制台，进入 "Workers & Pages"。
    *   点击 "Create application"，然后选择 "Create Worker"。
    *   为您的Worker命名（例如 `qwen-gemini-worker`），然后点击 "Deploy"。

2.  **粘贴代码**
    *   部署完成后，点击 "Edit code"。
    *   将 `worker.js` 文件中的所有代码复制并粘贴到Cloudflare的在线编辑器中，覆盖原有内容。
    *   点击 "Save and deploy"。

3.  **配置环境变量和密钥**
    *   返回Worker的管理页面，进入 "Settings" -> "Variables"。
    *   添加以下**环境变量 (Environment Variables)** 和**加密的环境变量 (Encrypted Environment Variables)**:

| 变量名 | 类型 | 是否必须 | 描述 |
| :--- | :--- | :--- | :--- |
| `PASSWORD` | Encrypted | 是 | 访问Web UI界面的密码。 |
| `API_KEY` | Encrypted | 否 | 访问API的Bearer Token。如果不需要API，可不设置。 |
| `GEMINI_API_KEY` | Encrypted | 否 | 谷歌Gemini模型的API Key。如果不使用Gemini，可不设置。 |

4.  **绑定 KV 命名空间**
    *   在Worker的 "Settings" -> "Variables" 页面向下滚动到 "KV Namespace Bindings"。
    *   点击 "Add binding"。
    *   **变量名称 (Variable name)** 必须设置为 `SETTINGS_KV`。
    *   选择一个现有的KV命名空间，或者创建一个新的（例如 `QWEN_SETTINGS`）。
    *   点击 "Save"。

5.  **初始化配置**
    *   访问您Worker的URL（例如 `https://qwen-gemini-worker.your-subdomain.workers.dev`）。
    *   输入您设置的 `PASSWORD` 登录。
    *   点击右下角的 "⚙️ Cookie设置" 按钮。
    *   将准备工作中获取的通义千问Cookie完整粘贴进去，然后点击 "保存设置到云端"。

至此，您的智能识别系统已部署完成！

---

## 📖 使用说明

### Web 界面

*   **模型选择**: 在页面顶部选择使用“通义千问”或“Gemini”，需提前输入自己的apikey。
*   **图片上传**:
    *   **文件/粘贴 (默认)**: 点击或拖拽图片文件到上传区域，或直接粘贴剪贴板中的图片。
    *   **URL输入**: 切换到URL模式，输入图片的公开链接。
    *   **Base64输入**: 切换到Base64模式，粘贴图片的Base64编码。
*   **高级模式**: 在 "Cookie设置" 侧边栏中，勾选 "高级模式" 可以自定义发送给模型的Prompt，以获得更精确的识别结果。

---

## 📡 API 接口

### 1. 图片识别接口

#### 通过 URL 识别
```http
POST /api/recognize/url
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY
x-recognition-model: 0

{
  "imageUrl": "https://example.com/image.png"
}
```

#### 通过 Base64 识别
```http
POST /api/recognize/base64
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY
x-recognition-model: 1

{
  "base64Image": "iVBORw0KGgo..."
}
```

#### 请求头说明

| Header | 说明 | 值 |
|--------|------|-----|
| `x-recognition-model` | 选择识别模型 | `0`: 通义千问（默认）<br>`1`: Gemini 2.5 Flash |
| `x-advanced-mode` | 启用高级模式 | `true` 或 `false` |
| `x-custom-prompt` | 自定义提示词 | Base64 编码的提示词 |

#### 响应格式
```json
{
  "success": true,
  "result": "识别出的文本内容...",
  "type": "text"
}
```

---

### 2. 对话与生成接口

#### 接口地址
```http
POST /v1/chat/completions
Content-Type: application/json
Authorization: Bearer YOUR_API_KEY
```

#### 功能模式

通过模型名称后缀控制功能：

| 模型后缀 | 功能 | 示例 |
|---------|------|------|
| 无后缀 | 标准文本对话 | `qwen-max-latest` |
| `-image` | 文本生成图片 | `qwen-max-latest-image` |
| `-image-edit` | 图片编辑 | `qwen-max-latest-image-edit` |
| `-video` | 文本生成视频 | `qwen-max-latest-video` |
| `-search` | 搜索增强模式 | `qwen-max-latest-search` |

---

## 💡 使用示例

### 示例 1：文本对话

```bash
curl -X POST 'https://your-worker.workers.dev/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "model": "qwen-max-latest",
    "messages": [
      {"role": "user", "content": "你好，请介绍一下你自己"}
    ],
    "stream": false
  }'
```

**响应**：
```json
{
  "success": true,
  "data": {
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "你好！我是通义千问，一个由阿里云开发的大型语言模型..."
      }
    }]
  }
}
```

---

### 示例 2：图片生成

```bash
curl -X POST 'https://your-worker.workers.dev/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "model": "qwen-max-latest-image",
    "messages": [
      {"role": "user", "content": "画一只可爱的小猫"}
    ],
    "stream": false
  }'
```

**响应**：
```json
{
  "data": {
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "https://cdn.qwenlm.ai/output/.../image.png?key=..."
      }
    }]
  }
}
```

---

### 示例 3：图片理解（多模态）

```bash
curl -X POST 'https://your-worker.workers.dev/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "model": "qwen-max-latest",
    "messages": [{
      "role": "user",
      "content": [
        {"type": "text", "text": "这张图片里有什么？"},
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/png;base64,iVBORw0KGgo..."
          }
        }
      ]
    }],
    "stream": false
  }'
```

**响应**：
```json
{
  "success": true,
  "data": {
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "这张图片中有一只可爱的小猫，它正在..."
      }
    }]
  }
}
```

---

### 示例 4：图片识别（URL）

```bash
curl -X POST 'https://your-worker.workers.dev/api/recognize/url' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -H 'x-recognition-model: 0' \
  -d '{
    "imageUrl": "https://example.com/captcha.png"
  }'
```

**响应**：
```json
{
  "success": true,
  "result": "ABCD1234",
  "type": "captcha"
}
```

---


## 📄 许可证

MIT License
