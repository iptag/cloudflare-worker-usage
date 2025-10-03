// =================================================
// Qwen + Gemini 智能识别系统 (Qwen v2 API)
// 支持：对话、图片识别、图片生成、图片编辑
// 更新日期：2025-10-01
// =================================================

/**
 * 生成 UUID v4
 */
function generateUUID() {
  return crypto.randomUUID();
}

/**
 * SHA256 加密
 */
async function sha256Encrypt(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 图片缓存管理器
 */
class ImageCacheManager {
  constructor() {
    this.cache = new Map();
    this.maxSize = 100;
  }
  cacheExists(signature) {
    return this.cache.has(signature);
  }
  getCache(signature) {
    return this.cache.get(signature);
  }
  addCache(signature, url) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(signature, { url, timestamp: Date.now() });
  }
}

const imageCacheManager = new ImageCacheManager();

/**
 * 判断聊天类型
 */
function isChatType(model) {
  if (!model) return 't2t';
  if (model.includes('-search')) return 'search';
  if (model.includes('-image-edit')) return 'image_edit';
  if (model.includes('-image')) return 't2i';
  if (model.includes('-video')) return 't2v';
  if (model.includes('-deep-research')) return 'deep_research';
  return 't2t';
}

/**
 * 解析模型名称
 */
function parserModel(model) {
  if (!model) return 'qwen3-235b-a22b';
  try {
    model = String(model);
    model = model.replace('-search', '');
    model = model.replace('-thinking', '');
    model = model.replace('-edit', '');
    model = model.replace('-video', '');
    model = model.replace('-deep-research', '');
    model = model.replace('-image', '');
    return model;
  } catch (e) {
    return 'qwen3-235b-a22b';
  }
}

/**
 * 判断是否启用思考模式
 */
function isThinkingEnabled(model, enable_thinking, thinking_budget) {
  const thinking_config = {
    "output_schema": "phase",
    "thinking_enabled": false,
    "thinking_budget": 81920
  };
  if (!model) return thinking_config;
  if (model.includes('-thinking') || enable_thinking) {
    thinking_config.thinking_enabled = true;
  }
  if (thinking_budget && Number(thinking_budget) > 0 && Number(thinking_budget) < 38912) {
    thinking_config.budget = Number(thinking_budget);
  }
  return thinking_config;
}

/**
 * 获取简化的文件类型
 */
function getSimpleFileType(mimeType) {
  if (!mimeType) return 'file';
  const mainType = mimeType.split('/')[0].toLowerCase();
  const supportedTypes = ['image', 'video', 'audio', 'document'];
  return supportedTypes.includes(mainType) ? mainType : 'file';
}

// =================================================
// 1. Authentication & Configuration
// =================================================

async function handleLogin(request) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }
  if (typeof PASSWORD === 'undefined') {
    return new Response('Server configuration error: The PASSWORD secret is not set in the Worker environment.', { status: 500 });
  }
  const formData = await request.formData();
  const password = formData.get('password');
  if (password === PASSWORD) {
    const sessionCookie = `auth_session=ok; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`; // 24-hour session
    return new Response(null, {
      status: 302,
      headers: { 'Set-Cookie': sessionCookie, 'Location': '/' },
    });
  } else {
    return new Response(null, {
      status: 302,
      headers: { 'Location': '/?error=1' },
    });
  }
}

async function checkAuth(request) {
  if (typeof API_KEY !== 'undefined' && API_KEY) {
    const authHeader = request.headers.get('Authorization') || '';
    if (authHeader === `Bearer ${API_KEY}`) {
      return null;
    }
  }
  const url = new URL(request.url);
  const cookie = request.headers.get('Cookie') || '';
  if (cookie.includes('auth_session=ok')) {
    return null;
  }
  const isApiCall = url.pathname.startsWith('/api/') || url.pathname.startsWith('/recognize') || url.pathname.startsWith('/proxy/upload');
  if (isApiCall) {
    return new Response(JSON.stringify({ error: 'Unauthorized. Provide API Key in Authorization header or log in.' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(getLoginPage(url), {
    status: 401,
    headers: { 'Content-Type': 'text/html' },
  });
}

function getLoginPage(url) {
  const error = url.searchParams.get('error') ? '<p style="color: red; text-align: center;">密码错误，请重试！</p>' : '';
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>请输入密码</title><style>body { font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; background: #f0f2f5; margin: 0; } .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 320px; } h1 { text-align: center; color: #333; margin-top: 0; } input[type="password"] { width: 100%; padding: 12px; margin-top: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; } button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; } button:hover { background: #0056b3; }</style></head><body><div class="login-box"><h1>身份验证</h1>${error}<form action="/login" method="post"><input type="password" name="password" placeholder="请输入访问密码" required autofocus><button type="submit">进入</button></form></div></body></html>`;
}

async function getQwenCookie() {
  if (typeof SETTINGS_KV === 'undefined') {
    throw new Error('Server configuration error: The SETTINGS_KV namespace is not bound to this Worker.');
  }
  const cookie = await SETTINGS_KV.get('QWEN_COOKIE');
  if (!cookie) {
    throw new Error('Qwen cookie not set in Worker settings. Please save it via the UI.');
  }
  return cookie;
}

// NEW: Helper to get Gemini API Key from environment variables
async function getGeminiApiKey() {
  if (typeof GEMINI_API_KEY === 'undefined' || !GEMINI_API_KEY) {
    throw new Error('Server configuration error: The GEMINI_API_KEY secret is not set in the Worker environment.');
  }
  return GEMINI_API_KEY;
}

// =================================================
// 1.5. Qwen v2 图片上传到 OSS
// =================================================

/**
 * 请求 STS Token
 */
async function requestStsToken(filename, filesize, filetypeSimple, authToken) {
  const requestId = generateUUID();
  const bearerToken = authToken.startsWith('Bearer ') ? authToken : `Bearer ${authToken}`;

  const response = await fetch('https://chat.qwen.ai/api/v1/files/getstsToken', {
    method: 'POST',
    headers: {
      'Authorization': bearerToken,
      'Content-Type': 'application/json',
      'x-request-id': requestId,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    },
    body: JSON.stringify({
      filename,
      filesize,
      filetype: filetypeSimple
    })
  });

  if (!response.ok) {
    throw new Error(`获取STS Token失败: ${response.status}`);
  }

  const stsData = await response.json();

  return {
    credentials: {
      access_key_id: stsData.access_key_id,
      access_key_secret: stsData.access_key_secret,
      security_token: stsData.security_token
    },
    file_info: {
      url: stsData.file_url,
      path: stsData.file_path,
      bucket: stsData.bucketname,
      endpoint: stsData.region + '.aliyuncs.com',
      id: stsData.file_id
    }
  };
}

/**
 * 上传到 OSS
 */
async function uploadToOss(fileBuffer, credentials, fileInfo, mimeType) {
  const date = new Date().toUTCString();
  const contentType = mimeType || 'application/octet-stream';

  // 构建签名字符串
  const stringToSign = `PUT\n\n${contentType}\n${date}\nx-oss-security-token:${credentials.security_token}\n/${fileInfo.bucket}/${fileInfo.path}`;

  // 使用 HMAC-SHA1 签名
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(credentials.access_key_secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(stringToSign)
  );

  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  const authorization = `OSS ${credentials.access_key_id}:${signatureBase64}`;

  const response = await fetch(`https://${fileInfo.bucket}.${fileInfo.endpoint}/${fileInfo.path}`, {
    method: 'PUT',
    headers: {
      'Content-Type': contentType,
      'Date': date,
      'Authorization': authorization,
      'x-oss-security-token': credentials.security_token
    },
    body: fileBuffer
  });

  if (!response.ok) {
    throw new Error(`OSS上传失败: ${response.status}`);
  }

  return { success: true };
}

/**
 * 完整的文件上传流程
 */
async function uploadFileToQwenOss(fileBuffer, originalFilename, authToken) {
  const filesize = fileBuffer.byteLength || fileBuffer.length;

  // 从文件名获取 MIME 类型
  const ext = originalFilename.split('.').pop().toLowerCase();
  const mimeTypes = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'bmp': 'image/bmp'
  };
  const mimeType = mimeTypes[ext] || 'application/octet-stream';
  const filetypeSimple = getSimpleFileType(mimeType);

  // 获取 STS Token
  const { credentials, file_info } = await requestStsToken(
    originalFilename,
    filesize,
    filetypeSimple,
    authToken
  );

  // 上传到 OSS
  await uploadToOss(fileBuffer, credentials, file_info, mimeType);

  return {
    status: 200,
    file_url: file_info.url,
    file_id: file_info.id,
    message: '文件上传成功'
  };
}

// =================================================
// 1.6. Qwen v2 消息解析
// =================================================

/**
 * 解析消息格式，处理图片上传
 */
async function parserMessages(messages, thinking_config, chat_type, authToken) {
  try {
    const feature_config = thinking_config;

    for (let message of messages) {
      if (message.role === 'user' || message.role === 'assistant') {
        message.chat_type = "t2t";
        message.extra = {};
        message.feature_config = {
          "output_schema": "phase",
          "thinking_enabled": false,
        };

        if (!Array.isArray(message.content)) continue;

        const newContent = [];

        for (let item of message.content) {
          if (item.type === 'image' || item.type === 'image_url') {
            let base64 = null;
            if (item.type === 'image_url') {
              base64 = item.image_url.url;
            }

            if (base64) {
              const regex = /data:(.+);base64,/;
              const fileType = base64.match(regex);
              const fileExtension = fileType && fileType[1] ? fileType[1].split('/')[1] || 'png' : 'png';
              const filename = `${generateUUID()}.${fileExtension}`;
              const pureBase64 = base64.replace(regex, '');
              const signature = await sha256Encrypt(pureBase64);

              try {
                // 将 base64 转换为 ArrayBuffer
                const binaryString = atob(pureBase64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                  bytes[i] = binaryString.charCodeAt(i);
                }
                const buffer = bytes.buffer;

                // 检查缓存
                if (imageCacheManager.cacheExists(signature)) {
                  delete item.image_url;
                  item.type = 'image';
                  item.image = imageCacheManager.getCache(signature).url;
                  newContent.push(item);
                } else {
                  const uploadResult = await uploadFileToQwenOss(buffer, filename, authToken);
                  if (uploadResult && uploadResult.status === 200) {
                    delete item.image_url;
                    item.type = 'image';
                    item.image = uploadResult.file_url;
                    imageCacheManager.addCache(signature, uploadResult.file_url);
                    newContent.push(item);
                  }
                }
              } catch (error) {
                console.error('图片上传失败:', error);
              }
            }
          } else if (item.type === 'text') {
            item.chat_type = 't2t';
            item.feature_config = {
              "output_schema": "phase",
              "thinking_enabled": false,
            };

            if (newContent.length >= 2) {
              messages.push({
                "role": "user",
                "content": item.text,
                "chat_type": "t2t",
                "extra": {},
                "feature_config": {
                  "output_schema": "phase",
                  "thinking_enabled": false,
                }
              });
            } else {
              newContent.push(item);
            }
          }
        }

        if (newContent.length > 0) {
          message.content = newContent;
        }
      } else {
        // 处理 system 消息
        if (Array.isArray(message.content)) {
          let system_prompt = '';
          for (let item of message.content) {
            if (item.type === 'text') {
              system_prompt += item.text;
            }
          }
          if (system_prompt) {
            message.content = system_prompt;
          }
        }
      }
    }

    messages[messages.length - 1].feature_config = feature_config;
    messages[messages.length - 1].chat_type = chat_type;

    return messages;
  } catch (e) {
    console.error('消息解析失败:', e);
    return [{
      "role": "user",
      "content": "直接返回字符串： '聊天历史处理有误...'",
      "chat_type": "t2t",
      "extra": {},
      "feature_config": {
        "output_schema": "phase",
        "enabled": false,
      }
    }];
  }
}

/**
 * 生成 chat_id
 * 注意：chat_type 硬编码为 "t2i"，这是 Qwen2api 的标准做法
 */
async function generateChatID(token, model) {
  try {
    const response = await fetch('https://chat.qwen.ai/api/v2/chats/new', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      body: JSON.stringify({
        "title": "New Chat",
        "models": [model],
        "chat_mode": "local",
        "chat_type": "t2i",  // 硬编码为 t2i，与 Qwen2api 保持一致
        "timestamp": Date.now()
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('生成chat_id失败 - HTTP错误:', response.status, errorText);
      return null;
    }

    const data = await response.json();
    return data?.data?.id || null;
  } catch (error) {
    console.error('生成chat_id失败:', error);
    return null;
  }
}

/**
 * 发送聊天请求
 */
async function sendChatRequest(body, token) {
  try {
    const chat_id = await generateChatID(token, body.model);
    if (!chat_id) {
      throw new Error('生成chat_id失败');
    }

    const response = await fetch(`https://chat.qwen.ai/api/v2/chat/completions?chat_id=${chat_id}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      body: JSON.stringify({
        ...body,
        chat_id: chat_id
      })
    });

    return response;
  } catch (error) {
    console.error('发送聊天请求失败:', error);
    throw error;
  }
}

// =================================================
// 2. Main Request Handler
// =================================================

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);

  try {
    if (url.pathname === '/login') {
      return await handleLogin(request);
    }

    if (url.pathname !== '/favicon.ico' && url.pathname !== '/api-docs') {
      const authResponse = await checkAuth(request);
      if (authResponse) {
        return authResponse;
      }
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-recognition-model, x-custom-prompt',
        },
      });
    }

    switch (url.pathname) {
      // 新增：Qwen v2 对话接口
      case '/v1/chat/completions':
        return await handleChatCompletions(request);

      case '/api/settings':
        if (request.method === 'GET') {
          const cookie = await SETTINGS_KV.get('QWEN_COOKIE') || '';
          return new Response(JSON.stringify({ cookie }), { headers: { 'Content-Type': 'application/json' } });
        }
        if (request.method === 'POST') {
          const requestData = await request.json();
          // 处理Cookie保存
          if (requestData.cookie !== undefined) {
            await SETTINGS_KV.put('QWEN_COOKIE', requestData.cookie);
            return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
          }
          // 处理历史记录获取
          if (requestData.action === 'get_history' && requestData.key) {
            try {
              const history = await SETTINGS_KV.get(requestData.key);
              return new Response(JSON.stringify({
                success: true,
                history: history ? JSON.parse(history) : []
              }), { headers: { 'Content-Type': 'application/json' } });
            } catch (error) {
              return new Response(JSON.stringify({
                success: false,
                error: '获取历史记录失败',
                history: []
              }), { headers: { 'Content-Type': 'application/json' } });
            }
          }
          // 处理历史记录保存
          if (requestData.action === 'save_history' && requestData.key && requestData.history) {
            try {
              await SETTINGS_KV.put(requestData.key, JSON.stringify(requestData.history));
              return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
            } catch (error) {
              return new Response(JSON.stringify({
                success: false,
                error: '保存历史记录失败'
              }), { headers: { 'Content-Type': 'application/json' } });
            }
          }
          return new Response(JSON.stringify({ success: false, error: '无效的请求参数' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        break;
      case '/api/recognize/url':
        return await handleImageUrlRecognition(request);
      case '/api/recognize/base64':
        return await handleBase64Recognition(request);
      case '/recognize':
        return await handleFileRecognition(request);
      case '/proxy/upload':
        return await handleProxyUpload(request);
      case '/api-docs':
        return new Response(getApiDocsHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      case '/':
        return new Response(getHTML(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    return new Response('Not Found', { status: 404 });
  } catch (e) {
    console.error('[handleRequest] 错误:', e);
    return new Response(JSON.stringify({
      error: e.message,
      stack: e.stack
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

// =================================================
// 3. API Handlers
// =================================================

// MODIFIED: This function now routes to Qwen or Gemini based on a header
async function handleImageUrlRecognition(request) {
  try {
    const model = request.headers.get('x-recognition-model') || '0';
    const { imageUrl } = await request.json();
    if (!imageUrl) return new Response(JSON.stringify({ error: 'Missing imageUrl' }), { status: 400 });

    let customPrompt = '';
    try {
      const encodedPrompt = request.headers.get('x-custom-prompt');
      if (encodedPrompt) customPrompt = decodeURIComponent(atob(encodedPrompt));
    } catch (e) {}

    if (model === '1') { // Gemini
      const imageResponse = await fetch(imageUrl);
      if (!imageResponse.ok) throw new Error(`Failed to fetch image from URL: ${imageResponse.statusText}`);
      const imageBlob = await imageResponse.blob();
      const buffer = await imageBlob.arrayBuffer();
      // Convert buffer to base64
      let binary = '';
      const bytes = new Uint8Array(buffer);
      for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
      }
      const base64 = btoa(binary);

      const defaultPrompt = 'Describe the image. If it is a math formula, output in LaTeX. If it is a captcha, output only the characters.';
      const prompt = customPrompt || defaultPrompt;
      const result = await recognizeWithGemini(base64, prompt);
      return new Response(JSON.stringify({ success: true, result: result, type: 'text' }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    } else { // Qwen v2
      const cookie = await getQwenCookie();
      const tokenMatch = cookie.match(/token=([^;]+)/);
      if (!tokenMatch) throw new Error('Invalid cookie format in KV: missing token');
      const token = tokenMatch[1];

      // 下载图片 - 添加浏览器请求头以避免 403 错误
      const imageResponse = await fetch(imageUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Referer': new URL(imageUrl).origin,
          'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
          'Cache-Control': 'no-cache'
        }
      });
      if (!imageResponse.ok) {
        throw new Error(`Failed to fetch image: ${imageResponse.status} ${imageResponse.statusText}`);
      }
      const arrayBuffer = await imageResponse.arrayBuffer();

      // 上传到 OSS
      const uploadResult = await uploadFileToQwenOss(arrayBuffer, 'image.png', token);

      if (!uploadResult || uploadResult.status !== 200) {
        throw new Error('File upload to Qwen OSS failed');
      }

      // 使用上传后的 URL 进行识别
      return await recognizeImage(token, uploadResult.file_url, request);
    }
  } catch (error) {
    console.error('[handleImageUrlRecognition] 错误:', error);
    return new Response(JSON.stringify({
      error: error.message,
      stack: error.stack
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

// MODIFIED: This function now routes to Qwen or Gemini based on a header
async function handleBase64Recognition(request) {
  try {
    const model = request.headers.get('x-recognition-model') || '0';
    const { base64Image } = await request.json();
    if (!base64Image) return new Response(JSON.stringify({ error: 'Missing base64Image' }), { status: 400 });

    let customPrompt = '';
    try {
      const encodedPrompt = request.headers.get('x-custom-prompt');
      if (encodedPrompt) customPrompt = decodeURIComponent(atob(encodedPrompt));
    } catch (e) {}

    if (model === '1') { // Gemini
      const defaultPrompt = 'Describe the image. If it is a math formula, output in LaTeX. If it is a captcha, output only the characters.';
      const prompt = customPrompt || defaultPrompt;
      const result = await recognizeWithGemini(base64Image, prompt);
      return new Response(JSON.stringify({ success: true, result: result, type: 'text' }), { headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    } else { // Qwen v2
      const cookie = await getQwenCookie();
      const tokenMatch = cookie.match(/token=([^;]+)/);
      if (!tokenMatch) throw new Error('Invalid cookie format in KV: missing token');
      const token = tokenMatch[1];

      // 将 base64 转换为 ArrayBuffer
      const imageData = base64Image.startsWith('data:') ? base64Image : 'data:image/png;base64,' + base64Image;
      const pureBase64 = imageData.replace(/^data:image\/\w+;base64,/, '');
      const binaryString = atob(pureBase64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const arrayBuffer = bytes.buffer;

      // 上传到 OSS
      const uploadResult = await uploadFileToQwenOss(arrayBuffer, 'image.png', token);

      if (!uploadResult || uploadResult.status !== 200) {
        throw new Error('File upload to Qwen OSS failed');
      }

      // 使用上传后的 URL 进行识别
      return await recognizeImage(token, uploadResult.file_url, request);
    }
  } catch (error) {
    console.error('[handleBase64Recognition] 错误:', error);
    return new Response(JSON.stringify({
      error: error.message,
      stack: error.stack
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

async function handleFileRecognition(request) {
    try {
      const { imageId } = await request.json();

      if (!imageId) return new Response(JSON.stringify({ error: 'Missing imageId' }), { status: 400 });

      const cookie = await getQwenCookie();
      const tokenMatch = cookie.match(/token=([^;]+)/);
      if (!tokenMatch) throw new Error('Invalid cookie format: missing token');
      const token = tokenMatch[1];

      // imageId 现在应该是 OSS URL
      return await recognizeImage(token, imageId, request);
    } catch (error) {
      console.error('[handleFileRecognition] 错误:', error);
      return new Response(JSON.stringify({
        error: error.message,
        stack: error.stack
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
}

async function handleProxyUpload(request) {
    try {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) {
        return new Response(JSON.stringify({ error: 'No file uploaded' }), { status: 400 });
      }

      const cookie = await getQwenCookie();
      const tokenMatch = cookie.match(/token=([^;]+)/);
      if (!tokenMatch) throw new Error('Invalid cookie format: missing token');
      const token = tokenMatch[1];

      // 读取文件内容
      const arrayBuffer = await file.arrayBuffer();

      // 上传到 OSS
      const uploadResult = await uploadFileToQwenOss(arrayBuffer, file.name, token);

      return new Response(JSON.stringify({
        success: true,
        id: uploadResult.file_url,  // 返回 URL 作为 ID
        url: uploadResult.file_url
      }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    } catch (error) {
      console.error('文件上传失败:', error);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
}

// =================================================
// 2.5. Qwen v2 对话处理函数
// =================================================

/**
 * 处理 /v1/chat/completions 请求
 */
async function handleChatCompletions(request) {
  try {
    const body = await request.json();
    const { model, messages, stream, enable_thinking, thinking_budget } = body;

    // 获取 Qwen Cookie
    const cookie = await getQwenCookie();
    const tokenMatch = cookie.match(/token=([^;]+)/);
    if (!tokenMatch) {
      throw new Error('Invalid cookie format: missing token');
    }
    const token = tokenMatch[1];

    // 解析模型和聊天类型
    const parsedModel = parserModel(model);
    const chatType = isChatType(model);
    const thinkingConfig = isThinkingEnabled(model, enable_thinking, thinking_budget);

    // 解析消息
    const parsedMessages = await parserMessages(messages, thinkingConfig, chatType, token);

    // 构建请求体
    const requestBody = {
      model: parsedModel,
      messages: parsedMessages,
      stream: stream !== false,
      session_id: generateUUID(),
      id: generateUUID()
    };

    // 发送请求
    const response = await sendChatRequest(requestBody, token);

    // 检查响应的 Content-Type
    const contentType = response.headers.get('content-type') || '';
    const isStreamResponse = contentType.includes('text/event-stream') || contentType.includes('stream');

    if (stream !== false && isStreamResponse) {
      // 流式响应
      return new Response(response.body, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*'
        }
      });
    } else {
      // 非流式响应或需要转换流式响应为非流式
      if (isStreamResponse) {
        // 如果 API 返回流式但用户要求非流式，需要解析流式数据
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let fullContent = '';
        let responseMetadata = null;
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || ''; // 保留最后一个不完整的行

          for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine) continue;

            if (trimmedLine.startsWith('data: ')) {
              const data = trimmedLine.slice(6);
              if (data === '[DONE]') continue;

              try {
                const parsed = JSON.parse(data);

                // 保存元数据（第一次遇到时）
                if (!responseMetadata) {
                  responseMetadata = {
                    success: parsed.success,
                    request_id: parsed.request_id,
                    data: {
                      chat_id: parsed.data?.chat_id,
                      parent_id: parsed.data?.parent_id,
                      message_id: parsed.data?.message_id
                    }
                  };
                }

                // 提取内容
                const content = parsed.data?.choices?.[0]?.delta?.content ||
                               parsed.choices?.[0]?.delta?.content ||
                               parsed.data?.choices?.[0]?.message?.content ||
                               parsed.choices?.[0]?.message?.content || '';

                if (content && content.trim()) {
                  // 对于图片生成（t2i），第一个非空内容通常是图片 URL
                  // 对于文本对话，累积所有内容
                  if (chatType === 't2i' || chatType === 't2v') {
                    // 图片/视频生成：只取第一个非空内容（通常是 URL）
                    if (!fullContent) {
                      fullContent = content;
                    }
                  } else {
                    // 文本对话：累积所有内容
                    fullContent += content;
                  }
                }
              } catch (e) {
                console.error('解析流式数据失败:', e, '数据:', data.substring(0, 100));
              }
            } else if (trimmedLine.startsWith('response.created:')) {
              // 处理 response.created 事件
              try {
                const data = trimmedLine.slice(17).trim();
                const parsed = JSON.parse(data);
                if (!responseMetadata) {
                  responseMetadata = {
                    success: true,
                    data: parsed
                  };
                }
              } catch (e) {
                console.error('解析 response.created 失败:', e);
              }
            }
          }
        }

        // 构建非流式响应
        const finalResponse = responseMetadata || { success: true, data: {} };

        // 确保有 choices 数组
        if (!finalResponse.data.choices) {
          finalResponse.data.choices = [{
            message: {
              role: 'assistant',
              content: fullContent || '生成完成'
            }
          }];
        } else {
          // 更新现有的 choices
          finalResponse.data.choices[0] = {
            ...finalResponse.data.choices[0],
            message: {
              role: 'assistant',
              content: fullContent || '生成完成'
            }
          };
          delete finalResponse.data.choices[0].delta;
        }

        return new Response(JSON.stringify(finalResponse), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      } else {
        // 真正的非流式响应
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }
  } catch (error) {
    console.error('Chat completions error:', error);
    return new Response(JSON.stringify({
      error: {
        message: error.message || 'Internal server error',
        type: 'server_error'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// NEW: Gemini recognition function
async function recognizeWithGemini(base64Image, prompt) {
  const apiKey = await getGeminiApiKey();
  const model = "gemini-2.5-flash"; // Use the standard model for vision
  const apiUrl = `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${apiKey}`;
  
  const pureBase64 = base64Image.split(',')[1] || base64Image;

  const requestBody = {
    contents: [{
      parts: [
        { text: prompt },
        { inline_data: { mime_type: "image/png", data: pureBase64 } }
      ]
    }],
    generationConfig: {
      temperature: 0.1,
      topK: 32,
      topP: 1,
      maxOutputTokens: 4096,
    },
     safetySettings: [ // Add safety settings to reduce blocking
      { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
      { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
      { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
      { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_MEDIUM_AND_ABOVE' },
    ]
  };
  
  const response = await fetch(apiUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error("Gemini API Error:", errorBody);
    throw new Error(`Gemini API request failed with status ${response.status}.`);
  }

  const responseData = await response.json();

  if (responseData.candidates && responseData.candidates.length > 0) {
    const candidate = responseData.candidates[0];
    if (candidate.finishReason === "SAFETY") {
        throw new Error("Gemini API Error: The response was blocked due to safety settings. Try a different image or prompt.");
    }
    if (candidate.content && candidate.content.parts && candidate.content.parts.length > 0) {
      return candidate.content.parts[0].text || "";
    }
  }
  
  // Check for prompt feedback if no candidates
  if (responseData.promptFeedback && responseData.promptFeedback.blockReason) {
    throw new Error(`Gemini API Error: The prompt was blocked due to ${responseData.promptFeedback.blockReason}.`);
  }
  
  throw new Error("Gemini recognition failed: No valid content was returned from the API.");
}

async function recognizeImage(token, imageUrl, request) {
  const advancedMode = request.headers.get('x-advanced-mode') === 'true';
  let customPrompt = '';
  try {
    const encodedPrompt = request.headers.get('x-custom-prompt');
    if (encodedPrompt) customPrompt = decodeURIComponent(atob(encodedPrompt));
  } catch (e) {}

  const defaultPrompt = '不要输出任何额外的解释或说明,禁止输出例如：识别内容、以上内容已严格按照要求进行格式化和转换等相关无意义的文字！请识别图片中的内容，注意以下要求：\n对于数学公式和普通文本：\n1. 所有数学公式和数学符号都必须使用标准的LaTeX格式\n2. 行内公式使用单个$符号包裹，如：$x^2$\n3. 独立公式块使用两个$$符号包裹，如：$$\\sum_{i=1}^n i^2$$\n4. 普通文本保持原样，不要使用LaTeX格式\n5. 保持原文的段落格式和换行\n6. 明显的换行使用\\n表示\n7. 确保所有数学符号都被正确包裹在$或$$中\n\n对于验证码图片：\n1. 只输出验证码字符，不要加任何额外解释\n2. 忽略干扰线和噪点\n3. 注意区分相似字符，如0和O、1和l、2和Z等\n4. 验证码通常为4-6位字母数字组合\n\n';

  // 使用 Qwen v2 API - 按照 Qwen2api 的格式构建消息
  // 注意：必须使用 parserMessages 处理过的格式
  const messages = [{
    role: 'user',
    content: [
      {
        type: 'text',
        text: advancedMode ? customPrompt : defaultPrompt,
        chat_type: 't2t',
        feature_config: {
          output_schema: 'phase',
          thinking_enabled: false
        }
      },
      {
        type: 'image',
        image: imageUrl  // 使用 OSS URL（已经上传过了）
      }
    ],
    chat_type: 't2t',  // 消息级别的 chat_type
    extra: {},
    feature_config: {
      output_schema: 'phase',
      thinking_enabled: false
    }
  }];

  const requestBody = {
    model: 'qwen-max-latest',
    messages: messages,
    stream: false,
    session_id: generateUUID(),
    id: generateUUID()
  };

  // 使用新的 sendChatRequest 函数
  const response = await sendChatRequest(requestBody, token);

  if (!response.ok) {
    const errorText = await response.text();
    console.error('[recognizeImage] Qwen API HTTP错误:', response.status, errorText);
    throw new Error(`Qwen API request failed: ${response.status} - ${errorText.substring(0, 200)}`);
  }

  let data;
  const responseText = await response.text();

  try {
    data = JSON.parse(responseText);
  } catch (e) {
    console.error('[recognizeImage] JSON 解析失败:', e);
    throw new Error(`Failed to parse Qwen API response: ${e.message}`);
  }

  // Qwen v2 API 响应格式检查
  // 注意：Qwen v2 API 返回格式为 {success: true, data: {choices: [...]}}
  let actualData = data;

  // 如果响应包含 data 字段，提取它
  if (data.success && data.data) {
    actualData = data.data;
  }

  // 提取结果
  let result = '';
  if (actualData.choices && Array.isArray(actualData.choices) && actualData.choices.length > 0) {
    // 标准 OpenAI 格式
    result = actualData.choices[0]?.message?.content || '识别失败';
  } else if (actualData.output && actualData.output.text) {
    // Qwen 原生格式
    result = actualData.output.text;
  } else if (data.message || actualData.message) {
    // 可能的错误消息
    const errorMsg = data.message || actualData.message;
    console.error('[recognizeImage] API 返回错误:', errorMsg);
    throw new Error(`Qwen API error: ${errorMsg}`);
  } else {
    console.error('[recognizeImage] 未知响应格式:', JSON.stringify(data));
    throw new Error(`Invalid response from Qwen API: unknown format. Response: ${JSON.stringify(data).substring(0, 500)}`);
  }

  if (!advancedMode) {
    if (result.length <= 10 && /^[A-Za-z0-9]+$/.test(result)) {
      return new Response(JSON.stringify({ success: true, result: result.toUpperCase(), type: 'captcha' }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
    result = result.replace(/\\（/g, '\\(').replace(/\\）/g, '\\)').replace(/\n{3,}/g, '\n\n').replace(/([^\n])\n([^\n])/g, '$1\n$2').replace(/\$\s+/g, '$').replace(/\s+\$/g, '$').replace(/\$\$/g, '$$').trim();
  }

  return new Response(JSON.stringify({ success: true, result: result, type: 'text' }), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

// =================================================
// 4. Frontend HTML & JavaScript
// =================================================
function getHTML() {
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="data:image/png;base64,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">
  <title>Qwen 智能识别系统</title>

  <!-- MathJax 支持 -->
  <script src="https://polyfill.io/v3/polyfill.min.js?features=es6"></script>
  <script>
  window.MathJax = {
    tex: { inlineMath: [["$", "$"]], displayMath: [["$$", "$$"]] },
    startup: {
      pageReady: () => {
        return MathJax.startup.defaultPageReady().then(() => {
          if (typeof historyManager !== 'undefined' && typeof currentToken !== 'undefined' && currentToken) {
            historyManager.displayHistory(currentToken);
          }
        });
      }
    },
    options: { enableMenu: false }
  };
  </script>
  <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
  <script>
  function waitForMathJax(callback, maxTries = 30) {
    let tries = 0;
    const checkMathJax = () => {
      tries++;
      if (window.MathJax && window.MathJax.typesetPromise) {
        callback();
      } else if (tries < maxTries) {
        setTimeout(checkMathJax, 100);
      }
    };
    checkMathJax();
  }
  </script>

  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
    .container { background: rgba(255, 255, 255, 0.95); padding: 2.5rem; padding-bottom: 4rem; border-radius: 16px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); width: 90%; max-width: 800px; transition: all 0.3s ease; }
    h1 { color: #2c3e50; margin-bottom: 0.5rem; font-size: 2.2rem; text-align: center; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; background: linear-gradient(135deg, #1a5fb4 0%, #3498db 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1); position: relative; padding-bottom: 10px; animation: titleFadeIn 1s ease-out; }
    @keyframes titleFadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
    h1::after { content: ""; position: absolute; bottom: 0; left: 50%; transform: translateX(-50%); width: 100px; height: 3px; background: linear-gradient(90deg, transparent, #3498db, transparent); }
    .subtitle { color: #7f8c8d; text-align: center; font-size: 1.1rem; margin-bottom: 1.5rem; font-weight: 300; letter-spacing: 1px; opacity: 0.8; animation: subtitleFadeIn 1s ease-out 0.3s both; }
    @keyframes subtitleFadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 0.8; transform: translateY(0); } }
    /* NEW: Styles for model selector */
    .model-selector { display: flex; align-items: center; justify-content: center; margin-bottom: 1.5rem; gap: 15px; }
    .model-label { font-size: 1rem; color: #2c3e50; font-weight: 500; }
    .model-switch { display: flex; border: 1px solid #ccc; border-radius: 8px; overflow: hidden; background: #e9ecef; }
    .model-btn { background: transparent; border: none; padding: 10px 20px; cursor: pointer; transition: all 0.3s ease; font-size: 0.9rem; color: #555; font-weight: 500;}
    .model-btn.active { background: #3498db; color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 7px; }
    .upload-area { border: 2px dashed #8e9eab; border-radius: 12px; padding: 2rem; text-align: center; transition: all 0.3s ease; margin-bottom: 1.5rem; cursor: pointer; position: relative; overflow: hidden; }
    .upload-area:hover { border-color: #3498db; background: rgba(52, 152, 219, 0.05); }
    .upload-area.dragover { border-color: #3498db; background: rgba(52, 152, 219, 0.1); transform: scale(1.02); }
    .upload-area i { font-size: 2rem; color: #8e9eab; margin-bottom: 1rem; }
    .upload-text { color: #7f8c8d; font-size: 0.9rem; }
    .result-container { margin-top: 1.5rem; opacity: 0; transform: translateY(20px); transition: all 0.3s ease; }
    .result-container.show { opacity: 1; transform: translateY(0); }
    .result { background: #f8f9fa; padding: 1.2rem; border-radius: 8px; color: #2c3e50; font-size: 1rem; line-height: 1.6; white-space: pre-wrap; }
    .loading { display: none; text-align: center; margin: 1rem 0; }
    .loading::after { content: ''; display: inline-block; width: 20px; height: 20px; border: 2px solid #3498db; border-radius: 50%; border-top-color: transparent; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .preview-image { max-width: 100%; max-height: 200px; margin: 1rem 0; border-radius: 8px; display: none; }
    .sidebar, .history-sidebar { position: fixed; right: -400px; top: 0; width: 400px; height: 100vh; background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); box-shadow: -5px 0 15px rgba(0, 0, 0, 0.1); transition: right 0.3s ease; padding: 30px; z-index: 1000; }
    .sidebar.open, .history-sidebar.open { right: 0; }
    .history-sidebar { overflow-y: auto; }
    .clear-all-btn { background: #e74c3c; color: white; border: none; padding: 8px 12px; border-radius: 5px; cursor: pointer; transition: background 0.3s; }
    .clear-all-btn:hover { background: #c0392b; }
    .sidebar-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #eee; }
    .sidebar-header h2 { margin: 0; color: #2c3e50; font-size: 1.5rem; }
    .close-sidebar { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #7f8c8d; }
    .cookie-input-container { margin-bottom: 15px; }
    #cookieInput { width: 100%; padding: 12px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 0.95rem; resize: vertical; min-height: 120px; font-family: monospace; line-height: 1.4; }
    #cookieInput:focus { outline: none; border-color: #3498db; }
    .cookie-info { background: #f8f9fa; padding: 12px; border-radius: 8px; margin-bottom: 15px; }
    .cookie-info p { margin: 0 0 8px 0; color: #2c3e50; font-size: 0.9rem; }
    .cookie-info p:last-child { margin-bottom: 0; }
    .token-expiry { font-size: 0.85rem; }
    .token-expiry.expired { color: #e74c3c; font-weight: bold; }
    #currentTokenDisplay { color: #3498db; font-family: monospace; word-break: break-all; }
    .save-btn { background: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 8px; cursor: pointer; width: 100%; font-size: 1rem; transition: background 0.3s ease; }
    .save-btn:hover { background: #2980b9; }
    .advanced-mode-toggle { display: flex; align-items: center; margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 8px; }
    #advancedMode { margin-right: 10px; }
    .prompt-container { display: none; margin-top: 15px; }
    .prompt-container.show { display: block; }
    #promptInput { width: 100%; padding: 12px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 0.95rem; resize: vertical; min-height: 120px; font-family: monospace; line-height: 1.4; }
    #promptInput:focus { outline: none; border-color: #3498db; }
    .input-controls { margin-top: 15px; width: 100%; }
    .button-group { display: flex; gap: 10px; margin-top: 10px; justify-content: center; }
    .toggle-btn { background: #7f8c8d; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; transition: background 0.3s ease; }
    .toggle-btn:hover { background: #5d6d7e; }
    .toggle-btn.active { background: #3498db; }
    #base64Input, #urlInput { display: none; width: 100%; padding: 10px; margin-top: 10px; border: 1px solid #dcdde1; border-radius: 8px; resize: vertical; }
    #base64Input { height: 100px; }
    .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
    .copy-btn { background: #3498db; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 0.9rem; transition: background 0.3s ease; }
    .copy-btn:hover { background: #2980b9; }
    .copy-btn.copied { background: #27ae60; }
    .history-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .history-item { background: #ffffff; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08); overflow: hidden; transition: transform 0.2s ease, box-shadow 0.2s ease; display: flex; flex-direction: column; }
    .history-item:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12); }
    .history-image-container { position: relative; width: 100%; height: 200px; overflow: hidden; cursor: pointer; }
    .history-image { width: 100%; height: 100%; object-fit: cover; transition: transform 0.3s ease; }
    .history-item:hover .history-image { transform: scale(1.05); }
    .history-content { padding: 16px; }
    .history-content-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #eee; }
    .history-time { color: #7f8c8d; font-size: 0.9rem; }
    .history-actions { display: flex; gap: 8px; }
    .action-btn { background: none; border: 1px solid #e0e0e0; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; transition: all 0.2s ease; }
    .action-btn:hover { background: #f8f9fa; transform: translateY(-1px); }
    .action-btn.copy-btn { color: #3498db; }
    .action-btn.delete-btn { color: #e74c3c; }
    .history-text { color: #2c3e50; font-size: 0.95rem; line-height: 1.6; max-height: 200px; overflow-y: auto; padding-right: 8px; }
    .no-history { text-align: center; color: #7f8c8d; padding: 2rem; }
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.9); z-index: 2000; cursor: pointer; }
    .modal-content { max-width: 90%; max-height: 90vh; margin: auto; display: block; position: relative; top: 50%; transform: translateY(-50%); }
    .bottom-right-controls { position: fixed; bottom: 20px; right: 20px; z-index: 1001; display: flex; flex-direction: column-reverse; align-items: flex-end; gap: 15px; }
    .actions-panel { display: flex; flex-direction: column; gap: 10px; width: 120px; }
    .action-button { width: 100%; background-color: #3498db; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; text-decoration: none; font-size: 14px; text-align: center; transition: background 0.3s; white-space: nowrap; display: inline-block; }
    .action-button:hover { background-color: #2980b9; }
    .action-button.green { background-color: #2ecc71; }
    .action-button.green:hover { background-color: #27ae60; }
    .action-button.orange { background-color: #f39c12; }
    .action-button.orange:hover { background-color: #e67e22; }
    .github-link { background: #333; color: white; border: none; padding: 10px; border-radius: 50%; cursor: pointer; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; transition: background 0.3s ease; }
    .github-link:hover { background: #24292e; }
    .github-icon { width: 24px; height: 24px; }
  </style>
</head>
<body>
  <div class="bottom-right-controls">
    <a href="https://github.com/Cunninger/ocr-based-qwen" target="_blank" rel="noopener noreferrer" class="github-link" title="View on GitHub">
      <svg class="github-icon" viewBox="0 0 16 16" fill="currentColor"><path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg>
    </a>
    <div class="actions-panel">
      <button class="action-button" id="sidebarToggle">⚙️ Cookie设置</button>
      <button class="action-button" id="historyToggle">📋 识别历史</button>
      <a href="https://chat.qwenlm.ai/" target="_blank" rel="noopener noreferrer" class="action-button green">获取Cookie</a>
      <a href="/api-docs" target="_blank" class="action-button orange">API文档</a>
    </div>
  </div>

  <div class="sidebar" id="sidebar">
    <div class="sidebar-header">
      <h2>Cookie管理</h2>
      <button class="close-sidebar" id="closeSidebar">×</button>
    </div>
    <div class="cookie-input-container">
      <label for="cookieInput">输入Cookie (将安全存储在云端)</label>
      <textarea id="cookieInput" placeholder="在此输入从 chat.qwenlm.ai 获取的完整Cookie字符串..." rows="8"></textarea>
    </div>
    <div class="cookie-info">
      <p>当前Token: <span id="currentTokenDisplay">未设置</span></p>
      <p>过期时间: <span id="tokenExpiryDisplay" class="token-expiry">未知</span></p>
    </div>
    <button class="save-btn" id="saveBtn">保存设置到云端</button>
    <div class="advanced-mode-toggle">
      <input type="checkbox" id="advancedMode">
      <label for="advancedMode">高级模式 (自定义Prompt)</label>
    </div>
    <div class="prompt-container" id="promptContainer">
      <label for="promptInput">自定义Prompt</label>
      <textarea id="promptInput" placeholder="输入自定义prompt..."></textarea>
    </div>
  </div>

  <div class="container">
    <h1>Qwen 智能识别系统</h1>
    <p class="subtitle">基于通义千问/Gemini大模型的多模态智能识别引擎</p>
    
    <!-- NEW: Model Selector -->
    <div class="model-selector">
      <label class="model-label">选择模型:</label>
      <div class="model-switch">
        <button id="modelQwen" class="model-btn active">通义千问</button>
        <button id="modelGemini" class="model-btn">Gemini</button>
      </div>
    </div>

    <div class="upload-area" id="uploadArea">
      <i>📸</i>
      <div class="upload-text">
        拖拽图片到此，或点击/粘贴图片<br>也支持下方通过URL或Base64输入
      </div>
      <img id="previewImage" class="preview-image">
      <div class="input-controls">
        <div class="button-group">
          <button id="toggleFile" class="toggle-btn active">文件/粘贴</button>
          <button id="toggleUrl" class="toggle-btn">URL输入</button>
          <button id="toggleBase64" class="toggle-btn">Base64输入</button>
        </div>
        <textarea id="urlInput" placeholder="在此输入图片URL，然后按回车或等待识别..."></textarea>
        <textarea id="base64Input" placeholder="在此粘贴Base64格式的图片内容，然后等待识别..."></textarea>
      </div>
    </div>
    <div class="loading" id="loading"></div>
    <div class="result-container" id="resultContainer">
      <div class="result-header">
        <span>识别结果</span>
        <button class="copy-btn" id="copyBtn">复制结果</button>
      </div>
      <div class="result" id="result"></div>
    </div>
  </div>
  
  <div class="history-sidebar" id="historySidebar">
    <div class="history-header">
      <h2>识别历史</h2>
      <button class="clear-all-btn" id="clearAllHistory">清空全部</button>
    </div>
    <div id="historyList"></div>
  </div>

  <div id="imageModal" class="modal">
    <img class="modal-content" id="modalImage">
  </div>

<script>
    // --- 定义类和全局变量 ---
    const elements = {
        uploadArea: document.getElementById('uploadArea'),
        resultDiv: document.getElementById('result'),
        resultContainer: document.getElementById('resultContainer'),
        loading: document.getElementById('loading'),
        previewImage: document.getElementById('previewImage'),
        sidebar: document.getElementById('sidebar'),
        sidebarToggle: document.getElementById('sidebarToggle'),
        closeSidebar: document.getElementById('closeSidebar'),
        saveBtn: document.getElementById('saveBtn'),
        cookieInput: document.getElementById('cookieInput'),
        currentTokenDisplay: document.getElementById('currentTokenDisplay'),
        tokenExpiryDisplay: document.getElementById('tokenExpiryDisplay'),
        copyBtn: document.getElementById('copyBtn'),
        historySidebar: document.getElementById('historySidebar'),
        historyToggle: document.getElementById('historyToggle'),
        historyList: document.getElementById('historyList'),
        clearAllHistoryBtn: document.getElementById('clearAllHistory'),
        imageModal: document.getElementById('imageModal'),
        modalImage: document.getElementById('modalImage'),
        toggleFile: document.getElementById('toggleFile'),
        toggleUrl: document.getElementById('toggleUrl'),
        toggleBase64: document.getElementById('toggleBase64'),
        urlInput: document.getElementById('urlInput'),
        base64Input: document.getElementById('base64Input'),
        advancedMode: document.getElementById('advancedMode'),
        promptContainer: document.getElementById('promptContainer'),
        promptInput: document.getElementById('promptInput'),
        // NEW: Model selector buttons
        modelQwen: document.getElementById('modelQwen'),
        modelGemini: document.getElementById('modelGemini'),
    };
    let currentToken = '';
    let selectedModel = 'qwen'; // NEW: 'qwen' or 'gemini'
    
    class HistoryManager {
        constructor(maxHistory = 20) {
            this.maxHistory = maxHistory;
            this.syncInProgress = false;
        }

        getHistoryKey(token) { return 'imageRecognition_history_' + token; }
        getCloudHistoryKey(token) { return 'history_' + token.slice(-10); } // 使用token后10位作为云端存储key

        // 从本地存储加载历史记录
        loadLocalHistory(token) {
            const h = localStorage.getItem(this.getHistoryKey(token));
            return h ? JSON.parse(h) : [];
        }

        // 从云端加载历史记录
        async loadCloudHistory(token) {
            try {
                const response = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action: 'get_history',
                        key: this.getCloudHistoryKey(token)
                    })
                });
                if (response.ok) {
                    const data = await response.json();
                    return data.history || [];
                }
            } catch (error) {
                console.log('加载云端历史失败，使用本地数据:', error.message);
            }
            return [];
        }

        // 保存历史记录到云端
        async saveCloudHistory(token, history) {
            try {
                await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action: 'save_history',
                        key: this.getCloudHistoryKey(token),
                        history: history
                    })
                });
            } catch (error) {
                console.log('保存云端历史失败:', error.message);
            }
        }

        // 合并本地和云端历史记录
        mergeHistories(localHistory, cloudHistory) {
            const merged = [...localHistory];

            // 将云端历史记录添加到本地，去重
            cloudHistory.forEach(cloudItem => {
                const exists = merged.some(localItem =>
                    localItem.timestamp === cloudItem.timestamp &&
                    localItem.result === cloudItem.result
                );
                if (!exists) {
                    merged.push(cloudItem);
                }
            });

            // 按时间戳排序（最新的在前）
            merged.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

            // 限制数量
            return merged.slice(0, this.maxHistory);
        }

        // 加载历史记录（合并本地和云端）
        async loadHistory(token) {
            if (!token) return [];

            const localHistory = this.loadLocalHistory(token);
            const cloudHistory = await this.loadCloudHistory(token);

            return this.mergeHistories(localHistory, cloudHistory);
        }

        // 保存历史记录（同时保存到本地和云端）
        async saveHistory(token, history) {
            if (!token) return;

            // 保存到本地
            localStorage.setItem(this.getHistoryKey(token), JSON.stringify(history));

            // 异步保存到云端
            if (!this.syncInProgress) {
                this.syncInProgress = true;
                try {
                    await this.saveCloudHistory(token, history);
                } finally {
                    this.syncInProgress = false;
                }
            }
        }

        // 添加新的历史记录
        async addHistory(token, imageData, result) {
            if (!token) return;

            const history = await this.loadHistory(token);
            history.unshift({ image: imageData, result, timestamp: new Date().toISOString() });

            if (history.length > this.maxHistory) {
                history.splice(this.maxHistory);
            }

            await this.saveHistory(token, history);
            await this.displayHistory(token);
        }
        async displayHistory(token) {
            if (!token) {
                elements.historyList.innerHTML = '<div class="no-history">请先在设置中保存Cookie以启用历史记录</div>';
                return;
            }

            // 显示加载状态
            elements.historyList.innerHTML = '<div class="no-history">正在同步历史记录...</div>';

            try {
                const history = await this.loadHistory(token);
                if (history.length === 0) {
                    elements.historyList.innerHTML = '<div class="no-history">暂无识别历史</div>';
                    return;
                }

                elements.historyList.innerHTML = history.map((record, i) => {
                    const imageUrl = record.image && (record.image.startsWith('data:') ? record.image : \`data:image/png;base64,\${record.image}\`);
                    const timeStr = new Date(record.timestamp).toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
                    return \`
                    <div class="history-item" data-index="\${i}">
                        <div class="history-image-container" onclick="showFullImage('\${imageUrl}')">
                            <img src="\${imageUrl}" class="history-image" alt="历史图片" onerror="this.style.display='none'">
                        </div>
                        <div class="history-content">
                            <div class="history-content-header">
                                <span class="history-time">\${timeStr}</span>
                                <div class="history-actions">
                                    <button class="action-btn copy-btn" onclick="event.stopPropagation(); copyHistoryResult(\${i}, this)">复制</button>
                                    <button class="action-btn delete-btn" onclick="event.stopPropagation(); deleteHistoryItem(\${i})">删除</button>
                                </div>
                            </div>
                            <div class="history-text" data-original-text="\${record.result || ''}">\${record.result || '无识别结果'}</div>
                        </div>
                    </div>\`;
                }).join('');

                waitForMathJax(() => MathJax.typesetPromise([elements.historyList]).catch(console.error));
            } catch (error) {
                console.error('显示历史记录失败:', error);
                elements.historyList.innerHTML = '<div class="no-history">加载历史记录失败，请刷新页面重试</div>';
            }
        }
    }
    const historyManager = new HistoryManager();

    // --- 辅助函数 ---
    const debounce = (func, wait) => {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    };
    const parseJwt = (token) => {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            return JSON.parse(decodeURIComponent(atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')));
        } catch (e) { return null; }
    };

    // --- 核心功能函数 ---
    async function updateTokenUI(cookie) {
        elements.cookieInput.value = cookie;
        const tokenMatch = cookie.match(/token=([^;]+)/);
        if (tokenMatch) {
            currentToken = tokenMatch[1];
            elements.currentTokenDisplay.textContent = currentToken.slice(0, 10) + "..." + currentToken.slice(-10);
            const decoded = parseJwt(currentToken);
            if (decoded && decoded.exp) {
                const expiryDate = new Date(decoded.exp * 1000);
                const isExpired = expiryDate < new Date();
                elements.tokenExpiryDisplay.textContent = expiryDate.toLocaleString('zh-CN');
                elements.tokenExpiryDisplay.classList.toggle('expired', isExpired);
                if(isExpired) elements.tokenExpiryDisplay.textContent += ' (已过期)';
            } else {
                elements.tokenExpiryDisplay.textContent = '无法解析';
            }
        } else {
            currentToken = '';
            elements.currentTokenDisplay.textContent = "未设置";
            elements.tokenExpiryDisplay.textContent = "未知";
        }
        await historyManager.displayHistory(currentToken);
    }
    async function loadConfig() {
        try {
            const response = await fetch('/api/settings');
            if (!response.ok) throw new Error("Failed to fetch settings");
            const data = await response.json();
            await updateTokenUI(data.cookie || '');
            const savedPrompt = localStorage.getItem('customPrompt');
            if (savedPrompt) elements.promptInput.value = savedPrompt;
            const savedMode = localStorage.getItem('advancedMode') === 'true';
            elements.advancedMode.checked = savedMode;
            elements.promptContainer.style.display = savedMode ? 'block' : 'none';
        } catch (error) { console.error("Error loading settings:", error); }
    }
    async function saveConfig() {
        const cookieValue = elements.cookieInput.value.trim();
        if (!cookieValue) { alert('请输入Cookie'); return; }
        try {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cookie: cookieValue })
            });
            alert('设置已成功保存到云端！');
            await updateTokenUI(cookieValue);
            elements.sidebar.classList.remove("open");
        } catch (error) { alert("保存失败: " + error.message); }
    }
    
    // MODIFIED: Main image processing router
    async function processImage(data, type) {
        // Using Gemini requires a login (for history), but doesn't use the cookie itself.
        // Qwen requires the cookie for API calls.
        if (!currentToken) {
            alert('请先在“Cookie设置”中保存一个有效的Cookie以启用历史记录等功能。');
            elements.sidebar.classList.add('open');
            return;
        }

        elements.loading.style.display = 'block';
        elements.resultContainer.classList.remove('show');
        elements.previewImage.style.display = 'none';

        try {
            if (selectedModel === 'gemini') {
                await processWithGemini(data, type);
            } else {
                await processWithQwen(data, type);
            }
        } catch (error) {
            elements.resultDiv.textContent = '处理失败: ' + error.message;
            elements.resultContainer.classList.add('show');
        } finally {
            elements.loading.style.display = 'none';
        }
    }

    // NEW: Logic for processing with Gemini
    async function processWithGemini(data, type) {
        let endpoint = '/api/recognize/base64';
        let body = {};
        let historyImage = '';

        if (type === "file") {
            const base64Image = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = e => resolve(e.target.result);
                reader.onerror = e => reject(new Error('Failed to read file as Base64'));
                reader.readAsDataURL(data);
            });
            body = { base64Image: base64Image.split(',')[1] };
            historyImage = base64Image;
        } else if (type === "url") {
            endpoint = '/api/recognize/url';
            body = { imageUrl: data };
            historyImage = data; 
        } else if (type === "base64") {
            body = { base64Image: data };
            historyImage = data.startsWith("data:") ? data : \`data:image/png;base64,\${data}\`;
        } else {
            throw new Error("Unsupported data type for Gemini");
        }
        
        if (type !== "url") {
            elements.previewImage.src = historyImage;
            elements.previewImage.style.display = 'block';
        }

        const res = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-recognition-model': '1', // Specify Gemini model
                'x-advanced-mode': elements.advancedMode.checked,
                'x-custom-prompt': btoa(encodeURIComponent(elements.promptInput.value))
            },
            body: JSON.stringify(body)
        });

        // MODIFIED: Robust error handling
        if (!res.ok) {
            const errorText = await res.text();
            try {
                const errorJson = JSON.parse(errorText);
                throw new Error(errorJson.error || errorText);
            } catch (jsonError) {
                throw new Error(errorText || \`Request failed with status \${res.status}\`);
            }
        }
        
        const resData = await res.json();
        if (!resData.success) throw new Error(resData.error || '识别失败');

        const result = resData.result || '识别失败';
        elements.resultDiv.setAttribute('data-original-text', result);
        elements.resultDiv.innerHTML = result;
        waitForMathJax(() => MathJax.typesetPromise([elements.resultDiv]).catch(console.error));
        await historyManager.addHistory(currentToken, historyImage, result);
        elements.resultContainer.classList.add('show');
    }

    // NEW: Logic for processing with Qwen (refactored from original function)
    async function processWithQwen(data, type) {
        let endpoint = '', body = {}, historyImage = '';

        if (type === "file") {
            historyImage = await new Promise(resolve => { const r = new FileReader(); r.onload = e => resolve(e.target.result); r.readAsDataURL(data); });
            elements.previewImage.src = historyImage;
            const formData = new FormData();
            formData.append('file', data);
            const uploadRes = await fetch('/proxy/upload', { method: 'POST', body: formData });
            if (!uploadRes.ok) throw new Error('File upload proxy failed.');
            const uploadData = await uploadRes.json();
            if (!uploadData.id) throw new Error('文件上传失败: ' + (uploadData.error || JSON.stringify(uploadData)));
            endpoint = '/recognize';
            body = { imageId: uploadData.id };
        } else if (type === "base64") {
            endpoint = '/api/recognize/base64';
            body = { base64Image: data };
            historyImage = data.startsWith("data:") ? data : \`data:image/png;base64,\${data}\`;
            elements.previewImage.src = historyImage;
        } else if (type === "url") {
            endpoint = '/api/recognize/url';
            body = { imageUrl: data };
            historyImage = data;
            elements.previewImage.src = historyImage;
        }
        elements.previewImage.style.display = 'block';

        const res = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-recognition-model': '0', // Specify Qwen model
                'x-advanced-mode': elements.advancedMode.checked,
                'x-custom-prompt': btoa(encodeURIComponent(elements.promptInput.value))
            },
            body: JSON.stringify(body)
        });
        
        // MODIFIED: Robust error handling
        if (!res.ok) {
            const errorText = await res.text();
            try {
                const errorJson = JSON.parse(errorText);
                throw new Error(errorJson.error || errorText);
            } catch (jsonError) {
                throw new Error(errorText || \`Request failed with status \${res.status}\`);
            }
        }

        const resData = await res.json();
        if (!resData.success) throw new Error(resData.error || '识别失败');

        const result = resData.result || '识别失败';
        elements.resultDiv.setAttribute('data-original-text', result);
        elements.resultDiv.innerHTML = result;
        waitForMathJax(() => MathJax.typesetPromise([elements.resultDiv]).catch(console.error));
        await historyManager.addHistory(currentToken, historyImage, result);
        elements.resultContainer.classList.add('show');
    }
    
    // --- UI交互函数 ---
    function switchInputMode(mode) {
        ['File', 'Url', 'Base64'].forEach(m => {
            const btn = elements[\`toggle\${m}\`];
            const input = elements[\`\${m.toLowerCase()}Input\`];
            const isActive = m.toLowerCase() === mode;
            btn.classList.toggle('active', isActive);
            if(input) input.style.display = isActive ? 'block' : 'none';
        });
        if (mode === 'file') {
             elements.uploadArea.style.cursor = 'pointer';
        } else {
            elements.urlInput.style.display = mode === 'url' ? 'block' : 'none';
            elements.base64Input.style.display = mode === 'base64' ? 'block' : 'none';
            elements.uploadArea.style.cursor = 'default';
        }
    }
    function showFullImage(src) {
        if (!src) return;
        elements.modalImage.src = src;
        elements.imageModal.style.display = 'block';
    }
    function copyToClipboard(text, btnElement) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.textContent;
            btnElement.textContent = '已复制!';
            btnElement.classList.add('copied');
            setTimeout(() => {
                btnElement.textContent = originalText;
                btnElement.classList.remove('copied');
            }, 2000);
        }).catch(err => alert('复制失败: ' + err));
    }
    window.copyHistoryResult = async (index, btn) => {
        const history = await historyManager.loadHistory(currentToken);
        copyToClipboard(history[index]?.result || '', btn);
    };
    window.deleteHistoryItem = async (index) => {
        if (!confirm('确定要删除这条历史记录吗？')) return;
        const history = await historyManager.loadHistory(currentToken);
        history.splice(index, 1);
        await historyManager.saveHistory(currentToken, history);
        await historyManager.displayHistory(currentToken);
    };
    
    // --- 事件监听器 ---
    elements.sidebarToggle.addEventListener('click', () => elements.sidebar.classList.toggle('open'));
    elements.closeSidebar.addEventListener('click', () => elements.sidebar.classList.remove('open'));
    elements.historyToggle.addEventListener('click', () => elements.historySidebar.classList.toggle('open'));
    elements.saveBtn.addEventListener('click', saveConfig);
    elements.advancedMode.addEventListener('change', () => {
        const isChecked = elements.advancedMode.checked;
        elements.promptContainer.style.display = isChecked ? 'block' : 'none';
        localStorage.setItem('advancedMode', isChecked);
    });
    elements.promptInput.addEventListener('input', debounce(() => localStorage.setItem('customPrompt', elements.promptInput.value), 500));
    elements.copyBtn.addEventListener('click', () => copyToClipboard(elements.resultDiv.getAttribute('data-original-text'), elements.copyBtn));
    
    // 输入模式切换
    elements.toggleFile.addEventListener('click', () => switchInputMode('file'));
    elements.toggleUrl.addEventListener('click', () => switchInputMode('url'));
    elements.toggleBase64.addEventListener('click', () => switchInputMode('base64'));

    // NEW: Model switch listeners
    elements.modelQwen.addEventListener('click', () => {
        selectedModel = 'qwen';
        elements.modelQwen.classList.add('active');
        elements.modelGemini.classList.remove('active');
    });
    elements.modelGemini.addEventListener('click', () => {
        selectedModel = 'gemini';
        elements.modelGemini.classList.add('active');
        elements.modelQwen.classList.remove('active');
    });

    // 拖放、粘贴、点击上传
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(event => {
        elements.uploadArea.addEventListener(event, e => {
            e.preventDefault();
            e.stopPropagation();
        });
    });
    elements.uploadArea.addEventListener('dragenter', () => elements.uploadArea.classList.add('dragover'));
    elements.uploadArea.addEventListener('dragleave', () => elements.uploadArea.classList.remove('dragover'));
    elements.uploadArea.addEventListener('drop', e => {
        elements.uploadArea.classList.remove('dragover');
        if (elements.toggleFile.classList.contains('active')) {
            const file = e.dataTransfer.files[0];
            if (file) processImage(file, "file");
        }
    });

    document.addEventListener('paste', e => {
        if (elements.toggleFile.classList.contains('active')) {
            const file = e.clipboardData.files[0];
            if (file && file.type.startsWith('image/')) processImage(file, "file");
        }
    });
    elements.uploadArea.addEventListener('click', (e) => {
        if (elements.toggleFile.classList.contains('active') && e.target.tagName !== 'BUTTON' && e.target.tagName !== 'TEXTAREA') {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*';
            input.onchange = e => processImage(e.target.files[0], "file");
            input.click();
        }
    });

    // URL和Base64输入处理
    elements.urlInput.addEventListener('input', debounce(e => {
        const value = e.target.value.trim();
        if (value) processImage(value, "url");
    }, 1000));
    elements.base64Input.addEventListener('input', debounce(e => {
        const value = e.target.value.trim();
        if(value) processImage(value, "base64");
    }, 1500));
    
    elements.clearAllHistoryBtn.addEventListener('click', async () => {
        if (!confirm('确定要清空所有历史记录吗？此操作将同时清空本地和云端的历史记录，不可恢复。')) return;
        await historyManager.saveHistory(currentToken, []);
        await historyManager.displayHistory(currentToken);
    });
    
    // 图片模态框
    elements.imageModal.addEventListener('click', () => elements.imageModal.style.display = "none");
    
    // 初始化
    document.addEventListener('DOMContentLoaded', () => {
        loadConfig();
        switchInputMode('file');
        elements.promptInput.value = '请识别图片中的内容，注意以下要求：\\n对于数学公式和普通文本：\\n1. 所有数学公式和数学符号都必须使用标准的LaTeX格式\\n2. 行内公式使用单个$符号包裹，如：$x^2$\\n3. 独立公式块使用两个$$符号包裹，如：$$\\sum_{i=1}^n i^2$$\\n4. 普通文本保持原样，不要使用LaTeX格式\\n5. 保持原文的段落格式和换行\\n\\n对于验证码图片：\\n1. 只输出验证码字符，不要加任何额外解释\\n\\n不要输出任何额外的解释或说明';
    });
</script>
</body>
</html>`;
  return html;
}

// =================================================
// 5. API Documentation Page
// =================================================
function getApiDocsHTML() {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API 文档 - Qwen 智能识别系统</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f8f9fa; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: 20px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); padding: 40px; }
        h1, h2, h3 { color: #2c3e50; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; margin-top: 40px; }
        h1 { font-size: 2.5em; text-align: center; border-bottom: none; }
        h2 { font-size: 2em; }
        h3 { font-size: 1.5em; border-bottom: 1px solid #e9ecef;}
        code { background-color: #e9ecef; padding: 0.2em 0.4em; margin: 0; font-size: 85%; border-radius: 3px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; }
        pre { background-color: #2d2d2d; color: #f8f8f2; padding: 20px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        pre code { background-color: transparent; color: inherit; padding: 0; }
        .endpoint { background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 20px; margin-bottom: 30px; }
        .method { font-weight: bold; padding: 5px 10px; border-radius: 3px; color: #fff; display: inline-block; margin-right: 15px; font-size: 0.9em;}
        .post { background-color: #28a745; }
        .get { background-color: #007bff; }
        .endpoint-path { font-size: 1.2em; font-family: monospace; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; }
        .alert-info { color: #31708f; background-color: #d9edf7; border-color: #bce8f1; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>API 文档</h1>
        <p style="text-align: center;">Qwen 智能识别系统 API 使用说明</p>

        <h2>认证</h2>
        <p>所有API请求都需要通过 <code>Authorization</code> 请求头进行认证。您需要在Cloudflare Worker的设置中配置一个名为 <code>API_KEY</code> 的环境变量作为您的API密钥。</p>
        <div class="alert alert-info">
            <strong>注意：</strong> 认证密钥必须以 <code>Bearer </code> 为前缀。此外，使用Gemini模型需要在Cloudflare Worker中额外配置 <code>GEMINI_API_KEY</code> 环境变量。
        </div>
        <h3>请求头示例</h3>
        <pre><code>Authorization: Bearer YOUR_API_KEY</code></pre>
        <p>请将 <code>YOUR_API_KEY</code> 替换为您在环境变量中设置的实际密钥。</p>

        <h2>API 端点</h2>
        
        <div class="endpoint">
            <h3>通过图片URL识别</h3>
            <p><span class="method post">POST</span><span class="endpoint-path">/api/recognize/url</span></p>
            <p>提供一个公开可访问的图片URL，服务将下载图片并进行识别。</p>
            <h4>请求体 (JSON)</h4>
            <pre><code>{
    "imageUrl": "https://example.com/path/to/your/image.png"
}</code></pre>
            <h4>cURL 示例</h4>
            <pre><code>curl --location --request POST 'https://YOUR_WORKER_URL/api/recognize/url' \\
--header 'Content-Type: application/json' \\
--header 'Authorization: Bearer YOUR_API_KEY' \\
--header 'x-recognition-model: 0' \\
--data-raw '{
    "imageUrl": "https://i.stack.imgur.com/i23ns.png"
}'</code></pre>
        </div>
        
        <div class="endpoint">
            <h3>通过 Base64 字符串识别</h3>
            <p><span class="method post">POST</span><span class="endpoint-path">/api/recognize/base64</span></p>
            <p>提供图片的Base64编码字符串进行识别。Base64字符串可以包含或不包含Data URI前缀 (例如 <code>data:image/png;base64,</code>)。</p>
            <h4>请求体 (JSON)</h4>
            <pre><code>{
    "base64Image": "iVBORw0KGgoAAAANSUhEUgAAAA...SUVORK5CYII=" 
}</code></pre>
            <h4>cURL 示例</h4>
            <pre><code>curl --location --request POST 'https://YOUR_WORKER_URL/api/recognize/base64' \\
--header 'Content-Type: application/json' \\
--header 'Authorization: Bearer YOUR_API_KEY' \\
--header 'x-recognition-model: 1' \\
--data-raw '{
    "base64Image": "PASTE_YOUR_BASE64_STRING_HERE"
}'</code></pre>
        </div>

        <div class="endpoint">
            <h3>对话、图片生成与编辑接口（OpenAI 兼容）</h3>
            <p><span class="method post">POST</span><span class="endpoint-path">/v1/chat/completions</span></p>
            <p>兼容 OpenAI API 格式的对话接口，支持文本对话、多模态对话、图片生成、图片编辑和视频生成。</p>

            <h4>功能说明</h4>
            <ul>
                <li><strong>文本对话</strong>：使用标准模型名称（如 <code>qwen-max-latest</code>）</li>
                <li><strong>多模态对话</strong>：在消息中包含图片（支持 URL 或 base64）</li>
                <li><strong>图片生成</strong>：在模型名称后添加 <code>-image</code> 后缀</li>
                <li><strong>图片编辑</strong>：在模型名称后添加 <code>-image-edit</code> 后缀</li>
                <li><strong>视频生成</strong>：在模型名称后添加 <code>-video</code> 后缀</li>
                <li><strong>搜索模式</strong>：在模型名称后添加 <code>-search</code> 后缀</li>
            </ul>

            <h4>请求体 (JSON) - 文本对话</h4>
            <pre><code>{
    "model": "qwen-max-latest",
    "messages": [
        {
            "role": "user",
            "content": "你好，请介绍一下你自己"
        }
    ],
    "stream": false
}</code></pre>

            <h4>请求体 (JSON) - 多模态对话（图片理解）</h4>
            <pre><code>{
    "model": "qwen-max-latest",
    "messages": [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "这张图片里有什么？"
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": "data:image/png;base64,iVBORw0KGgo..."
                    }
                }
            ]
        }
    ],
    "stream": false
}</code></pre>

            <h4>请求体 (JSON) - 图片生成</h4>
            <pre><code>{
    "model": "qwen-max-latest-image",
    "messages": [
        {
            "role": "user",
            "content": "画一只可爱的小猫"
        }
    ],
    "stream": false
}</code></pre>

            <h4>cURL 示例 - 文本对话</h4>
            <pre><code>curl --location --request POST 'https://YOUR_WORKER_URL/v1/chat/completions' \\
--header 'Content-Type: application/json' \\
--header 'Authorization: Bearer YOUR_API_KEY' \\
--data-raw '{
    "model": "qwen-max-latest",
    "messages": [
        {
            "role": "user",
            "content": "你好"
        }
    ],
    "stream": false
}'</code></pre>

            <h4>cURL 示例 - 图片生成</h4>
            <pre><code>curl --location --request POST 'https://YOUR_WORKER_URL/v1/chat/completions' \\
--header 'Content-Type: application/json' \\
--header 'Authorization: Bearer YOUR_API_KEY' \\
--data-raw '{
    "model": "qwen-max-latest-image",
    "messages": [
        {
            "role": "user",
            "content": "画一只可爱的小猫"
        }
    ],
    "stream": false
}'</code></pre>

            <h4>响应格式</h4>

            <h5>文本对话响应</h5>
            <pre><code>{
    "success": true,
    "request_id": "89ccd9b4-5912-4038-abda-e6e2c6348bde",
    "data": {
        "chat_id": "7d2881fb-ec01-4630-8905-ea784020864f",
        "parent_id": "075d22cb-7040-48fb-8b28-ea6e2a0650a3",
        "message_id": "42b2b859-e352-4f84-9ce2-ffa7bc74ceee",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "你好！我是通义千问，一个由阿里云开发的大型语言模型..."
            }
        }]
    }
}</code></pre>

            <h5>图片生成响应</h5>
            <pre><code>{
    "data": {
        "chat_id": "51a33d5e-036e-44f5-9be6-9f34a0920236",
        "parent_id": "3cc20566-2479-4cf7-9311-4749f366a439",
        "message_id": "1759334048",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "https://cdn.qwenlm.ai/output/fafbb2e9-aca9-4caa-bd2a-6c51e69ee858/t2i/3cc20566-2479-4cf7-9311-4749f366a439/1759334048.png?key=eyJhbGc..."
            }
        }]
    }
}</code></pre>
            <p><strong>说明</strong>：图片生成时，<code>content</code> 字段包含生成的图片 URL，可以直接访问下载。</p>

            <h5>多模态对话响应（图片理解）</h5>
            <pre><code>{
    "success": true,
    "request_id": "xxx-xxx-xxx",
    "data": {
        "chat_id": "xxx",
        "parent_id": "xxx",
        "message_id": "xxx",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "这张图片中有一只可爱的小猫，它正在..."
            }
        }]
    }
}</code></pre>

            <h5>响应字段说明</h5>
            <table>
                <thead>
                    <tr>
                        <th>字段</th>
                        <th>类型</th>
                        <th>说明</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>success</code></td>
                        <td>boolean</td>
                        <td>请求是否成功（可选字段）</td>
                    </tr>
                    <tr>
                        <td><code>request_id</code></td>
                        <td>string</td>
                        <td>请求唯一标识符（可选字段）</td>
                    </tr>
                    <tr>
                        <td><code>data.chat_id</code></td>
                        <td>string</td>
                        <td>对话会话 ID</td>
                    </tr>
                    <tr>
                        <td><code>data.parent_id</code></td>
                        <td>string</td>
                        <td>父消息 ID</td>
                    </tr>
                    <tr>
                        <td><code>data.message_id</code></td>
                        <td>string</td>
                        <td>当前消息 ID</td>
                    </tr>
                    <tr>
                        <td><code>data.choices</code></td>
                        <td>array</td>
                        <td>响应选项数组（通常只有一个）</td>
                    </tr>
                    <tr>
                        <td><code>data.choices[0].message.role</code></td>
                        <td>string</td>
                        <td>消息角色，固定为 "assistant"</td>
                    </tr>
                    <tr>
                        <td><code>data.choices[0].message.content</code></td>
                        <td>string</td>
                        <td>响应内容（文本对话为文本，图片生成为图片 URL）</td>
                    </tr>
                </tbody>
            </table>

            <h4>支持的模型后缀</h4>
            <table>
                <thead>
                    <tr>
                        <th>后缀</th>
                        <th>功能</th>
                        <th>示例</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>无后缀</td>
                        <td>标准文本对话</td>
                        <td><code>qwen-max-latest</code></td>
                    </tr>
                    <tr>
                        <td><code>-image</code></td>
                        <td>文本生成图片</td>
                        <td><code>qwen-max-latest-image</code></td>
                    </tr>
                    <tr>
                        <td><code>-image-edit</code></td>
                        <td>图片编辑</td>
                        <td><code>qwen-max-latest-image-edit</code></td>
                    </tr>
                    <tr>
                        <td><code>-video</code></td>
                        <td>文本生成视频</td>
                        <td><code>qwen-max-latest-video</code></td>
                    </tr>
                    <tr>
                        <td><code>-search</code></td>
                        <td>搜索增强模式</td>
                        <td><code>qwen-max-latest-search</code></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <h2>通用参数</h2>
        <h3>可选请求头（图片识别接口）</h3>
        <p>以下请求头仅适用于 <code>/api/recognize/url</code> 和 <code>/api/recognize/base64</code> 接口。</p>
        <table>
            <thead>
                <tr>
                    <th>Header</th>
                    <th>描述</th>
                    <th>值</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><code>x-recognition-model</code></td>
                    <td>选择用于识别的AI模型。</td>
                    <td><code>0</code>: 通义千问 (默认)<br><code>1</code>: Gemini 2.5 flash</td>
                </tr>
                <tr>
                    <td><code>x-advanced-mode</code></td>
                    <td>是否启用高级模式。如果为 <code>true</code>，将使用下面的自定义Prompt，否则使用默认Prompt。</td>
                    <td><code>true</code> 或 <code>false</code></td>
                </tr>
                <tr>
                    <td><code>x-custom-prompt</code></td>
                    <td>URL-Safe Base64 编码后的自定义Prompt。仅在 <code>x-advanced-mode</code> 为 <code>true</code> 时生效。</td>
                    <td>(Base64 encoded string of your prompt)</td>
                </tr>
            </tbody>
        </table>

        <h2>响应格式</h2>
        <h3>成功响应</h3>
        <p>如果识别成功，将返回一个JSON对象，包含成功状态、识别类型和结果。</p>
        <pre><code>{
    "success": true,
    "result": "识别出的文本内容...",
    "type": "text" 
}</code></pre>
        <p>如果识别出的是验证码，<code>type</code> 可能是 <code>captcha</code>。</p>

        <h3>失败响应</h3>
        <p>如果发生错误，将返回一个包含错误信息的JSON对象。</p>
        <pre><code>{
    "success": false,
    "error": "错误描述信息..."
}</code></pre>
        <p>未经授权的请求将返回 <code>401 Unauthorized</code> 状态码。</p>
    </div>
</body>
</html>
    `;
}
