export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname.replace(/^\/+/, "");
        const token = url.searchParams.get("token");
        if (!token || !path) return default_page()
        const tokenData = await verifyToken(token, env);
        console.log(tokenData)
        if (!tokenData || Date.now() - tokenData.time > 20000 || tokenData.token !== env.TOKEN) return new Response("Invalid token or time expired!", { status: 401 });
        try {
            switch (request.method) {
                case 'GET':
                    return await handleGet(env.storage, path);
                case 'PUT':
                    return await handlePut(env.storage, path, request);
                case 'DELETE':
                    return await handleDelete(env.storage, path);
                default:
                    return new Response('Method not allowed', { status: 405 });
            }
        } catch (error) {
            console.error('Error:', error);
            return new Response('Internal Server Error', { status: 500 });
        }
    }
};

async function handleGet(storage, path) {
    const { value, metadata } = await storage.getWithMetadata(path);
    if (!value) return new Response('File not found', { status: 404 });
    let contentType = metadata?.contentType || 'text/plain';
    let responseValue = value;
    if (metadata?.isChunkMetadata) {
        const chunkInfo = JSON.parse(value);
        if (chunkInfo.isChunked) {
            responseValue = JSON.stringify({ischunk:chunkInfo.isChunked,length:chunkInfo.totalChunks})
            contentType = 'text/plain';
        }
    } else if (contentType === 'application/json') {
        try {
            responseValue = JSON.stringify(JSON.parse(value), null, 2);
        } catch (e) {
            console.warn('Failed to parse JSON, returning raw value');
        }
    }
    return new Response(responseValue, { headers: { 'Content-Type': contentType } });
}
async function handlePut(storage, path, request) {
    const requestContentType = request.headers.get('Content-Type');
    let content, contentType;
    if (requestContentType === 'application/json') {
        content = JSON.stringify(await request.json());
        contentType = 'application/json';
    } else if (requestContentType?.startsWith('text/')) {
        content = await request.text();
        contentType = 'text/plain';
        const chunkSize = 786432 //
        if (content.length > chunkSize) {
            const chunks = [];
            for (let i = 0; i < content.length; i += chunkSize) {
                chunks.push(content.slice(i, i + chunkSize));
            }
            await Promise.all(chunks.map((chunk, index) => {
                const chunkPath = `${path}${index + 1}`;
                return storage.put(chunkPath, chunk, { 
                    metadata: { contentType: 'text/plain', isChunk: true, totalChunks: chunks.length, chunkIndex: index + 1 } 
                });
            }));
            await storage.put(path, JSON.stringify({ 
                isChunked: true, 
                totalChunks: chunks.length,
                originalContentType: contentType 
            }), { 
                metadata: { contentType: 'application/json', isChunkMetadata: true } 
            });
            return new Response(`File ${path} chunked and stored successfully`, { status: 200 });
        }
    } else {
        content = await request.arrayBuffer();
        contentType = requestContentType || 'application/octet-stream';
    }
    const isNewKey = await storage.get(path) === null;
    await storage.put(path, content, { metadata: { contentType } });
    return new Response(`File ${path} ${isNewKey ? 'created' : 'updated'} successfully`, { status: 200 });
}
async function handleDelete(storage, path) {
    if (await storage.get(path) === null) return new Response('File not found', { status: 404 });
    await storage.delete(path);
    return new Response(`File ${path} deleted successfully`, { status: 200 });
}
function default_page() {
    return new Response(
        `<!DOCTYPE html>
        <html>
        <head>
        <title>Welcome to nginx!</title>
        <style>
        html { color-scheme: light dark; }
        body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
        </style>
        </head>
        <body>
        <h1>Welcome to nginx!</h1>
        <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
        <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
        Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
        <p><em>Thank you for using nginx.</em></p>
        </body>
        </html>`,
        {headers: {"content-type": "text/html;charset=utf-8",},}
    )
}
async function verifyToken(token, env) {
    const response = await fetch('https://tool.lmeee.com/jiami/crypt128inter', {
        method: 'POST',
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'tool.lmeee.com',
        },
        body: new URLSearchParams({
            'mode': 'ECB',
            'padding': 'pkcs7',
            'block': '128',
            'password': env.KEY,
            'iv': '',
            'encode': 'hex',
            'way': '2',
            'text': token,
            'method': 'aes'
        }),
    });
    const respData = await response.json();
    return respData.d.r ? JSON.parse(respData.d.r) : null
}
