import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_APPS_DIRECTORY = fileURLToPath(new URL("../../apps/", import.meta.url));
const MAX_BODY_BYTES = 8 * 1024;
const MAX_MESSAGE_LENGTH = 2_000;
const MAX_CONVERSATIONS = 500;
const MAX_MESSAGES_PER_CONVERSATION = 200;
const MAX_TOTAL_MESSAGES = 10_000;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTENT_TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(body));
}

function applySecurityHeaders(response) {
  response.setHeader("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("x-frame-options", "DENY");
}

function assertSameOrigin(request, { requireOrigin = true } = {}) {
  const host = request.headers.host;
  const origin = request.headers.origin;
  if (!host || (requireOrigin && !origin)) {
    throw new HttpError(403, "Same-origin requests are required.");
  }

  let requestUrl;
  let originUrl;
  try {
    requestUrl = new URL(`http://${host}`);
    originUrl = origin ? new URL(origin) : null;
  } catch {
    throw new HttpError(403, "Same-origin requests are required.");
  }

  const localHosts = new Set(["127.0.0.1", "localhost"]);
  const port = requestUrl.port || "80";
  if (
    !localHosts.has(requestUrl.hostname) ||
    (originUrl && (originUrl.protocol !== "http:" || originUrl.origin !== requestUrl.origin)) ||
    port !== String(request.socket.localPort)
  ) {
    throw new HttpError(403, "Same-origin requests are required.");
  }
}

async function readJson(request) {
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (declaredLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "Request body is too large.");
  }

  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) {
      throw new HttpError(413, "Request body is too large.");
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function validateMessage(body) {
  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    typeof body.conversationId !== "string" ||
    !UUID_PATTERN.test(body.conversationId) ||
    typeof body.messageId !== "string" ||
    !UUID_PATTERN.test(body.messageId) ||
    typeof body.senderId !== "string" ||
    !UUID_PATTERN.test(body.senderId) ||
    typeof body.content !== "string"
  ) {
    throw new HttpError(400, "conversationId, messageId, senderId, and content are required.");
  }

  const content = body.content.trim();
  if (!content) {
    throw new HttpError(400, "Message content cannot be empty.");
  }
  if (content.length > MAX_MESSAGE_LENGTH) {
    throw new HttpError(413, `Messages cannot exceed ${MAX_MESSAGE_LENGTH} characters.`);
  }
  return { conversationId: body.conversationId, messageId: body.messageId, senderId: body.senderId, content };
}

function apiPath(pathname) {
  return pathname === "/api/messages" || pathname === "/api/messages/";
}

async function serveStatic(request, response, pathname, appsDirectory) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    throw new HttpError(405, "Method not allowed.");
  }

  let relativePath;
  try {
    relativePath = decodeURIComponent(pathname).replace(/^\/+/, "");
  } catch {
    throw new HttpError(400, "Invalid URL path.");
  }
  if (relativePath.includes("\\") || relativePath.includes("\0")) {
    throw new HttpError(400, "Invalid URL path.");
  }

  const root = resolve(appsDirectory);
  let filePath = resolve(root, relativePath || "index.html");
  if (filePath !== root && !filePath.startsWith(`${root}${sep}`)) {
    throw new HttpError(404, "Not found.");
  }

  try {
    const info = await stat(filePath);
    if (info.isDirectory()) filePath = resolve(filePath, "index.html");
    else if (!info.isFile()) throw new HttpError(404, "Not found.");
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(404, "Not found.");
  }

  let info;
  try {
    info = await stat(filePath);
  } catch {
    throw new HttpError(404, "Not found.");
  }
  if (!info.isFile() || (filePath !== root && !filePath.startsWith(`${root}${sep}`))) {
    throw new HttpError(404, "Not found.");
  }

  response.writeHead(200, {
    "cache-control": "no-store",
    "content-length": info.size,
    "content-type": CONTENT_TYPES.get(extname(filePath)) ?? "application/octet-stream",
  });
  if (request.method === "HEAD") {
    response.end();
  } else {
    createReadStream(filePath).pipe(response);
  }
}

export function createServer({ appsDirectory = DEFAULT_APPS_DIRECTORY } = {}) {
  const conversations = new Map();
  const messageIndex = new Map();

  return createHttpServer(async (request, response) => {
    applySecurityHeaders(response);
    let pathname;
    try {
      pathname = new URL(request.url, "http://localhost").pathname;

      if (apiPath(pathname)) {
        const url = new URL(request.url, "http://localhost");
        assertSameOrigin(request, { requireOrigin: request.method !== "GET" });
        if (request.method === "GET") {
          const conversationId = url.searchParams.get("conversationId");
          if (!conversationId || !UUID_PATTERN.test(conversationId)) {
            throw new HttpError(400, "A valid conversationId is required.");
          }
          sendJson(response, 200, { messages: conversations.get(conversationId) ?? [] });
          return;
        }

        if (request.method !== "POST") {
          throw new HttpError(405, "Method not allowed.");
        }
        if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) {
          throw new HttpError(415, "Content-Type must be application/json.");
        }

        const { conversationId, messageId, senderId, content } = validateMessage(await readJson(request));
        const key = `${conversationId}:${messageId}`;
        const existing = messageIndex.get(key);
        if (existing) {
          if (existing.content !== content || existing.senderId !== senderId) {
            throw new HttpError(409, "messageId was already used for different content.");
          }
          sendJson(response, 200, { message: existing, duplicate: true });
          return;
        }

        if (!conversations.has(conversationId) && conversations.size >= MAX_CONVERSATIONS) {
          throw new HttpError(503, "The in-memory service is full; restart it to clear demo data.");
        }
        if (messageIndex.size >= MAX_TOTAL_MESSAGES) {
          throw new HttpError(503, "The in-memory service reached its message limit; restart it to clear demo data.");
        }
        const messages = conversations.get(conversationId) ?? [];
        if (messages.length >= MAX_MESSAGES_PER_CONVERSATION) {
          throw new HttpError(413, "This demo conversation reached its message limit.");
        }

        const message = {
          id: messageId,
          conversationId,
          senderId,
          role: "human",
          content,
          acceptedAt: new Date().toISOString(),
        };
        messages.push(message);
        conversations.set(conversationId, messages);
        messageIndex.set(key, message);
        sendJson(response, 201, { message, duplicate: false });
        return;
      }

      await serveStatic(request, response, pathname, appsDirectory);
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (error instanceof HttpError) {
        sendJson(response, error.status, { error: error.message });
        return;
      }
      sendJson(response, 500, { error: "The request could not be completed." });
    }
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const port = Number(process.env.PORT ?? 4317);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    process.stderr.write("PORT must be an integer between 1 and 65535.\n");
    process.exitCode = 1;
  } else {
    const server = createServer();
    server.listen(port, "127.0.0.1", () => {
      process.stdout.write(`RIO preview and message API: http://127.0.0.1:${port}/\n`);
      process.stdout.write("Loopback only; messages are held in memory and cleared when the process stops.\n");
    });
  }
}
