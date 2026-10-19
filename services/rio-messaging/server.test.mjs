import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { randomUUID } from "node:crypto";

import { createServer } from "./server.mjs";

const server = createServer();
let baseUrl;

before(async () => {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

function postMessage(conversationId, messageId, senderId, content, origin = baseUrl) {
  return fetch(`${baseUrl}/api/messages`, {
    method: "POST",
    headers: { origin, "content-type": "application/json" },
    body: JSON.stringify({ conversationId, messageId, senderId, content }),
  });
}

test("serves the previews and accepts bounded same-origin messages idempotently", async () => {
  const page = await fetch(`${baseUrl}/rio-web/`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy"), /default-src 'self'/);
  assert.match(await page.text(), /Lokaal demo-gesprek/);

  const conversationId = randomUUID();
  const messageId = randomUUID();
  const senderId = randomUUID();
  const accepted = await postMessage(conversationId, messageId, senderId, "  Hallo RIO  ");
  assert.equal(accepted.status, 201);
  const body = await accepted.json();
  assert.equal(body.message.content, "Hallo RIO");
  assert.equal(body.message.role, "human");
  assert.equal(body.message.senderId, senderId);
  assert.equal(body.duplicate, false);

  const duplicate = await postMessage(conversationId, messageId, senderId, "Hallo RIO");
  assert.equal(duplicate.status, 200);
  assert.equal((await duplicate.json()).duplicate, true);

  const changedDuplicate = await postMessage(conversationId, messageId, senderId, "Andere tekst");
  assert.equal(changedDuplicate.status, 409);
  const changedSender = await postMessage(conversationId, messageId, randomUUID(), "Hallo RIO");
  assert.equal(changedSender.status, 409);

  const secondSenderId = randomUUID();
  const secondMessage = await postMessage(conversationId, randomUUID(), secondSenderId, "Bericht van een tweede browser");
  assert.equal(secondMessage.status, 201);

  const history = await fetch(
    `${baseUrl}/api/messages?conversationId=${conversationId}`,
  );
  assert.equal(history.status, 200);
  const messages = (await history.json()).messages;
  assert.equal(messages.length, 2);
  assert.equal(messages[1].senderId, secondSenderId);
});

test("rejects invalid content, cross-origin requests, and traversal", async () => {
  const conversationId = randomUUID();
  assert.equal((await postMessage(conversationId, randomUUID(), randomUUID(), "   ")).status, 400);
  assert.equal((await postMessage(conversationId, randomUUID(), randomUUID(), "x".repeat(2001))).status, 413);
  assert.equal((await postMessage(conversationId, randomUUID(), randomUUID(), "Nee", "https://example.com")).status, 403);

  const noOriginRead = await fetch(`${baseUrl}/api/messages?conversationId=${conversationId}`);
  assert.equal(noOriginRead.status, 200);
  const noOriginWrite = await fetch(`${baseUrl}/api/messages`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ conversationId, messageId: randomUUID(), senderId: randomUUID(), content: "Nee" }),
  });
  assert.equal(noOriginWrite.status, 403);
  const missingSender = await fetch(`${baseUrl}/api/messages`, {
    method: "POST",
    headers: { origin: baseUrl, "content-type": "application/json" },
    body: JSON.stringify({ conversationId, messageId: randomUUID(), content: "Geen afzender" }),
  });
  assert.equal(missingSender.status, 400);
  const wrongContentType = await fetch(`${baseUrl}/api/messages`, {
    method: "POST",
    headers: { origin: baseUrl, "content-type": "text/plain" },
    body: "message",
  });
  assert.equal(wrongContentType.status, 415);
  const oversizedBody = await fetch(`${baseUrl}/api/messages`, {
    method: "POST",
    headers: { origin: baseUrl, "content-type": "application/json" },
    body: JSON.stringify({ padding: "x".repeat(9 * 1024) }),
  });
  assert.equal(oversizedBody.status, 413);
  const traversal = await fetch(`${baseUrl}/%2e%2e/services/rio-messaging/server.mjs`);
  assert.equal(traversal.status, 404);
});
