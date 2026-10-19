# RIO local message service

This dependency-free Node.js service serves the previews and accepts messages from the RIO Web and Mobile pages.
Use Node.js 20 or later.

## Run locally

From the repository root:

```sh
node services/rio-messaging/server.mjs
```

Open [RIO Web](http://127.0.0.1:4317/rio-web/) or [RIO Mobile](http://127.0.0.1:4317/rio-mobile/). The service binds only to `127.0.0.1`; the GitHub Pages previews are visual-only and cannot send messages to this local service.

## API

- `POST /api/messages` — accepts `{ "conversationId": "<UUID>", "messageId": "<UUID>", "senderId": "<UUID>", "content": "..." }` and returns the accepted human message. `senderId` is a browser-generated display marker, not a verified identity.
- `GET /api/messages?conversationId=<UUID>` — returns messages accepted for that conversation.

Message submissions must be same-origin. Content is trimmed and limited to 2,000 characters; request bodies are limited to 8 KiB. The service caps memory at 500 conversations, 200 messages per conversation, and 10,000 messages total. Reusing a message ID with identical content is idempotent; reusing it with different content is rejected.

Use **Delen** to copy a conversation link and open it in another local browser tab. The previews check for new messages every 2.5 seconds. A conversation link grants read access to anyone who has it; share it only with trusted people. **Nieuw** starts a separate conversation without deleting the existing in-memory history.

## Prototype limits

This is a local development prototype, not a production messaging backend. It has no authentication, identity verification, encryption in transit, AI responses, or durable storage. Sender markers are unverified and conversation IDs are not access control. Message contents remain in process memory and disappear when the service stops. Do not expose the service to a network or use it for sensitive/private messages. Production deployment requires an approved authentication and authorization model, secure transport, durable storage, and privacy controls.

## Tests

```sh
node --test services/rio-messaging/server.test.mjs
```
