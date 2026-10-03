import { DurableObject } from "cloudflare:workers";

const ROOM_TTL_MS = 24 * 60 * 60 * 1000;
const MESSAGE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_MESSAGE_BYTES = 12000;
const MAX_CIPHERTEXT_BYTES = 10000;
const MAX_ID_LENGTH = 64;
const ALLOWED_ORIGINS = new Set(["https://omwei.org", "http://localhost:8080"]);
const ROOM_ID_RE = /^[a-f0-9]{32}$/;
const MESSAGE_ID_RE = /^[A-Za-z0-9_-]{20,64}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;

function corsHeaders(origin) {
  const headers = {
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type",
    "cache-control": "no-store",
    "vary": "Origin"
  };
  if (ALLOWED_ORIGINS.has(origin)) headers["access-control-allow-origin"] = origin;
  return headers;
}

function json(data, status = 200, origin = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...corsHeaders(origin)
    }
  });
}

function randomToken(bytes = 32) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  let s = "";
  for (const b of a) s += b.toString(16).padStart(2, "0");
  return s;
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  return Array.from(
    new Uint8Array(digest),
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

function validOrigin(request) {
  return ALLOWED_ORIGINS.has(request.headers.get("Origin"));
}

function validMessagePayload(payload) {
  if (!payload || typeof payload !== "object") return false;
  if (typeof payload.iv !== "string" || typeof payload.data !== "string") return false;
  if (!B64U_RE.test(payload.iv) || !B64U_RE.test(payload.data)) return false;
  if (payload.iv.length !== 16) return false; // 12-byte GCM IV
  if (payload.data.length > MAX_CIPHERTEXT_BYTES * 2) return false;
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    if (request.method === "OPTIONS") {
      if (!ALLOWED_ORIGINS.has(origin)) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === "/room" && request.method === "POST") {
      if (!validOrigin(request)) return json({ error: "forbidden origin" }, 403, origin);

      const roomId = randomToken(16);
      const creatorToken = randomToken();
      const inviteToken = randomToken();

      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      const r = await stub.fetch("https://room/init", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          creatorTokenHash: await hashToken(creatorToken),
          inviteTokenHash: await hashToken(inviteToken)
        })
      });

      if (!r.ok) return json({ error: "room creation failed" }, 500, origin);
      return json({ roomId, token: creatorToken, inviteToken }, 200, origin);
    }

    if (url.pathname === "/room/join" && request.method === "POST") {
      if (!validOrigin(request)) return json({ error: "forbidden origin" }, 403, origin);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "invalid json" }, 400, origin);
      }

      if (
        typeof body?.roomId !== "string" ||
        !ROOM_ID_RE.test(body.roomId) ||
        typeof body?.inviteToken !== "string" ||
        !/^[a-f0-9]{64}$/.test(body.inviteToken)
      ) {
        return json({ error: "invalid invite" }, 400, origin);
      }

      const id = env.CHAT_ROOM.idFromName(body.roomId);
      const stub = env.CHAT_ROOM.get(id);
      const response = await stub.fetch("https://room/join", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          inviteTokenHash: await hashToken(body.inviteToken)
        })
      });

      const responseBody = await response.text();
      return new Response(responseBody, {
        status: response.status,
        headers: {
          "content-type": "application/json; charset=utf-8",
          ...corsHeaders(origin)
        }
      });
    }

    if (url.pathname === "/room/delete" && request.method === "POST") {
      if (!validOrigin(request)) return json({ error: "forbidden origin" }, 403, origin);

      let body;
      try {
        body = await request.text();
        body = JSON.parse(body);
      } catch {
        return json({ error: "invalid json" }, 400, origin);
      }

      if (
        typeof body?.roomId !== "string" ||
        !ROOM_ID_RE.test(body.roomId) ||
        typeof body?.token !== "string" ||
        !/^[a-f0-9]{64}$/.test(body.token)
      ) {
        return json({ error: "invalid delete request" }, 400, origin);
      }

      const id = env.CHAT_ROOM.idFromName(body.roomId);
      const stub = env.CHAT_ROOM.get(id);
      const response = await stub.fetch("https://room/delete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tokenHash: await hashToken(body.token) })
      });

      const responseBody = await response.text();
      return new Response(responseBody, {
        status: response.status,
        headers: {
          "content-type": "application/json; charset=utf-8",
          ...corsHeaders(origin)
        }
      });
    }

    if (url.pathname.startsWith("/room/") && request.headers.get("Upgrade") === "websocket") {
      if (!validOrigin(request)) return new Response("forbidden origin", { status: 403 });

      const roomId = url.pathname.split("/")[2];
      if (!ROOM_ID_RE.test(roomId || "")) return new Response("invalid room", { status: 400 });

      const id = env.CHAT_ROOM.idFromName(roomId);
      return env.CHAT_ROOM.get(id).fetch(request);
    }

    return new Response("Not found", {
      status: 404,
      headers: { "cache-control": "no-store" }
    });
  }
};

export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/init" && request.method === "POST") {
      const existing = await this.ctx.storage.get("room");
      if (existing) return json({ error: "already initialized" }, 409);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "invalid json" }, 400);
      }

      if (
        typeof body?.creatorTokenHash !== "string" ||
        typeof body?.inviteTokenHash !== "string"
      ) {
        return json({ error: "invalid initialization" }, 400);
      }

      const createdAt = Date.now();
      await this.ctx.storage.put("room", {
        creatorTokenHash: body.creatorTokenHash,
        inviteTokenHash: body.inviteTokenHash,
        participantBTokenHash: null,
        createdAt
      });
      await this.ctx.storage.setAlarm(createdAt + MESSAGE_TTL_MS);

      return json({ ok: true });
    }

    if (url.pathname === "/join" && request.method === "POST") {
      const room = await this.ctx.storage.get("room");
      if (!room || !room.inviteTokenHash || room.participantBTokenHash) {
        return json({ error: "invite unavailable" }, 403);
      }

      if (room.createdAt + ROOM_TTL_MS <= Date.now()) {
        await this.ctx.storage.deleteAll();
        return json({ error: "room expired" }, 410);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "invalid json" }, 400);
      }

      if (body?.inviteTokenHash !== room.inviteTokenHash) {
        return json({ error: "invalid invite" }, 403);
      }

      const token = randomToken();
      room.participantBTokenHash = await hashToken(token);
      room.inviteTokenHash = null;
      await this.ctx.storage.put("room", room);

      return json({ token });
    }

    if (url.pathname === "/delete" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response("invalid json", { status: 400 });
      }

      const room = await this.ctx.storage.get("room");
      if (!room || typeof body?.tokenHash !== "string") {
        return new Response("not found", { status: 404 });
      }

      if (body.tokenHash !== room.creatorTokenHash && body.tokenHash !== room.participantBTokenHash) {
        return new Response("forbidden", { status: 403 });
      }

      for (const ws of this.ctx.getWebSockets()) {
        try { ws.send(JSON.stringify({ type: "chat-deleted" })); } catch {}
      }
      await this.ctx.storage.deleteAll();
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }

    if (request.headers.get("Upgrade") === "websocket") {
      if (!ALLOWED_ORIGINS.has(request.headers.get("Origin"))) {
        return new Response("forbidden origin", { status: 403 });
      }

      const token = url.searchParams.get("token");
      const room = await this.ctx.storage.get("room");

      if (!room || !token || room.createdAt + ROOM_TTL_MS <= Date.now()) {
        return new Response("unauthorized", { status: 401 });
      }

      const tokenHash = await hashToken(token);
      let role = null;
      if (tokenHash === room.creatorTokenHash) role = "A";
      if (tokenHash === room.participantBTokenHash) role = "B";
      if (!role) return new Response("unauthorized", { status: 401 });

      // One active browser session per participant.
      for (const old of this.ctx.getWebSockets(role)) {
        try { old.close(4001, "replaced by newer session"); } catch {}
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server, [role]);
      server.serializeAttachment({ role });

      const peerRole = role === "A" ? "B" : "A";
      const peer = this.ctx.getWebSockets(peerRole)[0];

      if (peer?.readyState === WebSocket.OPEN) {
        server.send(JSON.stringify({ type: "peer-present" }));
      }

      const pending = await this.ctx.storage.list({ prefix: "msg:" });
      const now = Date.now();
      for (const [key, value] of pending) {
        if (value.expiresAt > now && value.recipient === role) {
          server.send(JSON.stringify({
            type: "message",
            id: key.slice(4),
            payload: value.payload
          }));
        }
      }

      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response("Not found", { status: 404 });
  }

  async webSocketMessage(ws, raw) {
    if (typeof raw !== "string") return;

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    const attachment = ws.deserializeAttachment();
    if (!attachment?.role) return;

    const role = attachment.role;
    const otherRole = role === "A" ? "B" : "A";

    if (msg.type === "key") {
      if (!msg.key || typeof msg.key !== "object" || JSON.stringify(msg.key).length > 2048) return;

      ws.serializeAttachment({ ...attachment, key: msg.key });

      const peer = this.ctx.getWebSockets(otherRole)[0];
      if (peer?.readyState === WebSocket.OPEN) {
        peer.send(JSON.stringify({ type: "peer-key", key: msg.key }));
        const peerAttachment = peer.deserializeAttachment();
        if (peerAttachment?.key) {
          ws.send(JSON.stringify({ type: "peer-key", key: peerAttachment.key }));
        }
      }
      return;
    }

    if (msg.type === "send") {
      if (
        typeof msg.id !== "string" ||
        !MESSAGE_ID_RE.test(msg.id) ||
        msg.id.length > MAX_ID_LENGTH ||
        !validMessagePayload(msg.payload)
      ) return;

      const key = "msg:" + msg.id;
      const existing = await this.ctx.storage.get(key);
      if (existing) return;

      const serialized = JSON.stringify(msg.payload);
      if (serialized.length > MAX_MESSAGE_BYTES) return;

      const now = Date.now();
      await this.ctx.storage.put(key, {
        recipient: otherRole,
        payload: msg.payload,
        createdAt: now,
        expiresAt: now + MESSAGE_TTL_MS
      });

      const peer = this.ctx.getWebSockets(otherRole)[0];
      if (peer?.readyState === WebSocket.OPEN) {
        peer.send(JSON.stringify({
          type: "message",
          id: msg.id,
          payload: msg.payload
        }));
      }
      return;
    }

    if (msg.type === "read") {
      if (typeof msg.id !== "string" || !MESSAGE_ID_RE.test(msg.id)) return;

      const key = "msg:" + msg.id;
      const item = await this.ctx.storage.get(key);
      if (!item || item.recipient !== role) return;

      await this.ctx.storage.delete(key);

      for (const peer of this.ctx.getWebSockets()) {
        if (peer.readyState === WebSocket.OPEN) {
          peer.send(JSON.stringify({ type: "deleted", id: msg.id }));
        }
      }
    }
  }

  async webSocketClose(ws) {
    const attachment = ws.deserializeAttachment();
    if (!attachment?.role) return;

    const otherRole = attachment.role === "A" ? "B" : "A";
    for (const peer of this.ctx.getWebSockets(otherRole)) {
      if (peer.readyState === WebSocket.OPEN) {
        peer.send(JSON.stringify({ type: "peer-left" }));
      }
    }
  }

  async alarm() {
    const now = Date.now();
    const room = await this.ctx.storage.get("room");

    if (!room || room.createdAt + ROOM_TTL_MS <= now) {
      for (const ws of this.ctx.getWebSockets()) {
        try { ws.close(4000, "room expired"); } catch {}
      }
      await this.ctx.storage.deleteAll();
      return;
    }

    const entries = await this.ctx.storage.list({ prefix: "msg:" });
    for (const [key, value] of entries) {
      if (value.expiresAt <= now) {
        await this.ctx.storage.delete(key);
        for (const ws of this.ctx.getWebSockets()) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "deleted", id: key.slice(4) }));
          }
        }
      }
    }

    const nextMessageExpiry = entries
      .map(([, value]) => value.expiresAt)
      .filter(t => t > now)
      .sort((a, b) => a - b)[0];

    await this.ctx.storage.setAlarm(
      Math.min(
        room.createdAt + ROOM_TTL_MS,
        nextMessageExpiry || now + MESSAGE_TTL_MS
      )
    );
  }
}
