import { DurableObject } from "cloudflare:workers";

const ROOM_TTL_MS = 24 * 60 * 60 * 1000;
const MESSAGE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_MESSAGE_BYTES = 12000;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {"content-type":"application/json", "cache-control":"no-store"}
  });
}
function randomToken(bytes = 32) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  let s = "";
  for (const b of a) s += b.toString(16).padStart(2, "0");
  return s;
}
async function hashToken(token) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, {status:204, headers:{
        "access-control-allow-origin":"https://omwei.org",
        "access-control-allow-methods":"POST,OPTIONS",
        "access-control-allow-headers":"content-type"
      }});
    }
    if (url.pathname === "/room" && request.method === "POST") {
      const roomId = randomToken(16);
      const creatorToken = randomToken();
      const inviteToken = randomToken();
      const id = env.CHAT_ROOM.idFromName(roomId);
      const stub = env.CHAT_ROOM.get(id);
      const r = await stub.fetch("https://room/init", {
        method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({
          creatorTokenHash: await hashToken(creatorToken),
          inviteTokenHash: await hashToken(inviteToken)
        })
      });
      if (!r.ok) return json({error:"room creation failed"}, 500);
      return json({roomId, token:creatorToken, inviteToken});
    }
    if (url.pathname === "/room/join" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return json({error:"invalid json"}, 400); }
      if (!body?.roomId || !body?.inviteToken) return json({error:"missing invite"}, 400);
      const id = env.CHAT_ROOM.idFromName(body.roomId);
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch("https://room/join", {
        method:"POST",
        headers:{"content-type":"application/json"},
        body:JSON.stringify({inviteTokenHash:await hashToken(body.inviteToken)})
      });
    }
    if (url.pathname.startsWith("/room/") && request.headers.get("Upgrade") === "websocket") {
      const roomId = url.pathname.split("/")[2];
      if (!roomId) return new Response("missing room", {status:400});
      const id = env.CHAT_ROOM.idFromName(roomId);
      return env.CHAT_ROOM.get(id).fetch(request);
    }
    return new Response("Not found", {status:404});
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
      if (existing) return json({error:"already initialized"}, 409);
      const body = await request.json();
      await this.ctx.storage.put("room", {
        creatorTokenHash: body.creatorTokenHash,
        inviteTokenHash: body.inviteTokenHash,
        participantBTokenHash: null,
        createdAt: Date.now()
      });
      await this.ctx.storage.setAlarm(Date.now() + ROOM_TTL_MS);
      return json({ok:true});
    }

    if (url.pathname === "/join" && request.method === "POST") {
      const room = await this.ctx.storage.get("room");
      if (!room || !room.inviteTokenHash || room.participantBTokenHash) return json({error:"invite unavailable"}, 403);
      const body = await request.json();
      if (body.inviteTokenHash !== room.inviteTokenHash) return json({error:"invalid invite"}, 403);
      const token = randomToken();
      room.participantBTokenHash = await hashToken(token);
      room.inviteTokenHash = null;
      await this.ctx.storage.put("room", room);
      return json({token});
    }

    if (request.headers.get("Upgrade") === "websocket") {
      const token = url.searchParams.get("token");
      const room = await this.ctx.storage.get("room");
      if (!room || !token) return new Response("unauthorized", {status:401});
      const tokenHash = await hashToken(token);
      let role = null;
      if (tokenHash === room.creatorTokenHash) role = "A";
      if (tokenHash === room.participantBTokenHash) role = "B";
      if (!role) return new Response("unauthorized", {status:401});

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server, [role]);
      server.serializeAttachment({role});
      const peer = this.ctx.getWebSockets(role === "A" ? "B" : "A")[0];
      if (peer?.readyState === WebSocket.OPEN) {
        server.send(JSON.stringify({type:"peer-present"}));
      }
      const pending = await this.ctx.storage.list({prefix:"msg:"});
      for (const [key, value] of pending) {
        if (value.expiresAt > Date.now() && value.recipient === role) {
          server.send(JSON.stringify({type:"message", id:key.slice(4), payload:value.payload}));
        }
      }
      return new Response(null, {status:101, webSocket:client});
    }

    return new Response("Not found", {status:404});
  }

  async webSocketMessage(ws, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const attachment = ws.deserializeAttachment();
    if (!attachment?.role) return;
    const role = attachment.role;
    const otherRole = role === "A" ? "B" : "A";

    if (msg.type === "key") {
      ws.serializeAttachment({...attachment, key:msg.key});
      const peer = this.ctx.getWebSockets(otherRole)[0];
      if (peer?.readyState === WebSocket.OPEN) {
        peer.send(JSON.stringify({type:"peer-key", key:msg.key}));
        const peerAttachment = peer.deserializeAttachment();
        if (peerAttachment?.key) ws.send(JSON.stringify({type:"peer-key", key:peerAttachment.key}));
      }
      return;
    }

    if (msg.type === "send") {
      if (typeof msg.id !== "string" || !msg.payload || JSON.stringify(msg.payload).length > MAX_MESSAGE_BYTES) return;
      const recipient = otherRole;
      await this.ctx.storage.put("msg:" + msg.id, {
        recipient,
        payload:msg.payload,
        createdAt:Date.now(),
        expiresAt:Date.now() + MESSAGE_TTL_MS
      });
      const peer = this.ctx.getWebSockets(recipient)[0];
      if (peer?.readyState === WebSocket.OPEN) {
        peer.send(JSON.stringify({type:"message", id:msg.id, payload:msg.payload}));
      }
      return;
    }

    if (msg.type === "read" && typeof msg.id === "string") {
      const key = "msg:" + msg.id;
      const item = await this.ctx.storage.get(key);
      if (!item || item.recipient !== role) return;
      await this.ctx.storage.delete(key);
      for (const peer of this.ctx.getWebSockets()) {
        if (peer.readyState === WebSocket.OPEN) peer.send(JSON.stringify({type:"deleted", id:msg.id}));
      }
    }
  }

  async webSocketClose(ws) {
    const attachment = ws.deserializeAttachment();
    if (!attachment?.role) return;
    const otherRole = attachment.role === "A" ? "B" : "A";
    for (const peer of this.ctx.getWebSockets(otherRole)) {
      if (peer.readyState === WebSocket.OPEN) peer.send(JSON.stringify({type:"peer-left"}));
    }
  }

  async alarm() {
    const now = Date.now();
    const entries = await this.ctx.storage.list({prefix:"msg:"});
    for (const [key, value] of entries) {
      if (value.expiresAt <= now) {
        await this.ctx.storage.delete(key);
        for (const ws of this.ctx.getWebSockets()) {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:"deleted", id:key.slice(4)}));
        }
      }
    }
    const room = await this.ctx.storage.get("room");
    if (room && room.createdAt + ROOM_TTL_MS > now) {
      await this.ctx.storage.setAlarm(Math.min(room.createdAt + ROOM_TTL_MS, now + MESSAGE_TTL_MS));
    } else {
      await this.ctx.storage.deleteAll();
    }
  }
}
