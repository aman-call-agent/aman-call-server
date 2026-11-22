/*
 * Aman (آمن) — signaling + accounts server for the encrypted calling app.
 *
 * What it does:
 *  - username accounts (passwords stored as scrypt hashes in data.json)
 *  - user search, friend requests, friends list, online presence
 *  - relays WebRTC call signaling (SDP/ICE) between two friends only
 *  - serves a small admin web page at /admin
 *
 * What it never sees: call audio. Media goes peer-to-peer via WebRTC
 * (DTLS-SRTP encrypted) between the two phones.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT || '3000', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin123';
const DB_FILE = path.join(__dirname, 'data.json');

// ---------- storage ----------
let db = { users: {}, friends: {}, requests: {}, blocks: {} };
try {
  if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch (e) { console.error('Could not read data.json, starting empty:', e.message); }
db.users = db.users || {}; db.friends = db.friends || {}; db.requests = db.requests || {}; db.blocks = db.blocks || {};

let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(DB_FILE, JSON.stringify(db, null, 2), err => {
      if (err) console.error('save failed:', err.message);
    });
  }, 200);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32).toString('hex');
}

// ---------- presence ----------
const online = new Map(); // username -> ws
const pubkeys = new Map();
// Statuses (حالات): memory-only, ciphertext only, 24-hour lifetime.
// target -> Map(from -> {iv, ct, exp})
const statuses = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [to, m] of statuses) {
    for (const [from, st] of m) if (st.exp <= now) m.delete(from);
    if (m.size === 0) statuses.delete(to);
  }
}, 60000).unref(); // username -> base64 X.509 ECDH P-256 public key (memory only, never saved)

function send(ws, obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}
function sendTo(username, obj) {
  const ws = online.get(username);
  if (ws) send(ws, obj);
}
function notifyFriends(username, obj) {
  (db.friends[username] || []).forEach(f => sendTo(f, obj));
}
function isFriend(a, b) {
  return (db.friends[a] || []).includes(b);
}
function isBlocked(by, other) { // "by" has blocked "other"
  return (db.blocks[by] || []).includes(other);
}
function removeRequest(to, from) {
  const arr = db.requests[to] || [];
  const i = arr.indexOf(from);
  if (i >= 0) { arr.splice(i, 1); save(); return true; }
  return false;
}

// ---------- websocket protocol ----------
const server = http.createServer(handleHttp);
const wss = new WebSocketServer({ server });

wss.on('connection', ws => {
  let me = null;

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const t = msg.type;

    if (t === 'register' || t === 'login') {
      const u = String(msg.username || '').trim();
      const p = String(msg.password || '');
      if (!/^[A-Za-z0-9_]{3,20}$/.test(u)) {
        return send(ws, { type: t + '_error', message: 'اسم المستخدم لازم يكون 3-20 حرف أو رقم إنجليزي بدون مسافات' });
      }
      if (p.length < 4) {
        return send(ws, { type: t + '_error', message: 'كلمة السر 4 حروف على الأقل' });
      }
      if (t === 'register') {
        if (db.users[u]) return send(ws, { type: 'register_error', message: 'اسم المستخدم ده موجود بالفعل' });
        const salt = crypto.randomBytes(16).toString('hex');
        db.users[u] = { passHash: hashPassword(p, salt), salt, created: new Date().toISOString() };
        db.friends[u] = db.friends[u] || [];
        save();
      } else {
        const rec = db.users[u];
        if (!rec || hashPassword(p, rec.salt) !== rec.passHash) {
          return send(ws, { type: 'login_error', message: 'اسم المستخدم أو كلمة السر غلط' });
        }
      }
      // take over the session: drop any older connection for this user
      const old = online.get(u);
      if (old && old !== ws) { try { old.close(); } catch {} }
      me = u;
      online.set(u, ws);
      send(ws, { type: t + '_ok', username: u });
      notifyFriends(u, { type: 'presence', username: u, online: true });
      return;
    }

    if (!me) return send(ws, { type: 'error', message: 'سجّل الدخول الأول' });

    if (t === 'search') {
      const q = String(msg.query || '').trim().toLowerCase();
      const users = !q ? [] : Object.keys(db.users)
        .filter(u => u !== me && u.toLowerCase().includes(q))
        .slice(0, 20)
        .map(u => ({
          username: u,
          isFriend: isFriend(me, u),
          requested: (db.requests[u] || []).includes(me),
          online: online.has(u),
          avatar: (db.users[u] || {}).avatar || null
        }));
      return send(ws, { type: 'search_results', users });
    }

    if (t === 'block') {
      const u = String(msg.username || '');
      if (!db.users[u]) return;
      db.blocks[me] = db.blocks[me] || [];
      const i = db.blocks[me].indexOf(u);
      if (msg.blocked && i < 0) { db.blocks[me].push(u); save(); }
      if (!msg.blocked && i >= 0) { db.blocks[me].splice(i, 1); save(); }
      return send(ws, { type: 'block_ok', username: u, blocked: !!msg.blocked });
    }

    if (t === 'blocks') {
      return send(ws, { type: 'blocks', users: (db.blocks[me] || []).slice() });
    }

    if (t === 'set_avatar') {
      const data = String(msg.data || '');
      if (data.length > 140000) return send(ws, { type: 'error', message: 'الصورة كبيرة أوي' });
      if (db.users[me]) { db.users[me].avatar = data; save(); }
      (db.friends[me] || []).forEach(f =>
        sendTo(f, { type: 'avatar', username: me, data }));
      return send(ws, { type: 'avatar_ok' });
    }

    if (t === 'friend_request') {
      const to = String(msg.to || '');
      if (!db.users[to] || to === me) return send(ws, { type: 'error', message: 'المستخدم مش موجود' });
      if (isBlocked(to, me)) return send(ws, { type: 'error', message: 'مش قادر تبعت طلب للمستخدم ده' });
      if (isFriend(me, to)) return send(ws, { type: 'error', message: 'أنتم أصحاب بالفعل' });
      db.requests[to] = db.requests[to] || [];
      if (!db.requests[to].includes(me)) { db.requests[to].push(me); save(); }
      sendTo(to, { type: 'friend_request', from: me });
      return send(ws, { type: 'friend_request_sent', to });
    }

    if (t === 'friend_respond') {
      const from = String(msg.from || '');
      const accept = !!msg.accept;
      if (!removeRequest(me, from)) return send(ws, { type: 'error', message: 'مفيش طلب من المستخدم ده' });
      if (accept) {
        db.friends[me] = db.friends[me] || [];
        db.friends[from] = db.friends[from] || [];
        if (!db.friends[me].includes(from)) db.friends[me].push(from);
        if (!db.friends[from].includes(me)) db.friends[from].push(me);
        save();
        sendTo(from, { type: 'friend_accepted', from: me });
      } else {
        sendTo(from, { type: 'friend_rejected', from: me });
      }
      return send(ws, { type: 'friend_respond_ok', from, accept });
    }

    if (t === 'friends') {
      return send(ws, {
        type: 'friends',
        users: (db.friends[me] || []).map(u => ({
          username: u, online: online.has(u), avatar: (db.users[u] || {}).avatar || null
        }))
      });
    }

    if (t === 'requests') {
      return send(ws, { type: 'requests', users: (db.requests[me] || []).slice() });
    }

    if (t === 'call') {
      const to = String(msg.to || '');
      if (!isFriend(me, to)) return send(ws, { type: 'call_error', message: 'تقدر تتصل بأصحابك بس' });
      if (isBlocked(to, me)) return send(ws, { type: 'call_error', message: 'المستخدم ده مش متاح للمكالمات' });
      if (isBlocked(me, to)) return send(ws, { type: 'call_error', message: 'انت حاظر المستخدم ده - افتح الحظر الأول' });
      if (!online.has(to)) return send(ws, { type: 'call_error', message: 'الطرف التاني مش متصل دلوقتي' });
      sendTo(to, { type: 'incoming_call', from: me });
      return send(ws, { type: 'call_ringing', to });
    }

    if (t === 'call_accept' || t === 'call_reject' || t === 'hangup') {
      const to = String(msg.to || '');
      const map = { call_accept: 'call_accepted', call_reject: 'call_rejected', hangup: 'hangup' };
      sendTo(to, { type: map[t], from: me });
      return;
    }

    if (t === 'signal') {
      const to = String(msg.to || '');
      if (!isFriend(me, to)) return; // signaling is strictly between friends
      if (isBlocked(to, me) || isBlocked(me, to)) return;
      sendTo(to, { type: 'signal', from: me, data: msg.data });
      return;
    }

    // ---- encrypted chat: relay only, never stored ----
    if (t === 'pubkey') {
      // client announces its ECDH public key; kept in memory while connected
      const key = String(msg.key || '');
      if (key.length > 20 && key.length < 500) pubkeys.set(me, key);
      return;
    }

    if (t === 'get_key') {
      const u = String(msg.username || '');
      const key = pubkeys.get(u);
      if (!key) return send(ws, { type: 'chat_key_error', username: u });
      return send(ws, { type: 'chat_key', username: u, key });
    }

    if (t === 'set_status') {
      const items = Array.isArray(msg.items) ? msg.items.slice(0, 200) : [];
      const exp = Date.now() + 24 * 3600 * 1000;
      for (const it of items) {
        const to = String((it && it.to) || '');
        if (!isFriend(me, to)) continue;
        if (isBlocked(to, me) || isBlocked(me, to)) continue;
        const entry = { iv: String(it.iv || ''), ct: String(it.ct || ''), exp };
        if (!statuses.has(to)) statuses.set(to, new Map());
        statuses.get(to).set(me, entry);
        sendTo(to, { type: 'status', from: me, iv: entry.iv, ct: entry.ct });
      }
      return send(ws, { type: 'status_ok' });
    }
    if (t === 'get_statuses') {
      const mine = statuses.get(me);
      const out = [];
      if (mine) {
        for (const [from, st] of mine) {
          if (st.exp > Date.now()) out.push({ from, iv: st.iv, ct: st.ct, secs: Math.max(1, Math.round((st.exp - Date.now()) / 1000)) });
        }
      }
      return send(ws, { type: 'statuses', items: out });
    }
    if (t === 'chat') {
      const to = String(msg.to || '');
      if (!isFriend(me, to)) return; // chat is strictly between friends
      if (isBlocked(to, me)) return send(ws, { type: 'chat_failed', id: msg.id, reason: 'blocked' });
      if (isBlocked(me, to)) return send(ws, { type: 'chat_failed', id: msg.id, reason: 'you_blocked' });
      if (!online.has(to)) {
        return send(ws, { type: 'chat_failed', id: msg.id, reason: 'offline' });
      }
      // relay ciphertext as-is; the server cannot read it and does not store it
      sendTo(to, {
        type: 'chat', from: me,
        id: String(msg.id || '').slice(0, 40),
        iv: String(msg.iv || ''),
        ct: String(msg.ct || '')
      });
      return;
    }
  });

  ws.on('close', () => {
    if (me && online.get(me) === ws) {
      online.delete(me);
      pubkeys.delete(me);
      notifyFriends(me, { type: 'presence', username: me, online: false });
    }
  });
});

// ---------- HTTP: health + admin ----------
function readBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(b));
  });
}

const ADMIN_PAGE = `<!DOCTYPE html>
<html dir="rtl" lang="ar"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>آمن — لوحة الأدمن</title>
<style>
  body{font-family:sans-serif;background:#0F172A;color:#F1F5F9;padding:24px;max-width:800px;margin:auto}
  h1{color:#22C55E} input{background:#1E293B;border:1px solid #334155;color:#F1F5F9;padding:10px;border-radius:8px}
  button{background:#22C55E;color:#0F172A;border:none;padding:10px 16px;border-radius:8px;font-weight:700;cursor:pointer}
  button.del{background:#EF4444;color:#fff;padding:6px 12px;font-size:13px}
  table{width:100%;border-collapse:collapse;margin-top:20px}
  td,th{border-bottom:1px solid #1E293B;padding:10px;text-align:right;font-size:14px}
  .on{color:#22C55E}.off{color:#64748B}
</style></head><body>
<h1>🔒 آمن — لوحة الأدمن</h1>
<div style="display:flex;gap:10px;margin-top:16px">
  <input id="tok" placeholder="رمز الأدمن (ADMIN_TOKEN)" style="flex:1">
  <button onclick="loadUsers()">عرض المستخدمين</button>
</div>
<div id="out"></div>
<script>
const tok = () => document.getElementById('tok').value;
async function loadUsers() {
  const r = await fetch('/api/admin/users?token=' + encodeURIComponent(tok()));
  if (r.status !== 200) { document.getElementById('out').innerHTML = '<p style="color:#EF4444">رمز غلط أو خطأ في السيرفر</p>'; return; }
  const users = await r.json();
  let h = '<table><tr><th>اسم المستخدم</th><th>تاريخ التسجيل</th><th>أصدقاء</th><th>الحالة</th><th></th></tr>';
  for (const u of users) {
    h += '<tr><td>' + u.username + '</td><td>' + (u.created||'').slice(0,10) + '</td><td>' + u.friendCount + '</td>' +
         '<td class="' + (u.online?'on':'off') + '">' + (u.online?'متصل':'غير متصل') + '</td>' +
         '<td><button class="del" onclick="delUser(\\'' + u.username + '\\')">حذف</button></td></tr>';
  }
  document.getElementById('out').innerHTML = h + '</table><p style="color:#64748B;font-size:13px">عدد المستخدمين: ' + users.length + '</p>';
}
async function delUser(u) {
  if (!confirm('حذف المستخدم ' + u + '؟')) return;
  await fetch('/api/admin/delete', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({token: tok(), username: u})});
  loadUsers();
}
</script></body></html>`;

async function handleHttp(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  if (url.pathname === '/version') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('5');
  }
  if (url.pathname === '/admin') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(ADMIN_PAGE);
  }
  if (url.pathname === '/api/admin/users') {
    if (url.searchParams.get('token') !== ADMIN_TOKEN) {
      res.writeHead(403); return res.end('forbidden');
    }
    const users = Object.keys(db.users).map(u => ({
      username: u,
      created: db.users[u].created,
      friendCount: (db.friends[u] || []).length,
      online: online.has(u)
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(users));
  }
  if (url.pathname === '/api/admin/delete' && req.method === 'POST') {
    const body = await readBody(req);
    let data; try { data = JSON.parse(body); } catch { data = {}; }
    if (data.token !== ADMIN_TOKEN) { res.writeHead(403); return res.end('forbidden'); }
    const u = String(data.username || '');
    if (db.users[u]) {
      delete db.users[u];
      (db.friends[u] || []).forEach(f => {
        db.friends[f] = (db.friends[f] || []).filter(x => x !== u);
      });
      delete db.friends[u];
      delete db.requests[u];
      Object.keys(db.requests).forEach(k => {
        db.requests[k] = (db.requests[k] || []).filter(x => x !== u);
      });
      const ws = online.get(u);
      if (ws) { try { ws.close(); } catch {} online.delete(u); }
      save();
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end('{"ok":true}');
  }
  res.writeHead(404); res.end('not found');
}

server.listen(PORT, () => {
  console.log('Aman server listening on port ' + PORT);
  console.log('Admin page: http://localhost:' + PORT + '/admin');
});
