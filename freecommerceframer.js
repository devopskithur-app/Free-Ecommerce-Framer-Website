/*
devopskithur - AmaXon free app
File: Untitled-1
A single-file Node.js web app "AmaXon free app" with sign-up, sign-in, product listing, cart, and checkout.
Run: node Untitled-1
Requires: Node 12+
*/

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, '.amaxon_data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');
const ORDERS_FILE = path.join(DATA_DIR, 'orders.json');

const APP_NAME = 'AmaXon free app';
const TOKEN_COOKIE = 'amaxon_token';
const TOKEN_SECRET = process.env.AMAXON_SECRET || 'dev_secret_change_me';
const TOKEN_TTL = 1000 * 60 * 60 * 24 * 7; // 7 days

function readJSON(file, fallback) {
    try {
        if (!fs.existsSync(file)) return fallback;
        return JSON.parse(fs.readFileSync(file, 'utf8') || 'null') || fallback;
    } catch (e) {
        return fallback;
    }
}
function writeJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

let users = readJSON(USERS_FILE, []);
let sessions = readJSON(SESSIONS_FILE, {});
let products = readJSON(PRODUCTS_FILE, null);
let orders = readJSON(ORDERS_FILE, []);

if (!products) {
    products = [
        { id: 'p1', title: 'Wireless Headphones', price: 49.99, img: '', desc: 'Comfortable over-ear Bluetooth.' },
        { id: 'p2', title: 'Smartwatch', price: 79.99, img: '', desc: 'Notifications, fitness tracking.' },
        { id: 'p3', title: 'USB-C Charger', price: 19.99, img: '', desc: 'Fast 30W charging.' },
    ];
    writeJSON(PRODUCTS_FILE, products);
}
writeJSON(USERS_FILE, users);
writeJSON(SESSIONS_FILE, sessions);
writeJSON(ORDERS_FILE, orders);

function hashPassword(password, salt = null) {
    salt = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return { salt, hash };
}
function verifyPassword(password, salt, hash) {
    return hashPassword(password, salt).hash === hash;
}
function makeToken(userId) {
    const ts = Date.now();
    const payload = `${userId}.${ts}`;
    const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
    return `${payload}.${sig}`;
}
function verifyToken(token) {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [userId, ts, sig] = parts;
    const payload = `${userId}.${ts}`;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
    if (expected !== sig) return null;
    const t = parseInt(ts, 10);
    if (isNaN(t)) return null;
    if (Date.now() - t > TOKEN_TTL) return null;
    return userId;
}

function saveAll() {
    writeJSON(USERS_FILE, users);
    writeJSON(SESSIONS_FILE, sessions);
    writeJSON(PRODUCTS_FILE, products);
    writeJSON(ORDERS_FILE, orders);
}

/* Helper to parse body */
function parseBody(req) {
    return new Promise((res, rej) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
            const ct = (req.headers['content-type'] || '').split(';')[0];
            if (ct === 'application/json') {
                try { res(JSON.parse(body || '{}')); } catch (e) { res({}); }
            } else {
                // parse urlencoded
                const obj = {};
                body.split('&').forEach((pair) => {
                    if (!pair) return;
                    const [k, v] = pair.split('=');
                    obj[decodeURIComponent(k)] = decodeURIComponent(v || '');
                });
                res(obj);
            }
        });
        req.on('error', rej);
    });
}

/* Simple HTML templates */
function page(title, body, user) {
    return `<!doctype html>
<html>
<head>
    <meta charset="utf-8" />
    <title>${APP_NAME} - ${title}</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <style>
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; margin:0; padding:0; background:#f6f6f8;}
        header{background:#141414; color:#fff; padding:12px 18px; display:flex; align-items:center; justify-content:space-between;}
        a{color:#06f;text-decoration:none}
        .container{max-width:980px;margin:18px auto;padding:12px;}
        .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
        .card{background:#fff;padding:12px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.06)}
        button{background:#06f;color:#fff;border:none;padding:8px 10px;border-radius:6px;cursor:pointer}
        input, select{padding:8px;margin:6px 0;width:100%}
        form{max-width:420px;background:#fff;padding:12px;border-radius:8px}
        .toplinks a{margin-left:12px;color:#fff}
        .small{font-size:13px;color:#666}
    </style>
</head>
<body>
<header>
    <div><strong>${APP_NAME}</strong></div>
    <div class="toplinks">
        <a href="/">Shop</a>
        <a href="/cart">Cart</a>
        ${user ? `<a href="/orders">Orders</a><span style="margin-left:12px">Hi ${escapeHtml(user.name || user.email)}</span> <a href="/signout">Sign out</a>` : `<a href="/signin">Sign in</a><a href="/signup">Sign up</a>`}
    </div>
</header>
<div class="container">
    ${body}
</div>
</body>
</html>`;
}

function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/[&<>"']/g, (m) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

/* Routes content */
function indexPage(user) {
    return page('Shop', `
    <h2>Products</h2>
    <div id="products" class="grid"></div>
    <script>
        async function load(){ 
            const res = await fetch('/api/products'); 
            const products = await res.json();
            const el = document.getElementById('products');
            el.innerHTML = products.map(p => \`<div class="card"><h3>\${p.title}</h3><p class="small">\${p.desc}</p><p><strong>\${p.price.toFixed(2)} USD</strong></p><p><button onclick="add('\${p.id}')">Add to cart</button></p></div>\`).join('');
        }
        async function add(id){
            const res = await fetch('/api/cart/add', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({productId:id,quantity:1})});
            const json = await res.json();
            if (res.ok) alert('Added to cart');
            else if (json && json.error) alert('Error: '+json.error);
            else alert('Sign in to add to cart');
        }
        load();
    </script>
    `, user);
}

function signupPage() {
    return page('Sign up', `
    <h2>Create account</h2>
    <form id="f">
        <label>Name</label><input name="name" required />
        <label>Email</label><input name="email" type="email" required />
        <label>Password</label><input name="password" type="password" required />
        <button type="submit">Sign up</button>
        <p class="small">Already have an account? <a href="/signin">Sign in</a></p>
    </form>
    <script>
        document.getElementById('f').onsubmit = async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const body = { name: fd.get('name'), email: fd.get('email'), password: fd.get('password') };
            const res = await fetch('/signup', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)});
            const json = await res.json();
            if (res.ok) location = '/';
            else alert(json.error || 'Error');
        }
    </script>
    `, null);
}

function signinPage() {
    return page('Sign in', `
    <h2>Sign in</h2>
    <form id="f">
        <label>Email</label><input name="email" type="email" required />
        <label>Password</label><input name="password" type="password" required />
        <button type="submit">Sign in</button>
        <p class="small">No account? <a href="/signup">Create one</a></p>
    </form>
    <script>
        document.getElementById('f').onsubmit = async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const body = { email: fd.get('email'), password: fd.get('password') };
            const res = await fetch('/signin', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)});
            const json = await res.json();
            if (res.ok) location = '/';
            else alert(json.error || 'Invalid');
        }
    </script>
    `, null);
}

function cartPage(user, cart) {
    const rows = (cart || []).map(item => {
        const p = products.find(x => x.id === item.productId) || { title: 'Unknown', price: 0 };
        return `<div class="card"><strong>${escapeHtml(p.title)}</strong><p class="small">${escapeHtml(p.desc||'')}</p><p>${(p.price*item.quantity).toFixed(2)} USD &nbsp; <small>Qty: ${item.quantity}</small></p></div>`;
    }).join('');
    return page('Cart', `
    <h2>Your cart</h2>
    <div id="cart">${rows || '<p>Cart is empty</p>'}</div>
    <div style="margin-top:12px">
        <button id="checkout">Checkout</button>
    </div>
    <script>
        document.getElementById('checkout').onclick = async () => {
            const res = await fetch('/api/checkout', { method:'POST' });
            const json = await res.json();
            if (res.ok) { alert('Order placed'); location='/orders' }
            else alert(json.error || 'Sign in to checkout');
        }
    </script>
    `, user);
}

function ordersPage(user, userOrders) {
    const rows = userOrders.map(o => `<div class="card"><strong>Order ${o.id}</strong><p class="small">Total: ${o.total.toFixed(2)} USD</p><p class="small">Placed: ${new Date(o.created).toLocaleString()}</p></div>`).join('') || '<p>No orders</p>';
    return page('Orders', `<h2>Your orders</h2>${rows}`, user);
}

/* Cookie helper */
function parseCookies(req) {
    const c = req.headers.cookie || '';
    const out = {};
    c.split(';').forEach(pair => {
        const idx = pair.indexOf('=');
        if (idx<0) return;
        const k = pair.slice(0, idx).trim();
        const v = pair.slice(idx+1).trim();
        out[k] = decodeURIComponent(v);
    });
    return out;
}

/* Server */
const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const pathname = url.pathname;
        const cookies = parseCookies(req);
        const token = cookies[TOKEN_COOKIE];
        const userId = verifyToken(token);
        const user = userId ? users.find(u=>u.id===userId) : null;
        // Static simple routes
        if (req.method === 'GET' && pathname === '/') {
            res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
            res.end(indexPage(user));
            return;
        }
        if (req.method === 'GET' && pathname === '/signup') {
            res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
            res.end(signupPage());
            return;
        }
        if (req.method === 'GET' && pathname === '/signin') {
            res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
            res.end(signinPage());
            return;
        }
        if (req.method === 'GET' && pathname === '/signout') {
            // clear cookie
            const headers = { 'Set-Cookie': `${TOKEN_COOKIE}=; HttpOnly; Path=/; Max-Age=0`, 'Content-Type':'text/plain' };
            res.writeHead(302, {...headers, Location: '/'});
            res.end('Signed out');
            return;
        }
        if (req.method === 'GET' && pathname === '/cart') {
            let cart = [];
            if (user) {
                sessions[token] = sessions[token] || { userId: user.id, cart: [] };
                cart = sessions[token].cart || [];
            }
            res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
            res.end(cartPage(user, cart));
            return;
        }
        if (req.method === 'GET' && pathname === '/orders') {
            if (!user) {
                res.writeHead(302, {'Location':'/signin'});
                res.end();
                return;
            }
            const userOrders = orders.filter(o => o.userId === user.id);
            res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
            res.end(ordersPage(user, userOrders));
            return;
        }

        // API endpoints
        if (pathname === '/api/products' && req.method === 'GET') {
            res.writeHead(200, {'Content-Type':'application/json'});
            res.end(JSON.stringify(products));
            return;
        }

        if (pathname === '/signup' && req.method === 'POST') {
            const body = await parseBody(req);
            const email = (body.email || '').toLowerCase();
            const name = (body.name || '').trim();
            const password = body.password || '';
            if (!email || !password) {
                res.writeHead(400, {'Content-Type':'application/json'});
                res.end(JSON.stringify({ error: 'Missing email or password' }));
                return;
            }
            if (users.some(u => u.email === email)) {
                res.writeHead(400, {'Content-Type':'application/json'});
                res.end(JSON.stringify({ error: 'Email in use' }));
                return;
            }
            const { salt, hash } = hashPassword(password);
            const id = 'u' + crypto.randomBytes(8).toString('hex');
            const u = { id, email, salt, hash, name };
            users.push(u);
            saveAll();
            // auto sign-in
            const t = makeToken(id);
            sessions[t] = { userId: id, cart: [] };
            saveAll();
            res.writeHead(200, {'Set-Cookie': `${TOKEN_COOKIE}=${encodeURIComponent(t)}; HttpOnly; Path=/; Max-Age=${TOKEN_TTL/1000}`, 'Content-Type':'application/json'});
            res.end(JSON.stringify({ ok: true }));
            return;
        }

        if (pathname === '/signin' && req.method === 'POST') {
            const body = await parseBody(req);
            const email = (body.email || '').toLowerCase();
            const password = body.password || '';
            const u = users.find(x => x.email === email);
            if (!u || !verifyPassword(password, u.salt, u.hash)) {
                res.writeHead(400, {'Content-Type':'application/json'});
                res.end(JSON.stringify({ error: 'Invalid credentials' }));
                return;
            }
            const t = makeToken(u.id);
            sessions[t] = sessions[t] || { userId: u.id, cart: [] };
            saveAll();
            res.writeHead(200, {'Set-Cookie': `${TOKEN_COOKIE}=${encodeURIComponent(t)}; HttpOnly; Path=/; Max-Age=${TOKEN_TTL/1000}`, 'Content-Type':'application/json'});
            res.end(JSON.stringify({ ok: true }));
            return;
        }

        if (pathname === '/api/cart/add' && req.method === 'POST') {
            const body = await parseBody(req);
            if (!user) {
                res.writeHead(401, {'Content-Type':'application/json'});
                res.end(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }
            const productId = body.productId;
            const qty = Math.max(1, parseInt(body.quantity || 1, 10));
            const prod = products.find(p => p.id === productId);
            if (!prod) {
                res.writeHead(400, {'Content-Type':'application/json'});
                res.end(JSON.stringify({ error: 'Product not found' }));
                return;
            }
            // ensure session exists for token
            sessions[token] = sessions[token] || { userId: user.id, cart: [] };
            const cart = sessions[token].cart;
            const item = cart.find(i => i.productId === productId);
            if (item) item.quantity += qty; else cart.push({ productId, quantity: qty });
            saveAll();
            res.writeHead(200, {'Content-Type':'application/json'});
            res.end(JSON.stringify({ ok: true }));
            return;
        }

        if (pathname === '/api/cart/remove' && req.method === 'POST') {
            const body = await parseBody(req);
            if (!user) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }
            const productId = body.productId;
            sessions[token] = sessions[token] || { userId: user.id, cart: [] };
            sessions[token].cart = sessions[token].cart.filter(i=>i.productId !== productId);
            saveAll();
            res.writeHead(200, {'Content-Type':'application/json'}); res.end(JSON.stringify({ ok:true })); return;
        }

        if (pathname === '/api/checkout' && req.method === 'POST' || pathname === '/api/checkout' && req.method === 'GET') {
            if (!user) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }
            sessions[token] = sessions[token] || { userId: user.id, cart: [] };
            const cart = sessions[token].cart || [];
            if (!cart.length) { res.writeHead(400, {'Content-Type':'application/json'}); res.end(JSON.stringify({ error: 'Cart empty' })); return; }
            // compute total
            let total = 0;
            const items = cart.map(i => {
                const p = products.find(x => x.id === i.productId) || { price: 0 };
                const price = p.price || 0;
                total += price * i.quantity;
                return { productId: i.productId, quantity: i.quantity, price };
            });
            const order = { id: 'o' + crypto.randomBytes(8).toString('hex'), userId: user.id, items, total, created: Date.now() };
            orders.push(order);
            // clear cart
            sessions[token].cart = [];
            saveAll();
            res.writeHead(200, {'Content-Type':'application/json'});
            res.end(JSON.stringify({ ok: true, orderId: order.id }));
            return;
        }

        // simple API to get session cart
        if (pathname === '/api/cart' && req.method === 'GET') {
            if (!user) { res.writeHead(200, {'Content-Type':'application/json'}); res.end(JSON.stringify([])); return; }
            sessions[token] = sessions[token] || { userId: user.id, cart: [] };
            res.writeHead(200, {'Content-Type':'application/json'});
            res.end(JSON.stringify(sessions[token].cart || []));
            return;
        }

        // serve favicon or unknown
        if (pathname === '/favicon.ico') { res.writeHead(204); res.end(); return; }

        // fallback 404
        res.writeHead(404, {'Content-Type':'text/plain'});
        res.end('Not found');
    } catch (err) {
        console.error('ERR', err);
        res.writeHead(500, {'Content-Type':'application/json'});
        res.end(JSON.stringify({ error: 'Server error' }));
    }
});

process.on('SIGINT', ()=>{ saveAll(); process.exit(); });
process.on('exit', ()=>{ saveAll(); });

server.listen(PORT, ()=> {
    console.log(`${APP_NAME} running at http://localhost:${PORT}/`);
});