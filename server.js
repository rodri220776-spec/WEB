const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const port = process.env.PORT || 3000;
const demoMode = process.env.DEMO_MODE === 'true' || process.env.NODE_ENV !== 'production';
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const database = new DatabaseSync(path.join(__dirname, 'data', 'correoseguro.db'));

database.exec('PRAGMA journal_mode = WAL');
database.exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		password_salt TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS email_verifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		code_hash TEXT NOT NULL,
		code_salt TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS payments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		amount_cents INTEGER NOT NULL,
		currency TEXT NOT NULL,
		status TEXT NOT NULL,
		provider_reference TEXT,
		card_last4 TEXT,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS subscriptions (
		user_id INTEGER PRIMARY KEY,
		status TEXT NOT NULL,
		payment_method TEXT NOT NULL,
		current_period_start INTEGER NOT NULL,
		current_period_end INTEGER NOT NULL,
		updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_user_id INTEGER NOT NULL,
		recipient_user_id INTEGER NOT NULL,
		sender_email TEXT NOT NULL,
		recipient_email TEXT NOT NULL,
		subject TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS mailbox_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		message_id INTEGER NOT NULL,
		folder TEXT NOT NULL CHECK (folder IN ('inbox', 'sent', 'archived')),
		archived_from TEXT,
		is_read INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (user_id, message_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
	);
`);
if (!database.prepare('PRAGMA table_info(payments)').all().some((column) => column.name === 'payment_method')) database.exec("ALTER TABLE payments ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'legacy'");

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

app.get('/api/database', (request, response) => {
	if (process.env.NODE_ENV === 'production' || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.ip)) return response.status(403).json({ error: 'Vista disponible solo en desarrollo local.' });
	response.json({
		users: database.prepare('SELECT id, name, email, verified, created_at FROM users ORDER BY id DESC').all(),
		payments: database.prepare('SELECT payments.id, users.email, payments.amount_cents, payments.currency, payments.status, payments.payment_method, payments.provider_reference, payments.created_at FROM payments JOIN users ON users.id = payments.user_id ORDER BY payments.id DESC').all(),
		sessions: database.prepare('SELECT sessions.rowid AS session_id, sessions.user_id, users.email, datetime(sessions.expires_at / 1000, \'unixepoch\') AS expires_at FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.expires_at > ? ORDER BY sessions.expires_at DESC').all(Date.now()),
		verifications: database.prepare('SELECT users.email, datetime(email_verifications.expires_at / 1000, \'unixepoch\') AS expires_at FROM email_verifications JOIN users ON users.id = email_verifications.user_id ORDER BY email_verifications.id DESC').all()
	});
});

const requireLocalAdmin = (request, response, next) => {
	if (process.env.NODE_ENV === 'production' || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.ip)) return response.status(403).json({ error: 'Operación disponible solo en desarrollo local.' });
	next();
};

app.delete('/api/database/users/:id', requireLocalAdmin, (request, response) => {
	const userId = Number(request.params.id);
	if (!Number.isInteger(userId) || userId < 1) return response.status(400).json({ error: 'Identificador de usuario no válido.' });
	const user = database.prepare('SELECT id FROM users WHERE id = ?').get(userId);
	if (!user) return response.status(404).json({ error: 'Usuario no encontrado.' });
	database.prepare('DELETE FROM payments WHERE user_id = ?').run(userId);
	database.prepare('DELETE FROM subscriptions WHERE user_id = ?').run(userId);
	database.prepare('DELETE FROM mailbox_items WHERE user_id = ? OR message_id IN (SELECT id FROM messages WHERE sender_user_id = ? OR recipient_user_id = ?)').run(userId, userId, userId);
	database.prepare('DELETE FROM messages WHERE sender_user_id = ? OR recipient_user_id = ?').run(userId, userId);
	database.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(userId);
	database.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
	database.prepare('DELETE FROM users WHERE id = ?').run(userId);
	response.json({ ok: true });
});

app.delete('/api/database/sessions/:id', requireLocalAdmin, (request, response) => {
	const sessionId = Number(request.params.id);
	if (!Number.isInteger(sessionId) || sessionId < 1) return response.status(400).json({ error: 'Identificador de sesión no válido.' });
	const result = database.prepare('DELETE FROM sessions WHERE rowid = ?').run(sessionId);
	if (!result.changes) return response.status(404).json({ error: 'Sesión no encontrada o ya cerrada.' });
	response.json({ ok: true });
});

app.delete('/api/database/payments/:id', requireLocalAdmin, (request, response) => {
	const paymentId = Number(request.params.id);
	if (!Number.isInteger(paymentId) || paymentId < 1) return response.status(400).json({ error: 'Identificador de pago no válido.' });
	const result = database.prepare('DELETE FROM payments WHERE id = ?').run(paymentId);
	if (!result.changes) return response.status(404).json({ error: 'Pago no encontrado.' });
	response.json({ ok: true });
});

const hash = (value, salt = crypto.randomBytes(16).toString('hex')) => ({
	salt,
	hash: crypto.scryptSync(value, salt, 64).toString('hex')
});
const matches = (value, expected, salt) => crypto.timingSafeEqual(Buffer.from(hash(value, salt).hash, 'hex'), Buffer.from(expected, 'hex'));
const tokenHash = (token) => crypto.createHash('sha256').update(token).digest('hex');
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const makeCode = () => String(crypto.randomInt(100000, 1000000));
const makeSession = (userId, response) => {
	const token = crypto.randomBytes(32).toString('hex');
	database.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(tokenHash(token), userId, Date.now() + 7 * 24 * 60 * 60 * 1000);
	const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
	response.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}${secure}`);
};
const currentUser = (request) => {
	const token = request.cookies.session;
	if (!token) return null;
	return database.prepare(`SELECT users.id, users.name, users.email FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?`).get(tokenHash(token), Date.now()) || null;
};
const requireUser = (request, response, next) => {
	const user = currentUser(request);
	if (!user) return response.status(401).json({ error: 'Sesión no válida o expirada.' });
	request.user = user;
	next();
};
const requireActivePlan = (request, response, next) => {
	const subscription = database.prepare('SELECT status, current_period_end FROM subscriptions WHERE user_id = ?').get(request.user.id);
	if (subscription?.status === 'active' && subscription.current_period_end > Date.now()) return next();
	if (subscription?.status === 'active') database.prepare("UPDATE subscriptions SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE user_id = ?").run(request.user.id);
	return response.status(403).json({ error: 'Necesitas un plan Plus activo para usar el correo.' });
};

app.post('/api/register', (request, response) => {
	const name = String(request.body.name || '').trim();
	const email = normalizeEmail(request.body.email);
	const password = String(request.body.password || '');
	if (!name || !email.includes('@') || password.length < 8) return response.status(400).json({ error: 'Completa los datos con un correo válido y una contraseña de 8 caracteres.' });
	if (database.prepare('SELECT id FROM users WHERE email = ?').get(email)) return response.status(409).json({ error: 'Este correo ya está registrado. Inicia sesión.' });
	const passwordData = hash(password);
	const result = database.prepare('INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)').run(name, email, passwordData.hash, passwordData.salt);
	const code = makeCode();
	const codeData = hash(code);
	database.prepare('INSERT INTO email_verifications (user_id, code_hash, code_salt, expires_at) VALUES (?, ?, ?, ?)').run(result.lastInsertRowid, codeData.hash, codeData.salt, Date.now() + 15 * 60 * 1000);
	response.status(201).json({ email, demoCode: process.env.NODE_ENV === 'production' && !demoMode ? undefined : code });
});

app.post('/api/verify', (request, response) => {
	const email = normalizeEmail(request.body.email);
	const verification = database.prepare('SELECT email_verifications.*, users.id FROM email_verifications JOIN users ON users.id = email_verifications.user_id WHERE users.email = ? ORDER BY email_verifications.id DESC').get(email);
	if (!verification || verification.expires_at < Date.now() || !matches(String(request.body.code || ''), verification.code_hash, verification.code_salt)) return response.status(400).json({ error: 'El código no coincide o ha caducado.' });
	database.prepare('UPDATE users SET verified = 1 WHERE id = ?').run(verification.user_id);
	database.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(verification.user_id);
	response.json({ ok: true });
});

app.post('/api/resend-code', (request, response) => {
	const email = normalizeEmail(request.body.email);
	const user = database.prepare('SELECT id FROM users WHERE email = ? AND verified = 0').get(email);
	if (!user) return response.status(404).json({ error: 'No hay una verificación pendiente para ese correo.' });
	const code = makeCode();
	const codeData = hash(code);
	database.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(user.id);
	database.prepare('INSERT INTO email_verifications (user_id, code_hash, code_salt, expires_at) VALUES (?, ?, ?, ?)').run(user.id, codeData.hash, codeData.salt, Date.now() + 15 * 60 * 1000);
	response.json({ demoCode: process.env.NODE_ENV === 'production' && !demoMode ? undefined : code });
});

app.post('/api/login', (request, response) => {
	const email = normalizeEmail(request.body.email);
	const user = database.prepare('SELECT * FROM users WHERE email = ?').get(email);
	if (!user || !matches(String(request.body.password || ''), user.password_hash, user.password_salt)) return response.status(401).json({ error: 'El correo o la contraseña no son correctos.' });
	if (!user.verified) return response.status(403).json({ error: 'Confirma tu correo antes de iniciar sesión.', needsVerification: true, email });
	makeSession(user.id, response);
	response.json({ user: { name: user.name, email: user.email } });
});

app.get('/api/me', requireUser, (request, response) => response.json({ user: request.user }));
app.post('/api/logout', (request, response) => {
	const token = request.cookies.session;
	if (token) database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(token));
	response.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
	response.json({ ok: true });
});

app.post('/api/payments', requireUser, (request, response) => {
	if (!demoMode) return response.status(503).json({ error: 'No hay ningún proveedor de pagos real configurado.' });
	const method = String(request.body.method || '').toLowerCase();
	const value = String(request.body.value || '').replace(/\s/g, '');
	if (!['bizum', 'paypal'].includes(method) || (method === 'bizum' && !/^\+?\d{9,15}$/.test(value)) || (method === 'paypal' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))) return response.status(400).json({ error: 'Los datos de Bizum o PayPal no son válidos.' });
	const now = Date.now();
	const existingPlan = database.prepare('SELECT status, current_period_end FROM subscriptions WHERE user_id = ?').get(request.user.id);
	if (existingPlan?.status === 'active' && existingPlan.current_period_end > now) return response.status(409).json({ error: 'Tu plan Plus ya está activo.' });
	const reference = crypto.randomUUID();
	const periodEnd = now + 30 * 24 * 60 * 60 * 1000;
	database.exec('BEGIN IMMEDIATE');
	try {
		database.prepare('INSERT INTO payments (user_id, amount_cents, currency, status, payment_method, provider_reference) VALUES (?, ?, ?, ?, ?, ?)').run(request.user.id, 499, 'EUR', 'approved', method, reference);
		database.prepare(`INSERT INTO subscriptions (user_id, status, payment_method, current_period_start, current_period_end, updated_at) VALUES (?, 'active', ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET status = 'active', payment_method = excluded.payment_method, current_period_start = excluded.current_period_start, current_period_end = excluded.current_period_end, updated_at = CURRENT_TIMESTAMP`).run(request.user.id, method, now, periodEnd);
		database.exec('COMMIT');
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
	response.status(201).json({ status: 'approved', reference, subscription: { status: 'active', current_period_end: periodEnd } });
});

app.get('/api/payments', requireUser, (request, response) => response.json({ payments: database.prepare('SELECT amount_cents, currency, status, payment_method, provider_reference, created_at FROM payments WHERE user_id = ? ORDER BY id DESC').all(request.user.id) }));

app.get('/api/plan', requireUser, (request, response) => {
	let subscription = database.prepare('SELECT status, payment_method, current_period_start, current_period_end FROM subscriptions WHERE user_id = ?').get(request.user.id) || null;
	if (subscription?.status === 'active' && subscription.current_period_end <= Date.now()) {
		database.prepare("UPDATE subscriptions SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE user_id = ?").run(request.user.id);
		subscription = database.prepare('SELECT status, payment_method, current_period_start, current_period_end FROM subscriptions WHERE user_id = ?').get(request.user.id);
	}
	response.json({ subscription });
});

app.post('/api/plan/cancel', requireUser, (request, response) => {
	const result = database.prepare("UPDATE subscriptions SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND status = 'active' AND current_period_end > ?").run(request.user.id, Date.now());
	if (!result.changes) return response.status(409).json({ error: 'No hay un plan activo que cancelar.' });
	response.json({ ok: true });
});

app.get('/api/messages', requireUser, requireActivePlan, (request, response) => {
	const folder = String(request.query.folder || 'inbox');
	if (!['inbox', 'sent', 'archived'].includes(folder)) return response.status(400).json({ error: 'Carpeta de correo no válida.' });
	const messages = database.prepare(`SELECT mailbox_items.id, mailbox_items.folder, mailbox_items.is_read, messages.sender_email, messages.recipient_email, messages.subject, messages.body, messages.created_at FROM mailbox_items JOIN messages ON messages.id = mailbox_items.message_id WHERE mailbox_items.user_id = ? AND mailbox_items.folder = ? ORDER BY messages.id DESC`).all(request.user.id, folder);
	response.json({ messages });
});

app.post('/api/messages', requireUser, requireActivePlan, (request, response) => {
	const recipientEmail = normalizeEmail(request.body.recipient);
	const subject = String(request.body.subject || '').trim();
	const body = String(request.body.body || '').trim();
	if (!recipientEmail.includes('@') || subject.length < 1 || subject.length > 160 || body.length < 1 || body.length > 10000) return response.status(400).json({ error: 'Indica un destinatario, un asunto y un mensaje válido (máximo 10.000 caracteres).' });
	const recipient = database.prepare('SELECT id, email FROM users WHERE email = ? AND verified = 1').get(recipientEmail);
	if (!recipient) return response.status(404).json({ error: 'Solo puedes enviar mensajes a cuentas registradas y verificadas en esta demo.' });
	if (recipient.id === request.user.id) return response.status(400).json({ error: 'Elige otra cuenta como destinataria.' });
	database.exec('BEGIN IMMEDIATE');
	try {
		const message = database.prepare('INSERT INTO messages (sender_user_id, recipient_user_id, sender_email, recipient_email, subject, body) VALUES (?, ?, ?, ?, ?, ?)').run(request.user.id, recipient.id, request.user.email, recipient.email, subject, body);
		const messageId = Number(message.lastInsertRowid);
		database.prepare("INSERT INTO mailbox_items (user_id, message_id, folder) VALUES (?, ?, 'sent')").run(request.user.id, messageId);
		database.prepare("INSERT INTO mailbox_items (user_id, message_id, folder) VALUES (?, ?, 'inbox')").run(recipient.id, messageId);
		database.exec('COMMIT');
		response.status(201).json({ ok: true, messageId });
	} catch (error) {
		database.exec('ROLLBACK');
		throw error;
	}
});

app.post('/api/messages/:id/read', requireUser, requireActivePlan, (request, response) => {
	const itemId = Number(request.params.id);
	if (!Number.isInteger(itemId) || itemId < 1) return response.status(400).json({ error: 'Identificador de mensaje no válido.' });
	const result = database.prepare("UPDATE mailbox_items SET is_read = 1 WHERE id = ? AND user_id = ? AND folder IN ('inbox', 'archived')").run(itemId, request.user.id);
	if (!result.changes) return response.status(404).json({ error: 'Mensaje no encontrado.' });
	response.json({ ok: true });
});

app.post('/api/messages/:id/archive', requireUser, requireActivePlan, (request, response) => {
	const itemId = Number(request.params.id);
	if (!Number.isInteger(itemId) || itemId < 1) return response.status(400).json({ error: 'Identificador de mensaje no válido.' });
	const result = database.prepare("UPDATE mailbox_items SET archived_from = folder, folder = 'archived' WHERE id = ? AND user_id = ? AND folder IN ('inbox', 'sent')").run(itemId, request.user.id);
	if (!result.changes) return response.status(404).json({ error: 'Mensaje no encontrado o ya archivado.' });
	response.json({ ok: true });
});

app.post('/api/messages/:id/restore', requireUser, requireActivePlan, (request, response) => {
	const itemId = Number(request.params.id);
	if (!Number.isInteger(itemId) || itemId < 1) return response.status(400).json({ error: 'Identificador de mensaje no válido.' });
	const result = database.prepare("UPDATE mailbox_items SET folder = COALESCE(archived_from, 'inbox'), archived_from = NULL WHERE id = ? AND user_id = ? AND folder = 'archived'").run(itemId, request.user.id);
	if (!result.changes) return response.status(404).json({ error: 'Mensaje archivado no encontrado.' });
	response.json({ ok: true });
});

app.listen(port, () => console.log(`CorreoSeguro disponible en http://localhost:${port}`));
