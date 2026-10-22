'use strict';

const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomBytes, randomInt, scryptSync, timingSafeEqual, createHmac } = require('node:crypto');

const ROOT = __dirname;
const PORT = Number(process.env.PORT) || 8000;
const MYSQL_COMMAND = process.env.MYSQL_COMMAND || 'mysql';
const MYSQL_LOGIN_PATH = process.env.MYSQL_LOGIN_PATH || 'zovya-local';
const DATABASE_NAME = process.env.ZOVYA_DB_NAME || 'zovya_gifts';

const passwordResetChallenges = new Map();
const passwordResetCooldown = new Map();
const otpSecret = randomBytes(32);
const loginSessions = new Map();
const LOGIN_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function runMysql(sql) {
    return new Promise((resolve, reject) => {
        const args = [
            '--login-path=' + MYSQL_LOGIN_PATH,
            '--database=' + DATABASE_NAME,
            '--batch',
            '--raw',
            '--skip-column-names',
            '--default-character-set=utf8mb4'
        ];
        const mysql = spawn(MYSQL_COMMAND, args, { stdio: ['pipe', 'pipe', 'pipe'] });
        let stdout = '';
        let stderr = '';

        mysql.stdout.setEncoding('utf8');
        mysql.stderr.setEncoding('utf8');
        mysql.stdout.on('data', chunk => { stdout += chunk; });
        mysql.stderr.on('data', chunk => { stderr += chunk; });
        mysql.stdin.on('error', () => {});

        mysql.on('error', error => reject(error));
        mysql.on('close', code => {
            if (code === 0) return resolve(stdout.trim());
            const error = new Error(stderr.trim() || 'MySQL command failed.');
            error.stderr = stderr;
            reject(error);
        });

        mysql.stdin.end(sql + '\n');
    });
}

function sqlText(value) {
    const base64 = Buffer.from(value, 'utf8').toString('base64');
    return "CONVERT(FROM_BASE64('" + base64 + "') USING utf8mb4)";
}

async function initializeDatabase() {
    const schema =
        'CREATE TABLE IF NOT EXISTS users (' +
        'id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, ' +
        'name VARCHAR(100) NOT NULL, ' +
        'email VARCHAR(254) NOT NULL UNIQUE, ' +
        'phone VARCHAR(24) NOT NULL, ' +
        'password_salt CHAR(32) NOT NULL, ' +
        'password_hash CHAR(128) NOT NULL, ' +
        'created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP' +
        ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;';
    await runMysql(schema);
}

const contentTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

function sendHtml(response, status, title, message, success) {
    const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);

    const color = success ? '#287a3b' : '#b00020';
    const html = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '  <meta charset="UTF-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '  <title>' + escapeHtml(title) + ' - ZOVYA_Gifts</title>',
        '  <style>',
        '    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#fff0f6;font-family:Arial,sans-serif;padding:20px;box-sizing:border-box}',
        '    main{max-width:420px;background:#fff;padding:32px;border-radius:12px;text-align:center;box-shadow:0 5px 25px rgba(0,0,0,.12)}',
        '    h1{color:' + color + ';font-size:25px}',
        '    p{color:#555;line-height:1.6}',
        '    button{margin-top:12px;padding:12px 20px;border:0;border-radius:6px;background:#a0208b;color:#fff;font-size:16px;cursor:pointer}',
        '  </style>',
        '</head>',
        '<body><main>',
        '  <h1>' + escapeHtml(title) + '</h1>',
        '  <p>' + escapeHtml(message) + '</p>',
        '  <button type="button" onclick="history.back()">Go back</button>',
        '</main></body>',
        '</html>'
    ].join('\n');

    response.writeHead(status, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
    });
    response.end(html);
}

function sendJson(response, status, payload) {
    response.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store'
    });
    response.end(JSON.stringify(payload));
}

function getLoginSession(request) {
    const cookie = String(request.headers.cookie || '')
        .split(';')
        .map(part => part.trim())
        .find(part => part.startsWith('zovya_session='));
    if (!cookie) return null;

    const token = cookie.slice('zovya_session='.length);
    if (!/^[a-f0-9]{64}$/.test(token)) return null;
    const session = loginSessions.get(token);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        loginSessions.delete(token);
        return null;
    }
    return session;
}

function handleCurrentUser(request, response) {
    const session = getLoginSession(request);
    if (!session) return sendJson(response, 401, { authenticated: false });
    return sendJson(response, 200, {
        authenticated: true,
        user: { id: session.userId, name: session.name }
    });
}
function handleSignup(request, response) {
    let body = '';
    let tooLarge = false;

    request.on('data', chunk => {
        if (tooLarge) return;
        body += chunk.toString('utf8');
        if (Buffer.byteLength(body, 'utf8') > 8192) tooLarge = true;
    });

    request.on('end', async () => {
        if (tooLarge) {
            return sendHtml(response, 413, 'Signup failed', 'Signup details are too large.', false);
        }

        let data;
        try {
            const contentType = String(request.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
            if (contentType === 'application/x-www-form-urlencoded') {
                data = Object.fromEntries(new URLSearchParams(body));
            } else if (contentType === 'application/json') {
                data = JSON.parse(body);
            } else {
                return sendHtml(response, 415, 'Signup failed', 'Please submit the signup form again.', false);
            }
        } catch {
            return sendHtml(response, 400, 'Signup failed', 'Please check the signup details and try again.', false);
        }

        if (!data || typeof data !== 'object') {
            return sendHtml(response, 400, 'Signup failed', 'Please enter your signup details.', false);
        }

        const name = typeof data.name === 'string' ? data.name.trim() : '';
        const email = typeof data.email === 'string' ? data.email.trim().toLowerCase() : '';
        const phone = typeof data.phone === 'string' ? data.phone.trim() : '';
        const password = typeof data.password === 'string' ? data.password : '';
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const phoneDigits = phone.replace(/\D/g, '');

        if (name.length < 1 || name.length > 100) {
            return sendHtml(response, 400, 'Signup failed', 'Please enter a name up to 100 characters.', false);
        }
        if (email.length > 254 || !emailPattern.test(email)) {
            return sendHtml(response, 400, 'Signup failed', 'Please enter a valid email address.', false);
        }
        if (phoneDigits.length < 7 || phoneDigits.length > 15) {
            return sendHtml(response, 400, 'Signup failed', 'Please enter a valid phone number.', false);
        }
        if (password.length < 8) {
            return sendHtml(response, 400, 'Signup failed', 'Password must be at least 8 characters long.', false);
        }

        const salt = randomBytes(16).toString('hex');
        const passwordHash = scryptSync(password, salt, 64).toString('hex');
        const sql =
            'INSERT INTO users (name, email, phone, password_salt, password_hash) VALUES (' +
            sqlText(name) + ', ' +
            sqlText(email) + ', ' +
            sqlText(phone) + ', ' +
            sqlText(salt) + ', ' +
            sqlText(passwordHash) + '); SELECT LAST_INSERT_ID();';

        try {
            const result = await runMysql(sql);
            const userId = result.split(/\r?\n/).filter(Boolean).pop();
            if (!userId || !/^\d+$/.test(userId)) {
                throw new Error('MySQL did not return the new user ID.');
            }
            return sendHtml(
                response,
                201,
                'Account created',
                'Your unique User ID is ' + userId + '. Save this ID and use it with the same password to log in.',
                true
            );
        } catch (error) {
            if ((error.stderr || error.message).includes('ERROR 1062')) {
                return sendHtml(response, 409, 'Signup failed', 'An account with this email already exists.', false);
            }
            console.error('Could not save signup details:', error.message);
            return sendHtml(response, 500, 'Signup failed', 'Could not save your details. Please try again.', false);
        }
    });
}

function handleLogin(request, response) {
    let body = '';
    let tooLarge = false;

    request.on('data', chunk => {
        if (tooLarge) return;
        body += chunk.toString('utf8');
        if (Buffer.byteLength(body, 'utf8') > 8192) tooLarge = true;
    });

    request.on('end', async () => {
        if (tooLarge) {
            return sendHtml(response, 413, 'Login failed', 'Login details are too large.', false);
        }

        let data;
        try {
            const contentType = String(request.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
            if (contentType === 'application/x-www-form-urlencoded') {
                data = Object.fromEntries(new URLSearchParams(body));
            } else if (contentType === 'application/json') {
                data = JSON.parse(body);
            } else {
                return sendHtml(response, 415, 'Login failed', 'Please submit the login form again.', false);
            }
        } catch {
            return sendHtml(response, 400, 'Login failed', 'Please check your login details and try again.', false);
        }

        const userId = data && typeof data.userId === 'string' ? data.userId.trim() : '';
        const password = data && typeof data.password === 'string' ? data.password : '';
        if (!/^\d{1,20}$/.test(userId) || password.length === 0 || password.length > 1024) {
            return sendHtml(response, 400, 'Login failed', 'Enter your User ID and password.', false);
        }

        try {
            const result = await runMysql(
                'SELECT HEX(name), password_salt, password_hash FROM users WHERE id = ' + userId + ' LIMIT 1;'
            );
            const row = result.split(/\r?\n/).filter(Boolean)[0];
            if (!row) {
                return sendHtml(response, 401, 'Login failed', 'The User ID or password is incorrect.', false);
            }

            const [nameHex, salt, savedHash] = row.split('\t');
            const submittedHash = scryptSync(password, salt, 64);
            const savedHashBytes = Buffer.from(savedHash || '', 'hex');
            if (savedHashBytes.length !== submittedHash.length || !timingSafeEqual(submittedHash, savedHashBytes)) {
                return sendHtml(response, 401, 'Login failed', 'The User ID or password is incorrect.', false);
            }

            const name = Buffer.from(nameHex || '', 'hex').toString('utf8');
            const token = randomBytes(32).toString('hex');
            loginSessions.set(token, {
                userId,
                name,
                expiresAt: Date.now() + LOGIN_SESSION_TTL_MS
            });
            response.writeHead(303, {
                'Location': '/Account.HTML',
                'Set-Cookie': 'zovya_session=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800',
                'Cache-Control': 'no-store'
            });
            return response.end();
        } catch (error) {
            console.error('Could not verify login details:', error.message);
            return sendHtml(response, 500, 'Login failed', 'Could not check your details. Please try again.', false);
        }
    });
}
function readPostData(request) {
    return new Promise(resolve => {
        let body = '';
        let tooLarge = false;
        request.on('data', chunk => {
            if (tooLarge) return;
            body += chunk.toString('utf8');
            if (Buffer.byteLength(body, 'utf8') > 8192) tooLarge = true;
        });
        request.on('end', () => resolve({ body, tooLarge }));
    });
}

function parsePostData(request, body) {
    const contentType = String(request.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (contentType === 'application/x-www-form-urlencoded') {
        return Object.fromEntries(new URLSearchParams(body));
    }
    if (contentType === 'application/json') {
        return JSON.parse(body);
    }
    return null;
}

function maskEmail(email) {
    const at = email.indexOf('@');
    if (at < 1) return 'your registered email';
    return email.slice(0, 1) + '***' + email.slice(at);
}

function maskPhone(phone) {
    const digits = phone.replace(/\D/g, '');
    return '***' + digits.slice(-4);
}

function sendEmailOtp(email, otp) {
    const host = process.env.SMTP_HOST || 'smtp.gmail.com';
    const port = Number(process.env.SMTP_PORT) || 465;
    const username = process.env.SMTP_USER;
    const password = process.env.SMTP_PASS;
    const from = process.env.SMTP_FROM || username;
    if (!username || !password || !from) {
        return Promise.reject(new Error('Email OTP sender is not configured.'));
    }

    return new Promise((resolve, reject) => {
        const socket = tls.connect({ host, port, servername: host });
        let incoming = '';
        let partialLines = [];
        let completedResponses = [];
        let responseWaiter = null;
        let finished = false;

        const fail = error => {
            if (finished) return;
            finished = true;
            socket.destroy();
            reject(error);
        };

        const readResponse = () => {
            if (completedResponses.length) return Promise.resolve(completedResponses.shift());
            return new Promise(resolveResponse => {
                responseWaiter = { resolve: resolveResponse };
            });
        };

        socket.on('data', chunk => {
            incoming += chunk.toString('utf8');
            let newline;
            while ((newline = incoming.indexOf('\n')) !== -1) {
                const line = incoming.slice(0, newline).replace(/\r$/, '');
                incoming = incoming.slice(newline + 1);
                if (line) partialLines.push(line);
                if (/^\d{3} /.test(line)) {
                    const responseText = partialLines.join('\n');
                    partialLines = [];
                    if (responseWaiter) {
                        const waiter = responseWaiter;
                        responseWaiter = null;
                        waiter.resolve(responseText);
                    } else {
                        completedResponses.push(responseText);
                    }
                }
            }
        });
        socket.on('error', fail);
        socket.setTimeout(15000, () => fail(new Error('SMTP connection timed out.')));

        socket.once('secureConnect', async () => {
            const command = async (text, acceptedCodes) => {
                if (text) socket.write(text + '\r\n');
                const responseText = await readResponse();
                const lastLine = responseText.split('\n').pop();
                const code = lastLine.slice(0, 3);
                if (!acceptedCodes.includes(code)) {
                    throw new Error('SMTP rejected a command: ' + lastLine);
                }
            };

            try {
                await command(null, ['220']);
                await command('EHLO zovya.local', ['250']);
                const auth = Buffer.from('\0' + username + '\0' + password).toString('base64');
                await command('AUTH PLAIN ' + auth, ['235']);
                await command('MAIL FROM:<' + from + '>', ['250']);
                await command('RCPT TO:<' + email + '>', ['250', '251']);
                await command('DATA', ['354']);

                const message = [
                    'From: ZOVYA Gifts <' + from + '>',
                    'To: ' + email,
                    'Subject: Your ZOVYA password reset code',
                    'MIME-Version: 1.0',
                    'Content-Type: text/plain; charset=UTF-8',
                    'Content-Transfer-Encoding: 8bit',
                    '',
                    'Your ZOVYA password reset code is ' + otp + '.',
                    'It expires in 10 minutes. If you did not request this, ignore this email.'
                ].join('\r\n').replace(/^\./gm, '..');
                socket.write(message + '\r\n.\r\n');
                await command(null, ['250']);
                await command('QUIT', ['221']);
                finished = true;
                socket.end();
                resolve();
            } catch (error) {
                fail(error);
            }
        });
    });
}

function normalizePhoneForSms(phone) {
    const clean = phone.trim();
    if (clean.startsWith('+')) return clean.replace(/[^\d+]/g, '');
    const digits = clean.replace(/\D/g, '');
    const countryCode = (process.env.SMS_COUNTRY_CODE || '+91').replace(/[^\d+]/g, '');
    const countryDigits = countryCode.replace(/\D/g, '');
    if (digits.startsWith(countryDigits) && digits.length > 10) return '+' + digits;
    return countryCode + digits.replace(/^0+/, '');
}

function sendSmsOtp(phone, otp) {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const from = process.env.TWILIO_FROM;
    if (!accountSid || !authToken || !from) {
        return Promise.reject(new Error('SMS OTP sender is not configured.'));
    }
    if (!/^AC[0-9a-f]{32}$/i.test(accountSid)) {
        return Promise.reject(new Error('Twilio account settings are invalid.'));
    }

    const to = normalizePhoneForSms(phone);
    if (!/^\+\d{10,15}$/.test(to)) {
        return Promise.reject(new Error('The saved phone number is not in a usable international format.'));
    }
    const body = new URLSearchParams({
        To: to,
        From: from,
        Body: 'Your ZOVYA password reset code is ' + otp + '. It expires in 10 minutes.'
    }).toString();

    return new Promise((resolve, reject) => {
        const request = https.request({
            hostname: 'api.twilio.com',
            port: 443,
            path: '/2010-04-01/Accounts/' + accountSid + '/Messages.json',
            method: 'POST',
            headers: {
                Authorization: 'Basic ' + Buffer.from(accountSid + ':' + authToken).toString('base64'),
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(body)
            }
        }, response => {
            let responseBody = '';
            response.setEncoding('utf8');
            response.on('data', chunk => { responseBody += chunk; });
            response.on('end', () => {
                if (response.statusCode >= 200 && response.statusCode < 300) return resolve();
                reject(new Error('SMS provider rejected the request: HTTP ' + response.statusCode + ' ' + responseBody.slice(0, 300)));
            });
        });
        request.on('error', reject);
        request.end(body);
    });
}

function sendResetOtpForm(response, challenge, maskedTarget) {
    const escape = value => String(value).replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
    const html = [
        '<!DOCTYPE html>',
        '<html lang="en"><head><meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '<title>Verify OTP - ZOVYA_Gifts</title>',
        '<style>',
        '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:#fff0f6;font-family:Arial,sans-serif;color:#333}',
        'main{width:min(440px,100%);padding:34px;background:#fff;border-radius:16px;box-shadow:0 8px 32px #8e287522;text-align:center}',
        '.icon{width:62px;height:62px;margin:auto;border-radius:50%;display:grid;place-items:center;background:#fff0f6;color:#8e2875;font-size:28px}',
        'h1{margin:18px 0 8px;color:#8e2875;font-size:27px}.sub{color:#666;line-height:1.6;margin:0 0 24px}',
        'label{display:block;text-align:left;font-weight:600;font-size:14px;margin:16px 0 7px}',
        'input{width:100%;padding:13px;border:1px solid #d8c8d3;border-radius:8px;font-size:16px}',
        'input:focus{outline:2px solid #d58ac6;border-color:#8e2875}',
        'button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:8px;background:#9f2089;color:#fff;font-size:16px;font-weight:700;cursor:pointer}',
        '.back{display:inline-block;margin-top:18px;color:#8e2875;text-decoration:none;font-weight:600}',
        '.hint{font-size:13px;color:#777;margin-top:18px}',
        '</style></head><body><main>',
        '<div class="icon">🔐</div><h1>Verify your code</h1>',
        '<p class="sub">We sent a one-time code to <strong>' + escape(maskedTarget) + '</strong>. It expires in 10 minutes.</p>',
        '<form action="http://localhost:8000/api/password/reset" method="post">',
        '<input type="hidden" name="challenge" value="' + escape(challenge) + '">',
        '<label for="otp">6-digit OTP</label>',
        '<input id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Enter the code" required>',
        '<label for="newPassword">New password</label>',
        '<input id="newPassword" name="newPassword" type="password" minlength="8" maxlength="1024" autocomplete="new-password" placeholder="At least 8 characters" required>',
        '<button type="submit">Verify &amp; Reset Password</button>',
        '</form><p class="hint">After reset, sign in with your new password. Your User ID will be shown on the confirmation page.</p>',
        '<a class="back" href="Login.HTML">Back to Login</a>',
        '</main></body></html>'
    ].join('\n');
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end(html);
}

async function handlePasswordResetRequest(request, response) {
    const { body, tooLarge } = await readPostData(request);
    if (tooLarge) return sendHtml(response, 413, 'Could not send code', 'The request was too large.', false);

    let data;
    try {
        data = parsePostData(request, body);
    } catch {
        return sendHtml(response, 400, 'Could not send code', 'Please check the details and try again.', false);
    }
    if (!data) return sendHtml(response, 415, 'Could not send code', 'Please submit the reset form again.', false);

    const identifier = typeof data.identifier === 'string' ? data.identifier.trim() : '';
    const channel = data.channel === 'sms' ? 'sms' : data.channel === 'email' ? 'email' : '';
    if (!identifier || identifier.length > 254 || !channel) {
        return sendHtml(response, 400, 'Could not send code', 'Enter your ID, phone or email, and choose where to receive the code.', false);
    }

    try {
        const numericId = /^\d{1,20}$/.test(identifier) && BigInt(identifier) <= 18446744073709551615n
            ? identifier
            : '0';
        const phoneDigits = identifier.replace(/\D/g, '');
        const phoneSearch = /^[+0-9()\s.-]{7,24}$/.test(identifier) && phoneDigits
            ? " OR REGEXP_REPLACE(phone, '[^0-9]', '') = " + sqlText(phoneDigits)
            : '';
        const result = await runMysql(
            'SELECT id, email, phone FROM users WHERE id = ' + numericId +
            ' OR email = ' + sqlText(identifier.toLowerCase()) +
            ' OR phone = ' + sqlText(identifier) + phoneSearch + ' LIMIT 1;'
        );
        const row = result.split(/\r?\n/).filter(Boolean)[0];
        if (!row) {
            return sendHtml(response, 404, 'Account not found', 'No matching account was found. Check the ID or registered contact and try again.', false);
        }

        const [userId, email, phone] = row.split('\t');
        const destination = channel === 'email' ? email : phone;
        if (!destination) {
            return sendHtml(response, 400, 'No contact available', 'This account has no saved contact for the selected delivery method.', false);
        }

        const cooldownKey = userId + ':' + channel;
        const now = Date.now();
        for (const [key, sentAt] of passwordResetCooldown) {
            if (now - sentAt > 10 * 60 * 1000) passwordResetCooldown.delete(key);
        }
        for (const [key, challengeData] of passwordResetChallenges) {
            if (challengeData.expiresAt <= now) passwordResetChallenges.delete(key);
        }
        const previousSentAt = passwordResetCooldown.get(cooldownKey);
        if (previousSentAt && now - previousSentAt < 60 * 1000) {
            return sendHtml(response, 429, 'Please wait', 'A code was sent recently. Wait one minute before requesting another code.', false);
        }

        const otp = String(randomInt(100000, 1000000));
        const challenge = randomBytes(24).toString('hex');
        if (channel === 'email') {
            await sendEmailOtp(destination, otp);
        } else {
            await sendSmsOtp(destination, otp);
        }

        const codeHash = createHmac('sha256', otpSecret).update(challenge + ':' + otp).digest();
        passwordResetChallenges.set(challenge, {
            userId,
            codeHash,
            expiresAt: now + 10 * 60 * 1000,
            attempts: 0
        });
        passwordResetCooldown.set(cooldownKey, now);

        const masked = channel === 'email' ? maskEmail(destination) : maskPhone(destination);
        return sendResetOtpForm(response, challenge, masked);
    } catch (error) {
        console.error('Could not send password reset OTP:', error.message);
        const senderSettingsMissing = channel === 'email'
            ? !process.env.SMTP_USER || !process.env.SMTP_PASS
            : !process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_FROM;
        const failureMessage = senderSettingsMissing
            ? channel === 'email'
                ? 'Email sender settings are missing in the PowerShell window that started server.js.'
                : 'SMS sender settings are missing in the PowerShell window that started server.js.'
            : channel === 'email'
                ? 'The email service rejected the request. Check the Gmail address and full App Password, then read the server PowerShell window for details.'
                : 'The SMS service rejected the request. Check the Twilio settings and read the server PowerShell window for details.';
        return sendHtml(response, 503, 'Could not send code', failureMessage, false);
    }
}

async function handlePasswordReset(request, response) {
    const { body, tooLarge } = await readPostData(request);
    if (tooLarge) return sendHtml(response, 413, 'Password reset failed', 'The request was too large.', false);

    let data;
    try {
        data = parsePostData(request, body);
    } catch {
        return sendHtml(response, 400, 'Password reset failed', 'Please check the code and new password.', false);
    }
    if (!data) return sendHtml(response, 415, 'Password reset failed', 'Please submit the reset form again.', false);

    const challenge = typeof data.challenge === 'string' ? data.challenge : '';
    const otp = typeof data.otp === 'string' ? data.otp.trim() : '';
    const newPassword = typeof data.newPassword === 'string' ? data.newPassword : '';
    if (!/^[a-f0-9]{48}$/.test(challenge) || !/^\d{6}$/.test(otp) || newPassword.length < 8 || newPassword.length > 1024) {
        return sendHtml(response, 400, 'Password reset failed', 'Enter a valid six-digit code and a new password of at least 8 characters.', false);
    }

    const reset = passwordResetChallenges.get(challenge);
    if (!reset || reset.expiresAt <= Date.now() || reset.attempts >= 5) {
        passwordResetChallenges.delete(challenge);
        return sendHtml(response, 400, 'Code expired', 'That code expired or is no longer valid. Request a new one and try again.', false);
    }

    const submittedHash = createHmac('sha256', otpSecret).update(challenge + ':' + otp).digest();
    if (!timingSafeEqual(submittedHash, reset.codeHash)) {
        reset.attempts += 1;
        if (reset.attempts >= 5) passwordResetChallenges.delete(challenge);
        return sendHtml(response, 400, 'Code not accepted', 'The OTP is incorrect. Check it and try again. You have up to 5 attempts.', false);
    }

    try {
        const salt = randomBytes(16).toString('hex');
        const passwordHash = scryptSync(newPassword, salt, 64).toString('hex');
        await runMysql(
            'UPDATE users SET password_salt = ' + sqlText(salt) +
            ', password_hash = ' + sqlText(passwordHash) +
            ' WHERE id = ' + reset.userId + ';'
        );
        for (const [key, value] of passwordResetChallenges) {
            if (value.userId === reset.userId) passwordResetChallenges.delete(key);
        }
        return sendHtml(
            response,
            200,
            'Password changed',
            'Your new password is saved. Your User ID is ' + reset.userId + '. Keep it for your next login.',
            true
        );
    } catch (error) {
        console.error('Could not reset password:', error.message);
        return sendHtml(response, 500, 'Password reset failed', 'Could not save the new password. Please try again.', false);
    }
}
function servePage(request, response, pathname) {
    let decodedPath;
    try {
        decodedPath = decodeURIComponent(pathname);
    } catch {
        response.writeHead(400);
        return response.end('Invalid URL');
    }

    const relativePath = decodedPath === '/' ? '/index.html' : decodedPath;
    const filePath = path.resolve(ROOT, '.' + relativePath);
    const rootPrefix = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;

    if (!filePath.startsWith(rootPrefix)) {
        response.writeHead(403);
        return response.end('Forbidden');
    }

    const contentType = contentTypes[path.extname(filePath).toLowerCase()];
    if (!contentType) {
        response.writeHead(404);
        return response.end('Not found');
    }

    fs.readFile(filePath, (error, contents) => {
        if (error) {
            response.writeHead(404);
            return response.end('Not found');
        }
        response.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-store'
        });
        response.end(request.method === 'HEAD' ? undefined : contents);
    });
}

const server = http.createServer((request, response) => {
    let url;
    try {
        url = new URL(request.url, 'http://localhost');
    } catch {
        response.writeHead(400);
        return response.end('Invalid request');
    }

    if (url.pathname === '/api/me') {
        if (request.method !== 'GET') return sendJson(response, 405, { authenticated: false });
        return handleCurrentUser(request, response);
    }
    if (url.pathname === '/api/signup') {
        if (request.method !== 'POST') {
            return sendHtml(response, 405, 'Signup unavailable', 'Please submit the signup form to continue.', false);
        }
        return handleSignup(request, response);
    }

    if (url.pathname === '/api/login') {
        if (request.method !== 'POST') {
            return sendHtml(response, 405, 'Login unavailable', 'Please submit the login form to continue.', false);
        }
        return handleLogin(request, response);
    }

    if (url.pathname === '/api/password/forgot') {
        if (request.method !== 'POST') {
            return sendHtml(response, 405, 'Reset unavailable', 'Please submit the password reset form.', false);
        }
        return handlePasswordResetRequest(request, response);
    }

    if (url.pathname === '/api/password/reset') {
        if (request.method !== 'POST') {
            return sendHtml(response, 405, 'Reset unavailable', 'Please submit the password reset form.', false);
        }
        return handlePasswordReset(request, response);
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.writeHead(405);
        return response.end('Method not allowed');
    }

    return servePage(request, response, url.pathname);
});

initializeDatabase()
    .then(() => {
        server.listen(PORT, '127.0.0.1', () => {
            console.log('ZOVYA is running at http://localhost:' + PORT);
            console.log('Signup data will be stored in MySQL database: ' + DATABASE_NAME);
            console.log('Email OTP settings: ' + (process.env.SMTP_USER && process.env.SMTP_PASS ? 'configured' : 'missing'));
            console.log('SMS OTP settings: ' + (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM ? 'configured' : 'missing'));
        });
    })
    .catch(error => {
        console.error('Could not connect to MySQL database "' + DATABASE_NAME + '".');
        console.error(error.message);
        console.error('Set up the "' + MYSQL_LOGIN_PATH + '" MySQL login path, then restart server.js.');
        process.exitCode = 1;
    });