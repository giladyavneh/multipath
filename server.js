const crypto = require("node:crypto");
const http = require("node:http");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";

const APP_CONFIG = {
  app1: {
    username: process.env.APP1_USERNAME || "app1-user",
    password: process.env.APP1_PASSWORD || "app1-pass",
    cookieName: "app1_session",
    title: "App 1",
  },
  app2: {
    username: process.env.APP2_USERNAME || "app2-user",
    password: process.env.APP2_PASSWORD || "app2-pass",
    cookieName: "app2_session",
    title: "App 2",
  },
};

const sessions = {
  app1: new Map(),
  app2: new Map(),
};

function htmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sendHtml(res, status, html) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, ...headers });
  res.end();
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) {
    return {};
  }

  const parsed = {};
  for (const pair of header.split(";")) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf("=");
    if (index < 0) continue;
    const key = decodeURIComponent(trimmed.slice(0, index));
    const value = decodeURIComponent(trimmed.slice(index + 1));
    parsed[key] = value;
  }
  return parsed;
}

function createSession(pathKey, username) {
  const token = crypto.randomBytes(24).toString("hex");
  sessions[pathKey].set(token, { username, createdAt: Date.now() });
  return token;
}

function clearSession(pathKey, token) {
  if (token) {
    sessions[pathKey].delete(token);
  }
}

function readBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];

    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });

    req.on("error", reject);
  });
}

function appLandingPage(pathKey) {
  const { title } = APP_CONFIG[pathKey];
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title}</title>
  </head>
  <body>
    <h1>${title}</h1>
    <p>This is a mock entry page for ${title}.</p>
    <a href="/${pathKey}/login"><button type="button">Login</button></a>
  </body>
</html>`;
}

function loginPage(pathKey, error = "") {
  const { title } = APP_CONFIG[pathKey];
  const errorHtml = error ? `<p style="color: #b00020;">${htmlEscape(error)}</p>` : "";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title} Login</title>
  </head>
  <body>
    <h1>${title} Login</h1>
    ${errorHtml}
    <form method="post" action="/${pathKey}/login">
      <label>
        Username
        <input type="text" name="username" required autocomplete="username">
      </label>
      <br>
      <label>
        Password
        <input type="password" name="password" required autocomplete="current-password">
      </label>
      <br>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>`;
}

function homepage(pathKey, username) {
  const { title } = APP_CONFIG[pathKey];
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title} Homepage</title>
  </head>
  <body>
    <h1>${title} Homepage</h1>
    <p>Authenticated user: <strong>${htmlEscape(username)}</strong></p>
    <form method="post" action="/${pathKey}/logout">
      <button type="submit">Logout</button>
    </form>
  </body>
</html>`;
}

function loginCookie(pathKey, token) {
  const cookieName = APP_CONFIG[pathKey].cookieName;
  return `${cookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/${pathKey}; Max-Age=86400`;
}

function clearCookie(pathKey) {
  const cookieName = APP_CONFIG[pathKey].cookieName;
  return `${cookieName}=; HttpOnly; SameSite=Lax; Path=/${pathKey}; Max-Age=0`;
}

async function handleLoginPost(req, res, pathKey) {
  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("application/x-www-form-urlencoded")) {
    sendHtml(res, 415, "<h1>Unsupported Media Type</h1>");
    return;
  }

  let bodyText;
  try {
    bodyText = await readBody(req);
  } catch (error) {
    sendHtml(res, 413, "<h1>Payload Too Large</h1>");
    return;
  }

  const params = new URLSearchParams(bodyText);
  const username = (params.get("username") || "").trim();
  const password = params.get("password") || "";

  const config = APP_CONFIG[pathKey];
  if (username !== config.username || password !== config.password) {
    sendHtml(res, 401, loginPage(pathKey, "Invalid credentials"));
    return;
  }

  const token = createSession(pathKey, username);
  redirect(res, `/${pathKey}/login/homepage`, {
    "Set-Cookie": loginCookie(pathKey, token),
  });
}

function getAuthenticatedSession(req, pathKey) {
  const cookieName = APP_CONFIG[pathKey].cookieName;
  const cookies = parseCookies(req);
  const token = cookies[cookieName];
  if (!token) {
    return null;
  }
  const session = sessions[pathKey].get(token);
  if (!session) {
    return null;
  }
  return { token, session };
}

async function routeRequest(req, res) {
  const method = req.method || "GET";
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (method === "GET" && path === "/") {
    sendHtml(
      res,
      200,
      `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Multi App Login Mock</title></head>
  <body>
    <h1>Multi App Login Mock</h1>
    <ul>
      <li><a href="/app1">Go to App 1</a></li>
      <li><a href="/app2">Go to App 2</a></li>
    </ul>
  </body>
</html>`
    );
    return;
  }

  for (const pathKey of ["app1", "app2"]) {
    if (method === "GET" && path === `/${pathKey}`) {
      sendHtml(res, 200, appLandingPage(pathKey));
      return;
    }

    if (method === "GET" && path === `/${pathKey}/login`) {
      sendHtml(res, 200, loginPage(pathKey));
      return;
    }

    if (method === "POST" && path === `/${pathKey}/login`) {
      await handleLoginPost(req, res, pathKey);
      return;
    }

    if (method === "GET" && path === `/${pathKey}/login/homepage`) {
      const auth = getAuthenticatedSession(req, pathKey);
      if (!auth) {
        redirect(res, `/${pathKey}/login`);
        return;
      }
      sendHtml(res, 200, homepage(pathKey, auth.session.username));
      return;
    }

    if (method === "POST" && path === `/${pathKey}/logout`) {
      const auth = getAuthenticatedSession(req, pathKey);
      if (auth) {
        clearSession(pathKey, auth.token);
      }
      redirect(res, `/${pathKey}/login`, { "Set-Cookie": clearCookie(pathKey) });
      return;
    }
  }

  sendHtml(res, 404, "<h1>Not Found</h1>");
}

const server = http.createServer((req, res) => {
  routeRequest(req, res).catch((error) => {
    console.error("Unhandled request error:", error);
    if (!res.headersSent) {
      sendHtml(res, 500, "<h1>Internal Server Error</h1>");
      return;
    }
    res.end();
  });
});

server.on("clientError", (error, socket) => {
  console.error("Client connection error:", error.message);
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Server listening at http://${HOST}:${PORT}`);
    console.log(`app1 login: ${APP_CONFIG.app1.username} / ${APP_CONFIG.app1.password}`);
    console.log(`app2 login: ${APP_CONFIG.app2.username} / ${APP_CONFIG.app2.password}`);
  });
}

module.exports = { server };
