import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import { handleApiRequest } from "./src/backend/apiEngine";

dotenv.config();

const app = express();
const PORT = 3000;

// Enterprise Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

app.use(express.json({ limit: "15mb" }));

// Route all /api/* requests through the Cloudflare Worker native API Engine
app.all("/api/*", async (req, res) => {
  try {
    const fullUrl = `${req.protocol}://${req.get("host") || "localhost:3000"}${req.originalUrl}`;
    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (val) {
        if (Array.isArray(val)) {
          val.forEach((v) => headers.append(key, v));
        } else {
          headers.set(key, String(val));
        }
      }
    }

    const hasBody = !["GET", "HEAD"].includes(req.method);
    const bodyString = hasBody && req.body ? JSON.stringify(req.body) : undefined;

    const webReq = new Request(fullUrl, {
      method: req.method,
      headers,
      body: bodyString,
    });

    const webRes = await handleApiRequest(webReq, process.env);

    res.status(webRes.status);
    webRes.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });

    const bodyText = await webRes.text();
    res.send(bodyText);
  } catch (err: any) {
    console.error("Express API bridge error:", err);
    res.status(500).json({ error: err?.message || "Internal server error" });
  }
});

// Bootstrap static file / Vite serving
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    console.log("Vite development middleware mounted.");
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
    console.log("Production static files mounted.");
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Unikorn360 server running on http://localhost:${PORT}`);
  });
}

startServer();
