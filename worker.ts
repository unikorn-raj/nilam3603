import { handleApiRequest } from "./src/backend/apiEngine";

export interface Env {
  GEMINI_API_KEY?: string;
  VITE_SUPABASE_URL?: string;
  VITE_SUPABASE_ANON_KEY?: string;
  ASSETS?: { fetch: typeof fetch };
}

export default {
  async fetch(request: Request, env: Env, ctx: any): Promise<Response> {
    const url = new URL(request.url);

    // 1. Handle CORS Preflight OPTIONS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        },
      });
    }

    // 2. Route all /api/* requests natively to the Cloudflare Worker API Engine
    if (url.pathname.startsWith("/api/")) {
      return await handleApiRequest(request, env);
    }

    // 3. Serve static SPA assets in Cloudflare Workers / Pages runtime
    if (env.ASSETS) {
      const assetResponse = await env.ASSETS.fetch(request);
      if (assetResponse.status !== 404) {
        return assetResponse;
      }
      // SPA Client-side routing fallback to /index.html
      const indexReq = new Request(new URL("/index.html", request.url), request);
      return await env.ASSETS.fetch(indexReq);
    }

    return new Response("Not Found", { status: 404 });
  },
};
