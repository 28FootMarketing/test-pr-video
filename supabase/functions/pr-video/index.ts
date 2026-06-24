// pr-video — GitHub pull_request webhook handler (round-trip scaffold)
//
// Responsibilities:
//   1. Verify the GitHub HMAC-SHA256 signature (X-Hub-Signature-256) using
//      the GITHUB_WEBHOOK_SECRET secret. Reject anything that doesn't match.
//   2. Log the event so deliveries are visible in the Supabase function logs.
//   3. If a GITHUB_TOKEN secret is present, post a confirmation comment back
//      on the PR so the round-trip is visible from GitHub too.
//
// Deployed with verify_jwt = false: GitHub cannot send a Supabase JWT, so
// authentication is handled entirely by the HMAC signature check below.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const encoder = new TextEncoder();

// Constant-time comparison to avoid leaking timing information.
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

async function verifySignature(
  secret: string,
  payload: string,
  signatureHeader: string | null,
): Promise<boolean> {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sigBytes = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const expected = "sha256=" +
    Array.from(new Uint8Array(sigBytes))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  return timingSafeEqual(expected, signatureHeader);
}

async function commentOnPR(
  commentsUrl: string,
  token: string,
  body: string,
): Promise<void> {
  const res = await fetch(commentsUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "pr-video-edge-function",
    },
    body: JSON.stringify({ body }),
  });
  if (!res.ok) {
    console.error("Failed to comment on PR:", res.status, await res.text());
  }
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const secret = Deno.env.get("GITHUB_WEBHOOK_SECRET");
  if (!secret) {
    console.error("GITHUB_WEBHOOK_SECRET is not configured");
    return new Response("Server misconfigured", { status: 500 });
  }

  const rawBody = await req.text();
  const signature = req.headers.get("x-hub-signature-256");
  if (!(await verifySignature(secret, rawBody, signature))) {
    console.warn("Rejected webhook: invalid signature");
    return new Response("Invalid signature", { status: 401 });
  }

  const event = req.headers.get("x-github-event") ?? "unknown";
  const delivery = req.headers.get("x-github-delivery") ?? "unknown";

  // GitHub pings the endpoint once when the hook is first created.
  if (event === "ping") {
    console.log(`ping received (delivery ${delivery})`);
    return new Response(JSON.stringify({ ok: true, pong: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  if (event !== "pull_request") {
    console.log(`ignoring event '${event}' (delivery ${delivery})`);
    return new Response(JSON.stringify({ ok: true, ignored: event }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  const action = payload.action;
  const number = payload.number;
  const repo = payload.repository?.full_name;
  const title = payload.pull_request?.title;
  console.log(
    `pull_request.${action} on ${repo}#${number} ("${title}") — delivery ${delivery}`,
  );

  // Optional round-trip: comment back on the PR if a token is configured.
  // Only do this on 'opened'/'reopened'/'synchronize' to avoid noise.
  const token = Deno.env.get("GITHUB_TOKEN");
  const commentsUrl = payload.pull_request?.comments_url;
  if (
    token && commentsUrl &&
    ["opened", "reopened", "synchronize"].includes(action)
  ) {
    await commentOnPR(
      commentsUrl,
      token,
      `🎬 \`pr-video\` received \`pull_request.${action}\` — webhook round-trip confirmed.`,
    );
  }

  return new Response(
    JSON.stringify({ ok: true, event, action, number, repo }),
    { headers: { "Content-Type": "application/json" } },
  );
});
