import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const MAX_BODY_BYTES = 2048;
const SHA256 = /^[0-9a-f]{64}$/;
const RAW_CHALLENGE = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BEARER_JWT = /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i;
const BEGIN_REQUEST_KEYS = new Set(["action"]);
const COMPLETE_REQUEST_KEYS = new Set([
  "action",
  "transactionId",
  "nonce",
  "state",
  "callbackSha256",
]);

type BeginRequest = {
  action: "begin";
};

type CompleteRequest = {
  action: "complete";
  transactionId: string;
  nonce: string;
  state: string;
  callbackSha256: string;
};

type CheckpointRequest = BeginRequest | CompleteRequest;

type CheckpointChallenge = {
  transaction_id: string;
  nonce: string;
  state: string;
  expires_at: string;
};

type CheckpointReceipt = {
  receipt_correlation: string;
  receipt_digest: string;
  status: "completed";
};

function response(status: number, body: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function invalidRequest(): Response {
  return response(400, { error: "invalid_checkpoint_request" });
}

function rejected(): Response {
  return response(403, { error: "checkpoint_rejected" });
}

function unavailable(): Response {
  return response(503, { error: "checkpoint_unavailable" });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowedKeys: Set<string>): boolean {
  const keys = Object.keys(value);
  return keys.length === allowedKeys.size && keys.every((key) => allowedKeys.has(key));
}

function parseRequest(value: unknown): CheckpointRequest | null {
  if (!isRecord(value) || typeof value.action !== "string") {
    return null;
  }

  if (value.action === "begin") {
    return hasOnlyKeys(value, BEGIN_REQUEST_KEYS) ? { action: "begin" } : null;
  }

  if (value.action !== "complete" || !hasOnlyKeys(value, COMPLETE_REQUEST_KEYS)) {
    return null;
  }

  const { transactionId, nonce, state, callbackSha256 } = value;
  if (
    typeof transactionId !== "string" ||
    typeof nonce !== "string" ||
    typeof state !== "string" ||
    typeof callbackSha256 !== "string" ||
    !UUID_V4.test(transactionId) ||
    !RAW_CHALLENGE.test(nonce) ||
    !RAW_CHALLENGE.test(state) ||
    !SHA256.test(callbackSha256)
  ) {
    return null;
  }

  return { action: "complete", transactionId, nonce, state, callbackSha256 };
}

function isChallenge(value: unknown): value is CheckpointChallenge {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== 4 ||
    typeof value.transaction_id !== "string" ||
    !UUID_V4.test(value.transaction_id) ||
    typeof value.nonce !== "string" ||
    !RAW_CHALLENGE.test(value.nonce) ||
    typeof value.state !== "string" ||
    !RAW_CHALLENGE.test(value.state) ||
    typeof value.expires_at !== "string"
  ) {
    return false;
  }

  return Number.isFinite(Date.parse(value.expires_at));
}

function isReceipt(value: unknown): value is CheckpointReceipt {
  return (
    isRecord(value) &&
    Object.keys(value).length === 3 &&
    typeof value.receipt_correlation === "string" &&
    UUID_V4.test(value.receipt_correlation) &&
    typeof value.receipt_digest === "string" &&
    SHA256.test(value.receipt_digest) &&
    value.status === "completed"
  );
}

function hasValidContentLength(request: Request): boolean {
  const contentLength = request.headers.get("content-length");
  if (contentLength === null) {
    return true;
  }

  if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength)) {
    return false;
  }

  const length = Number(contentLength);
  return Number.isSafeInteger(length) && length <= MAX_BODY_BYTES;
}

async function readJsonBody(request: Request): Promise<unknown | null> {
  if (!hasValidContentLength(request) || !request.body) {
    return null;
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      const nextLength = length + value.byteLength;
      if (nextLength > MAX_BODY_BYTES) {
        await reader.cancel();
        return null;
      }

      chunks.push(value);
      length = nextLength;
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
}

function configuration(): { url: string; anonKey: string } | null {
  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  if (!url || !anonKey) {
    return null;
  }

  try {
    if (new URL(url).protocol !== "https:") {
      return null;
    }
  } catch {
    return null;
  }

  return { url, anonKey };
}

function rpcRow(data: unknown): unknown {
  return Array.isArray(data) ? data[0] : data;
}

Deno.serve(async (request) => {
  if (request.method !== "POST") {
    return response(405, { error: "method_not_allowed" });
  }

  const contentType = request.headers.get("content-type")?.trim();
  if (!contentType || !JSON_CONTENT_TYPE.test(contentType)) {
    return invalidRequest();
  }

  const body = await readJsonBody(request);
  const checkpoint = parseRequest(body);
  if (!checkpoint) {
    return invalidRequest();
  }

  const authorization = request.headers.get("authorization");
  if (checkpoint.action === "complete" && (!authorization || !BEARER_JWT.test(authorization))) {
    return response(401, { error: "authentication_required" });
  }

  const config = configuration();
  if (!config) {
    return unavailable();
  }

  const authenticatedHeaders = checkpoint.action === "complete" && authorization
    ? { Authorization: authorization }
    : undefined;
  const supabase = createClient(config.url, config.anonKey, {
    auth: {
      autoRefreshToken: false,
      detectSessionInUrl: false,
      persistSession: false,
    },
    global: authenticatedHeaders ? { headers: authenticatedHeaders } : undefined,
  });

  try {
    if (checkpoint.action === "begin") {
      const begin = await supabase.rpc("m2a_begin_apple_auth_checkpoint");
      if (begin.error) {
        return rejected();
      }

      const challenge = rpcRow(begin.data);
      if (!isChallenge(challenge)) {
        return unavailable();
      }

      return response(200, {
        transactionId: challenge.transaction_id,
        nonce: challenge.nonce,
        state: challenge.state,
        expiresAt: challenge.expires_at,
      });
    }

    const complete = await supabase.rpc("m2a_complete_apple_auth_checkpoint", {
      p_transaction_id: checkpoint.transactionId,
      p_nonce: checkpoint.nonce,
      p_state: checkpoint.state,
      p_callback_sha256: checkpoint.callbackSha256,
    });
    if (complete.error) {
      return rejected();
    }

    const receipt = rpcRow(complete.data);
    if (!isReceipt(receipt)) {
      return unavailable();
    }

    return response(200, {
      receiptCorrelation: receipt.receipt_correlation,
      receiptDigest: receipt.receipt_digest,
      status: receipt.status,
    });
  } catch {
    return unavailable();
  }
});
