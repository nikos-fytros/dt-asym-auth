import { importJWK, jwtVerify, type JWK } from "jose";
import { createHash } from "crypto";

const DISCOVERY_URL =
  "https://identity.disruptive-technologies.com/data-connector/.well-known/openid-configuration";
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 min, can be longer if the kid match check is implemented as shown below

// simple in-memory cache — for this example only and not for production of course
let jwksCache: { keys: JWK[]; fetchedAt: number } = { keys: [], fetchedAt: 0 };

// fetch + cache the JWKS, refresh if stale or if the given kid isn't in the cache yet
async function getJwksKeys(forceRefresh = false) {
  const isStale = Date.now() - jwksCache.fetchedAt > CACHE_TTL_MS;
  if (!forceRefresh && !isStale && jwksCache.keys.length) return jwksCache.keys;

  const discovery = await (await fetch(DISCOVERY_URL)).json();
  const jwks = await (await fetch(discovery.jwks_uri)).json();

  jwksCache = { keys: jwks.keys, fetchedAt: Date.now() };
  return jwksCache.keys;
}

// find the right key by kid; if missing, refresh once (handles key rotation)
async function getSigningKey(kid: string) {
  let keys = await getJwksKeys();
  let match = keys.find((k) => k.kid === kid && k.kty === "EC" && k.use === "sig");

  if (!match) {
    keys = await getJwksKeys(true); // force refresh in case DT rotated keys
    match = keys.find((k) => k.kid === kid && k.kty === "EC" && k.use === "sig");
  }
  if (!match) throw new Error(`No signing key found for kid: ${kid}`);
  return match;
}

// main verification entrypoint
async function verifyDtEvent(token: string, rawBody: string) {
  // read kid from header (unsigned, just base64 — safe to peek before verifying)
  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());

  const jwk = await getSigningKey(header.kid);

  // pin algorithm ourselves — never trust header.alg (prevents algorithm-confusion attacks)
  const publicKey = await importJWK(jwk, "ES256");

  // cryptographic signature check — throws if invalid/expired/wrong issuer
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: "https://identity.disruptive-technologies.com/data-connector",
  });

  // integrity check — confirm the body we received matches what was signed
  const checksum = createHash("sha256").update(rawBody).digest("hex");
  if (checksum !== payload.checksum_sha256) {
    throw new Error("Checksum mismatch — body may have been altered");
  }

  return payload; // verified + integrity-checked claims
}

// usage in a route handler (needs raw, unparsed body)
// @ts-expect-error - this is an example so 'app' is not defined.
app.post("/dt-webhook", async (req: any, res: any) => {
  try {
    const claims = await verifyDtEvent(req.headers["dt-asymmetric-signature"], req.rawBody);
    console.log("Verified event from:", claims.sub);
    res.sendStatus(200);
  } catch (err) {
    console.error("Verification failed:", err);
    res.sendStatus(401);
  }
});
