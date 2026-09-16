import { describe, expect, it } from "vitest";
import { computeExchangeExpiresAt, type ExchangeContext, exchangeCacheKey } from "../exchange.mjs";

const context: ExchangeContext = {
	tokenEndpoint: "http://provider.example/oauth/token",
	clientId: "proxy-exchange",
	scope: "orders.read",
	audience: "https://api.example.com",
	resource: "https://api.example.com/orders",
};
const ASSERTION = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpIn0.c2ln";

describe("exchangeCacheKey", () => {
	it("is stable for the same context and assertion", () => {
		expect(exchangeCacheKey(context, ASSERTION)).toBe(exchangeCacheKey({ ...context }, ASSERTION));
		expect(exchangeCacheKey(context, ASSERTION)).toMatch(/^[0-9a-f]{64}$/);
	});

	it("never contains the assertion itself", () => {
		expect(exchangeCacheKey(context, ASSERTION)).not.toContain(ASSERTION);
	});

	it("differs whenever anything that affects the exchange differs", () => {
		const base = exchangeCacheKey(context, ASSERTION);
		const variants: [string, ExchangeContext, string][] = [
			["assertion", context, `${ASSERTION}x`],
			["provider", { ...context, tokenEndpoint: "http://other.example/oauth/token" }, ASSERTION],
			["client", { ...context, clientId: "other-client" }, ASSERTION],
			["scope", { ...context, scope: "orders.write" }, ASSERTION],
			["unset scope", { ...context, scope: null }, ASSERTION],
			["audience", { ...context, audience: "https://other.example" }, ASSERTION],
			["unset audience", { ...context, audience: null }, ASSERTION],
			["resource", { ...context, resource: "https://api.example.com/users" }, ASSERTION],
			["unset resource", { ...context, resource: null }, ASSERTION],
		];
		const keys = variants.map(([label, ctx, assertion]) => {
			const key = exchangeCacheKey(ctx, assertion);
			expect(key, label).not.toBe(base);
			return key;
		});
		expect(new Set(keys).size).toBe(keys.length);
	});

	// A delimiter-joined key would let one field's tail read as the next
	// field's head; the encoding must keep the boundaries.
	it("cannot be forged by shifting text between adjacent fields", () => {
		const a = exchangeCacheKey({ ...context, scope: "a b", audience: "c" }, ASSERTION);
		const b = exchangeCacheKey({ ...context, scope: "a", audience: "b c" }, ASSERTION);
		const c = exchangeCacheKey({ ...context, scope: 'a","b', audience: null }, ASSERTION);
		const d = exchangeCacheKey({ ...context, scope: "a", audience: "b" }, ASSERTION);
		expect(new Set([a, b, c, d]).size).toBe(4);
	});
});

describe("computeExchangeExpiresAt", () => {
	const now = 1_800_000_000_000;
	const base = {
		now,
		ttlSeconds: 60,
		safetyMarginSeconds: 5,
		expiresIn: 300 as number | null,
		assertionExpiresAt: now / 1000 + 600 as number | null,
	};

	it("takes the configured ttl when it is the smallest bound", () => {
		expect(computeExchangeExpiresAt(base)).toBe(now + 55_000);
	});

	it("takes the provider's expires_in when it is the smallest bound", () => {
		expect(computeExchangeExpiresAt({ ...base, expiresIn: 20 })).toBe(now + 15_000);
	});

	it("takes the assertion's exp when it is the smallest bound", () => {
		expect(
			computeExchangeExpiresAt({ ...base, assertionExpiresAt: now / 1000 + 30 }),
		).toBe(now + 25_000);
	});

	it("ignores an absent expires_in, leaving the other bounds", () => {
		expect(computeExchangeExpiresAt({ ...base, expiresIn: null })).toBe(now + 55_000);
	});

	it("returns null (do not cache) when the assertion has no exp", () => {
		expect(computeExchangeExpiresAt({ ...base, assertionExpiresAt: null })).toBeNull();
	});

	it("returns null when a bound leaves nothing after the safety margin", () => {
		expect(computeExchangeExpiresAt({ ...base, expiresIn: 5 })).toBeNull();
		expect(computeExchangeExpiresAt({ ...base, expiresIn: 0 })).toBeNull();
		expect(
			computeExchangeExpiresAt({ ...base, assertionExpiresAt: now / 1000 + 5 }),
		).toBeNull();
		expect(
			computeExchangeExpiresAt({ ...base, assertionExpiresAt: now / 1000 - 10 }),
		).toBeNull();
	});
});
