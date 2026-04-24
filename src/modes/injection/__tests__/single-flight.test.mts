import { describe, expect, it, vi } from "vitest";
import { createSingleFlight } from "../single-flight.mjs";

describe("createSingleFlight", () => {
	it("invokes fetcher once for concurrent run() on the same key", async () => {
		const sf = createSingleFlight<string>();
		const fetcher = vi.fn(
			() =>
				new Promise<string>((resolve) => setTimeout(() => resolve("tok"), 10)),
		);

		const results = await Promise.all(
			Array.from({ length: 10 }, () => sf.run("k1", fetcher)),
		);

		expect(fetcher).toHaveBeenCalledTimes(1);
		const leaderCount = results.filter((r) => !r.wasWaiter).length;
		const waiterCount = results.filter((r) => r.wasWaiter).length;
		expect(leaderCount).toBe(1);
		expect(waiterCount).toBe(9);
		expect(results.every((r) => r.value === "tok")).toBe(true);
	});

	it("invokes fetcher again for a second run() after the first resolves", async () => {
		const sf = createSingleFlight<string>();
		const fetcher = vi.fn().mockResolvedValueOnce("tok1").mockResolvedValueOnce("tok2");

		const r1 = await sf.run("k1", fetcher);
		expect(r1.value).toBe("tok1");
		expect(r1.wasWaiter).toBe(false);

		const r2 = await sf.run("k1", fetcher);
		expect(r2.value).toBe("tok2");
		expect(r2.wasWaiter).toBe(false);

		expect(fetcher).toHaveBeenCalledTimes(2);
	});

	it("propagates rejection to all concurrent waiters on the same key", async () => {
		const sf = createSingleFlight<string>();
		const err = new Error("boom");
		const fetcher = vi.fn(
			() =>
				new Promise<string>((_resolve, reject) => setTimeout(() => reject(err), 10)),
		);

		const results = await Promise.allSettled(
			Array.from({ length: 10 }, () => sf.run("k1", fetcher)),
		);

		expect(fetcher).toHaveBeenCalledTimes(1);
		for (const r of results) {
			expect(r.status).toBe("rejected");
			if (r.status === "rejected") expect(r.reason).toBe(err);
		}
	});

	it("clears pending entry after success", async () => {
		const sf = createSingleFlight<string>();
		const result = await sf.run("k1", () => Promise.resolve("tok"));
		expect(result.value).toBe("tok");
		expect(result.wasWaiter).toBe(false);
		expect(sf._sizeForTesting()).toBe(0);
	});

	it("clears pending entry after failure", async () => {
		const sf = createSingleFlight<string>();
		await expect(sf.run("k1", () => Promise.reject(new Error("x")))).rejects.toThrow("x");
		expect(sf._sizeForTesting()).toBe(0);
	});

	it("does not coalesce different keys", async () => {
		const sf = createSingleFlight<string>();
		const f1 = vi.fn().mockResolvedValue("a");
		const f2 = vi.fn().mockResolvedValue("b");

		const [r1, r2] = await Promise.all([sf.run("a", f1), sf.run("b", f2)]);
		expect(r1.value).toBe("a");
		expect(r1.wasWaiter).toBe(false);
		expect(r2.value).toBe("b");
		expect(r2.wasWaiter).toBe(false);
		expect(f1).toHaveBeenCalledTimes(1);
		expect(f2).toHaveBeenCalledTimes(1);
	});
});
