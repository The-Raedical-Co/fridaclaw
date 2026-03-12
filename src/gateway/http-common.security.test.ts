import type { ServerResponse } from "node:http";
import { describe, expect, it, vi } from "vitest";
import { setDefaultSecurityHeaders } from "./http-common.js";

describe("setDefaultSecurityHeaders", () => {
  it("sets baseline security headers", () => {
    const res = {
      setHeader: vi.fn(),
    } as unknown as ServerResponse;

    setDefaultSecurityHeaders(res);

    // oxlint-disable typescript-eslint(unbound-method)
    expect(res.setHeader).toHaveBeenCalledWith("X-Content-Type-Options", "nosniff");
    expect(res.setHeader).toHaveBeenCalledWith("Referrer-Policy", "no-referrer");
    // New headers to add
    expect(res.setHeader).toHaveBeenCalledWith("X-Frame-Options", "DENY");
    expect(res.setHeader).toHaveBeenCalledWith("X-Permitted-Cross-Domain-Policies", "none");
  });

  it("sets Strict-Transport-Security when provided", () => {
    const res = {
      setHeader: vi.fn(),
    } as unknown as ServerResponse;

    setDefaultSecurityHeaders(res, {
      strictTransportSecurity: "max-age=31536000",
    });

    // oxlint-disable-next-line typescript-eslint(unbound-method)
    expect(res.setHeader).toHaveBeenCalledWith("Strict-Transport-Security", "max-age=31536000");
  });
});
