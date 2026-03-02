import type {
  OpenClawPluginDefinition,
  OpenClawPluginApi,
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookAfterToolCallEvent,
  PluginHookToolContext,
} from "openclaw/plugin-sdk";
import { AuditLogger } from "./audit.js";
import { BUILTIN_RULES } from "./builtin-rules.js";
import { ChainDetector, DEFAULT_CHAIN_RULES } from "./chain-detector.js";
import { RulesEngine } from "./engine.js";
import { RateLimiter, DEFAULT_RATE_LIMITS } from "./rate-limiter.js";
import type { HarnessMode, HarnessClassification } from "./types.js";
import { classifyVerb } from "./verb-classifier.js";

const HARNESS_PRIORITY = 100;
const DEFAULT_AUDIT_PATH = "/var/log/fridaclaw/harness-audit.jsonl";

export const safetyHarnessPlugin: OpenClawPluginDefinition = {
  id: "safety-harness",
  name: "Safety Harness",
  description: "Classifies tool calls into allow/confirm/block tiers with audit logging",
  version: "0.1.0",

  register(api: OpenClawPluginApi) {
    const mode: HarnessMode = (process.env.HARNESS_MODE as HarnessMode) || "observe";
    const auditPath = process.env.HARNESS_AUDIT_PATH || DEFAULT_AUDIT_PATH;

    const engine = new RulesEngine(BUILTIN_RULES, [], []);
    const audit = new AuditLogger(auditPath);
    const rateLimiter = new RateLimiter(DEFAULT_RATE_LIMITS);
    const chainDetector = new ChainDetector(DEFAULT_CHAIN_RULES);

    // Store last classification per tool call for the post-hook
    const pendingClassifications = new Map<string, HarnessClassification>();

    api.logger.info(`[safety-harness] initialized in ${mode} mode, audit → ${auditPath}`);

    api.on(
      "before_tool_call",
      async (
        event: PluginHookBeforeToolCallEvent,
        ctx: PluginHookToolContext,
      ): Promise<PluginHookBeforeToolCallResult | void> => {
        const { toolName, params } = event;
        const verb = classifyVerb(toolName);

        // 1. Rules engine classification
        const classification = engine.classify(toolName, params);

        // 2. Rate limit check (may escalate tier)
        const rateCategory = RateLimiter.toRateCategory(verb);
        let effectiveTier = classification.tier;
        if (rateCategory && !rateLimiter.check(rateCategory)) {
          effectiveTier = "block";
          classification.reason = `Rate limit exceeded for ${rateCategory}: ${classification.reason}`;
        }

        // 3. Chain detection
        const chainFlags = chainDetector.check({
          tool: toolName,
          verb,
          target: toolName.split(".")[0] || toolName,
        });
        if (chainFlags.length > 0) {
          effectiveTier = "block";
          classification.reason = `Chain detected (${chainFlags.join(", ")}): ${classification.reason}`;
        }

        // Store for post-hook audit
        const callKey = `${ctx.sessionKey || ""}:${toolName}:${Date.now()}`;
        pendingClassifications.set(callKey, { ...classification, tier: effectiveTier });

        api.logger.info(
          `[safety-harness] ${toolName}: tier=${effectiveTier} reason="${classification.reason}" mode=${mode}`,
        );

        // In observe mode, never block
        if (mode === "observe") {
          return undefined;
        }

        // In enforce mode, block if tier is "block"
        if (effectiveTier === "block") {
          // Return generic message to AI, log details only in audit trail
          api.logger.warn(`[safety-harness] BLOCKED ${toolName}: ${classification.reason}`);
          return {
            block: true,
            blockReason: "Action blocked by safety policy. Please try a different approach.",
          };
        }

        // "confirm" tier: for Phase 1, treat as allow (confirmation flow is Phase 3)
        return undefined;
      },
      { priority: HARNESS_PRIORITY },
    );

    api.on(
      "after_tool_call",
      async (event: PluginHookAfterToolCallEvent, ctx: PluginHookToolContext) => {
        const { toolName, params } = event;
        const verb = classifyVerb(toolName);

        // Record in rate limiter
        const rateCategory = RateLimiter.toRateCategory(verb);
        if (rateCategory) {
          rateLimiter.record(rateCategory);
        }

        // Record in chain detector ledger
        chainDetector.record({
          tool: toolName,
          verb,
          target: toolName.split(".")[0] || toolName,
        });

        // Build args summary (sanitized — no full bodies or secrets)
        // Expanded redaction list for credential fields
        const SENSITIVE_KEY_PATTERN =
          /body|content|text|html|token|key|password|secret|auth|credential|bearer|private/i;
        const argsSummary = Object.entries(params)
          .map(([k, v]) =>
            SENSITIVE_KEY_PATTERN.test(k) ? `${k}: [REDACTED]` : `${k}: ${String(v).slice(0, 100)}`,
          )
          .join(", ");

        // Write audit log
        const result = event.error ? "error" : "executed";
        await audit
          .log({
            tool: toolName,
            argsSummary,
            tier: "allow", // Will be improved when we thread classification through
            tainted: false, // Phase 4
            result,
            chainFlags: [],
            rateWindow: rateLimiter.getCounts(),
          })
          .catch((err) => {
            api.logger.error(`[safety-harness] audit write failed: ${err}`);
          });
      },
      { priority: HARNESS_PRIORITY },
    );
  },
};

export default safetyHarnessPlugin;
