import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { HarnessMode } from "./types.js";

const HARNESS_PRIORITY = 100; // Run before other plugins

export const safetyHarnessPlugin = {
  id: "safety-harness",
  name: "Safety Harness",
  description: "Classifies tool calls into allow/confirm/block tiers with audit logging",
  version: "0.1.0",

  register(api: OpenClawPluginApi) {
    const mode: HarnessMode = "observe"; // Phase 1: log-only

    api.on(
      "before_tool_call",
      async (event, ctx) => {
        // Phase 1: observe only — classify but never block
        api.logger.info(`[safety-harness] before_tool_call: tool=${event.toolName} mode=${mode}`);
        return undefined; // pass-through
      },
      { priority: HARNESS_PRIORITY },
    );

    api.on(
      "after_tool_call",
      async (event, ctx) => {
        api.logger.info(
          `[safety-harness] after_tool_call: tool=${event.toolName} duration=${event.durationMs}ms`,
        );
      },
      { priority: HARNESS_PRIORITY },
    );
  },
};

export default safetyHarnessPlugin;
