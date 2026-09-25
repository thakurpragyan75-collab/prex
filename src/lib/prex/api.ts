import { createServerFn } from "@tanstack/react-start";
import type { CheckResult, MapResult, Proof } from "./types.ts";

export const mapExposure = createServerFn({ method: "POST" })
  .validator((data: { target: string; proof: Proof | null }) => data)
  .handler(async ({ data }): Promise<MapResult> => {
    const { executeMap } = await import("./passive.server.ts");
    return executeMap(data);
  });

export const checkControl = createServerFn({ method: "POST" })
  .validator((data: { host: string; method: Proof["method"]; token: string }) => data)
  .handler(async ({ data }): Promise<CheckResult> => {
    const { executeCheck } = await import("./passive.server.ts");
    return executeCheck(data);
  });
