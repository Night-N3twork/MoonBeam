import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["test/integration/**/*.test.ts"],
    exclude: ["node_modules"],
    testTimeout: 30_000,
  },
});
