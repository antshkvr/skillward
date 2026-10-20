import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Discovery and scan tests touch the filesystem; slow Windows machines and CI runners need more than 5 s under load.
    testTimeout: 20_000,
  },
});
