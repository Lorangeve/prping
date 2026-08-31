import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// prping web 前端（SolidJS SPA，bun + vite）：构建产物 dist/ 经 just build/build-release
// 同步为二进制同目录 UI/；--features web-embed 时由 rust-embed 内嵌
// （见 crates/prping-core/src/web/assets.rs）。
// 开发模式：`prping web --port 8788` 起后端，再 `bun dev`（/ws 与 /config.json 代理过去）。
export default defineConfig({
  plugins: [solid()],
  build: { target: "es2022", sourcemap: false },
  server: {
    proxy: {
      "/config.json": "http://127.0.0.1:8788",
      "/ws": { target: "ws://127.0.0.1:8788", ws: true },
    },
  },
});
