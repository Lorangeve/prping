import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// prping web 前端（SolidJS SPA）：构建产物 dist/ 由 rust-embed 内嵌进 prping 二进制
// （debug 直读、release 编译期内嵌，见 crates/prping-core/src/web/assets.rs）。
// 开发模式：`prping web --port 8788` 起后端，再 `pnpm dev`（/ws 与 /config.json 代理过去）。
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
