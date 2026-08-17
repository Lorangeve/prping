## 变更说明

<!-- 一句话说明这个 PR 做什么 -->

## 检查清单

- [ ] `cargo fmt --check` 通过
- [ ] `cargo clippy --all-targets -- -D warnings` 零警告
- [ ] `cargo test --all-targets` 全绿
- [ ] 涉及 Windows 路径时 `cargo check --target x86_64-pc-windows-msvc` 通过
- [ ] 用户可见输出已更新 i18n（`locales/en.yml` + `locales/zh-CN.yml`）
- [ ] 行为变更已更新 README / CHANGELOG
- [ ] 提交按逻辑主题分批，未夹带无关改动

## 变更类型

- [ ] 修复
- [ ] 新功能
- [ ] 性能
- [ ] 重构（行为零变更）
- [ ] 文档 / 测试
