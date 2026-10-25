# ADR-0061: VtHypervisor 归档业务代码调用彻底剥离与纯净虚拟机监控程序解耦规范

- **状态**: 已采纳
- **日期**: 2026-10-25
- **核心领域**: VT 核心架构 / 代码净化 / 模块解耦 / 死代码清除

---

## 一、 上下文与痛点

在完成 VT 架构拆分并将绘图、自瞄、游戏业务逻辑归档至 `vt/business_backup/`、将常驻桥接机制全面迁移至 `VtResidentPayload` 后，`VtHypervisor`（宿主基础 Hypervisor 内核）中仍然残留了大量针对旧业务的调用与临时兼容桩：
1. `hypercalls.cpp` 的 `test()` 函数原本包含了庞大的 `type == 1` 到 `20` 的旧业务分发逻辑，直接引用了 `CreateTexture`, `AimInfo`, `gameData`, `gameProcess`, `mouse_event`, `RenderInfo` 等已被归档的代码；
2. 顶部存在大量用于兼容编译的临时桩命名空间（`namespace game`, `namespace sjz`, `namespace hv` 中的渲染变量等）；
3. 诊断信息导出接口 `get_resident_hv_diag()` 中，`render_swapchain_ptr`、`render_buffer0_ptr` 等字段依赖这些外部业务变量指针，与 AMD 端（使用静态 `s_dummy_render`）实现不统一，存在跨平台行为差异与空指针/非规范地址解引用风险；
4. 末尾残留了十余个未被任何分发表引用的已归档死函数桩（`get_game_path`, `read_game_memory` 等）。

为了遵循系统架构的单一职责原则（Single Responsibility Principle）以及 `Ponytail Extreme` 极简规范，必须彻底清除 `VtHypervisor` 中的所有归档业务调用与死代码，恢复其作为纯净、高稳定硬件虚拟化内核的本质。

---

## 二、 技术决策与规范

1. **彻底物理删除已归档业务全局变量与临时兼容桩**：
   - 物理移除 `hypercalls.cpp` 顶部的 `buffer0`, `buffer0_hva`, `descBuffer`, `descBuffer_hva`, `swapChain`, `d2dRenderTarget`, `colorBrush`, `TextFormat`, `RenderInfo`, `CM_INFO`, `gameData`, `AimInfo`, `PmoValidationState` 等所有业务结构体与全局变量桩；
   - 彻底阻断任何对已归档模块的静态与动态依赖。

2. **恢复 `test()` 超调用为极简单行规范**：
   - 将 `void test(vcpu* const cpu)` 重构为标准单行 `skip_instruction();`，删除所有庞大的业务逻辑分支；
   - 确保 `hypercall_test` 不再执行任何未受保护的越界内存访问或跨进程解引用。

3. **诊断字段静态 Dummy 解耦 (对齐 AMD SVM 实现)**：
   - 在 `get_resident_hv_diag()` 中，为保持跨环通信结构体 `resident_hv_diag_record`（0x640 字节）与加载器/测试工具的二进制 ABI 严格兼容，已废弃的旧渲染字段统一指向模块局部的只读安全静态变量：
     ```cpp
     static uint64_t s_dummy_render = 0;
     out->render_swapchain_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_isfinish_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_d2d_rt_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_color_brush_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_text_format_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_buffer0_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_buffer0_hva_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_desc_buffer_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     out->render_desc_buffer_hva_ptr = reinterpret_cast<uint64_t>(&s_dummy_render);
     ```
   - 杜绝了外部通过诊断指针探测或读取时因无效地址引发的 `#PF` 或 `#GP` 蓝屏崩溃。

4. **死函数桩彻底物理清除**：
   - 在 `hypercalls.h` 与 `hypercalls.cpp` 中彻底清除 `get_game_path`, `get_game_module_info`, `hide_hv`, `unhide_hv`, `read_game_memory`, `write_game_memory`, `hide_cache_info`, `unhide_cache_info`, `get_gamevt_image_base`, `save_gamevt_image_base`, `call_function`, `add_vmcall_hook`, `enable_vmcall_hook`, `disable_vmcall_hook`, `remove_vmcall_hook` 等未引用的死声明与死实现；
   - 对应分发表未映射项统一在 `exit-handlers.cpp` 中安全返回 `cpu->ctx->rax = 0; skip_instruction();`。

---

## 三、 已知约束与避坑准则

1. **严禁破坏结构体 0x640 字节刚性 ABI 对齐**：
   - `resident_hv_diag_record` 受到 `static_assert(sizeof(...) == 0x640)` 与多端映射工具强约束，严禁随意删除或重排其中的废弃字段，必须通过静态合法变量地址填充。
2. **严禁混淆翻译脚本作用域**：
   - 汉化与维护内核注释时，严禁对代码逻辑中的变量名（如 `value`）执行机械全局替换，防止引入编译期未定义标识符错误。
3. **全线流水线验证闭环**：
   - 任何涉及 `VtHypervisor` 或 `VtResidentPayload` 的修改，必须保证 `VtBootstrapDriver` 的 `PackEmbeddedVtImages` 能够完整打包并重新计算哈希；
   - 必须通过 `python vt/verify_vt_layout.py` 的全量 38 项强断言检验。
