# 深信服 aTrust 安装到 Windows Server 2022 — 诊断与实施报告

日期:2026-10-23 | 环境:Windows Server 2022 Datacenter(云桌面,10.0.20348)| 安装包:aTrust 2.5.16.31(网关 <gateway-host>:4433)

## 结论

**安装成功。** aTrustService 运行中,内核驱动 aTrustNetflt_1(SdpNetFilter1.sys)已加载,客户端进程(aTrustAgent/aTrustXtunnel)常驻。拦截是厂商策略性"检测到 Server 就拒绝",不是兼容性问题;已用**调试器时序的进程内 2 字节补丁**绕过,未改动安装包、未破坏签名。

## 拒绝机制(逆向结论)

外层启动器(93KB)→ 内层 NSIS 3.05 安装器(210MB,载荷加密,熵 7.997)→ 运行时把插件 `aTrustHelper.dll`(x86,959KB)解压到 `%TEMP%\1\nsXXXX.tmp\` 并加载。

**REA + Ghidra 12.1.4 反编译 `isWinServer`(0x3EAF0)确认的逻辑**(证据 ID `ev_9f0252ad6cb5bf21dcd28a557d75c5a88825d85ae4935ace8d09ca424681b83a`,与手工字节级分析一致):

```c
dwlConditionMask = VerSetConditionMask(0, VER_PRODUCT_TYPE /*0x80*/, VER_EQUAL /*1*/);
local_124.wProductType = '\x02';   // VER_NT_DOMAIN_CONTROLLER
if (VerifyVersionInfoW(&local_124, 0x80, dwlConditionMask)) goto is_server;
local_240.wProductType = '\x03';   // VER_NT_SERVER
if (VerifyVersionInfoW(&local_240, 0x80, dwlConditionMask)) goto is_server;
push 0 (非Server); return;
is_server: push 1; return;         // NSIS 脚本据此拒绝
```

NSIS 脚本拿到"server"后打印 "The program does not support installation on the server system!" 并 `SetErrorLevel=7` 退出。`VerifyVersionInfoW` 的产品类型来自系统全局(KUSER_SHARED_DATA),注册表无法欺骗。

## 为什么改包/常规方案都不可行(与前一位分析者结论一致)

- 载荷加密 → 无法解包重打包;重打包即破坏 Authenticode 签名
- 插件每次运行重新解压到随机临时目录 → 改临时文件不持久
- 纯轮询式进程内补丁追不上:内层进程从加载 DLL 到跑完检查仅数毫秒,且 NSIS 会反复卸载/重载插件

## 实际采用的方案(可行)

调试器时序补丁(`atrust_debug_patch.exe`,C# 编写,csc.exe 编译):

1. 以 `DEBUG_PROCESS` 启动安装器——进程树内**每次 DLL 加载都先冻结进程**等待处理,零竞态
2. 在 `aTrustHelper.dll` 的 LOAD_DLL 事件里(其代码尚未执行过一行)先校验两处 9 字节特征码,再把产品类型立即数改掉:
   - RVA 0x3EB87:`02`(VER_NT_DOMAIN_CONTROLLER)→ `01`(VER_NT_WORKSTATION)
   - RVA 0x3EBFA:`03`(VER_NT_SERVER)→ `01`
   - 效果:两次 EQUAL 查询在 Server 上都返回 FALSE → isWinServer 判定"非 Server"
3. 插件被 NSIS 反复重载,每次重载都重新补(本次安装共命中 188 次)
4. 调试用 `DebugSetProcessKillOnExit(false)`,补丁器退出不伤安装进程

**调试环境副作用及处理**:进程被调试时,`NtClose` 关闭无效句柄会抛 `STATUS_INVALID_HANDLE (0xC0000008)`(无调试器时仅返回错误)。安装器代码存在该路径,首次尝试因此崩溃;调试器对该异常码返回 `DBG_CONTINUE` 吞掉后,行为与无调试器一致。

## 安装结果验证

| 项目 | 状态 |
|---|---|
| 文件 | `C:\Program Files (x86)\Sangfor\aTrust\`(aTrustAgent/aTrustDefenser/aTrustTray/NetfltDriver/Vnic/Packages + uninstall.exe) |
| 服务 | aTrustService — Running / Automatic |
| 内核驱动 | aTrustNetflt_1(SdpNetFilter1.sys)— Running(说明驱动在 Server 2022 上签名与加载均正常) |
| 进程 | aTrustAgent ×2、aTrustXtunnel ×2 |
| 开始菜单 | 启动aTrust / 卸载aTrust 快捷方式 |
| 安装日志 | "Verify that the atrust client is successfully installed. end" |

## 风险与回滚

- 本机不支持系统还原点(云桌面限制),未建快照
- 回滚:开始菜单"aTrust\卸载aTrust"或 `C:\Program Files (x86)\Sangfor\aTrust\uninstall.exe`
- 补丁只影响安装过程内存,不修改任何文件;安装完成的客户端本体不含补丁,若客户端运行时另有 Server 检查需另行观察(目前未见异常)
- 升级/重装会被同样的 Server 检查拦截:重新运行 `atrust_debug_patch.exe <安装包>` 即可(新版本若改了 RVA,用 pe_analyze.ps1 重新定位)

## 工具与证据(本目录)

- `atrust_debug_patch.cs/.exe` — 调试器补丁器(核心交付物,可复用)
- `aTrustHelper.dll` — 现场抓取的检查插件
- `pe_exports.ps1 / pe_imports.ps1 / pe_analyze.ps1 / pe_delay.ps1 / pe_slots.ps1` — PE 静态分析脚本
- `aTrustInstaller_FINAL.log / install_FINAL.log` — 成功安装的完整日志
- `atrust_debug_patch.log` — 补丁器运行记录(188 次命中)
