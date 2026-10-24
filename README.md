# atrust-winserver

Install the **Sangfor aTrust** zero-trust client on **Windows Server** (2016/2019/2022), past the vendor's *"The program does not support installation on the server system!"* policy gate — without modifying the installer, its signature, or any file on disk.

> 在 Windows Server 上安装深信服 aTrust 客户端,绕过"不支持服务器系统"的策略拦截。不修改安装包、不破坏签名、不落盘任何改动。

## How the gate works

The check lives in `aTrustHelper.dll`, an NSIS plugin that the installer extracts to `%TEMP%\ns*.tmp\` at runtime. Its exported function `isWinServer` (confirmed by Ghidra decompilation of build 2.5.16.31):

```c
ULONGLONG mask = VerSetConditionMask(0, VER_PRODUCT_TYPE /*0x80*/, VER_EQUAL /*1*/);
OSVERSIONINFOEXW o1 = { .dwOSVersionInfoSize = sizeof(o1) };
o1.wProductType = VER_NT_DOMAIN_CONTROLLER;           // 2
if (VerifyVersionInfoW(&o1, VER_PRODUCT_TYPE, mask)) return SERVER;

OSVERSIONINFOEXW o2 = { .dwOSVersionInfoSize = sizeof(o1) };
o2.wProductType = VER_NT_SERVER;                      // 3
if (VerifyVersionInfoW(&o2, VER_PRODUCT_TYPE, mask)) return SERVER;
return WORKSTATION;   // -> NSIS aborts with ErrorLevel=7 when SERVER
```

The system product type comes from `KUSER_SHARED_DATA` — global and immutable per boot — so registry spoofing, compatibility modes and `ProductName` edits cannot change what `VerifyVersionInfoW` reports.

## Why the obvious approaches fail

| Approach | Why it fails |
|---|---|
| Repack the installer | Payload is encrypted (entropy ≈ 7.997); repacking also breaks the Authenticode signature |
| Patch the extracted DLL file | Re-extracted to a fresh random temp dir on every run; NSIS also loads/unloads the plugin repeatedly |
| Poll-and-patch in memory | The inner installer runs the check **milliseconds** after `LoadLibrary`; polling loses the race (verified experimentally) |

## The working approach: patch at DLL-load time under a debugger

`src/atrust_debug_patch.cs` starts the installer with `DEBUG_PROCESS`. The kernel then freezes the whole process tree on **every** `LOAD_DLL_DEBUG_EVENT` — before a single instruction of the freshly mapped DLL runs. On each load event the patcher:

1. Parses the mapped image's PE headers in-memory, locates `.text`.
2. Scans for two instruction signatures — the writes of the `wProductType` immediates `2`/`3` into the stack `OSVERSIONINFOEXW` (build-independent; `--rva rva1,rva2` is available as a manual fallback).
3. Flips the two immediate bytes `02`/`03` → `01` (`VER_NT_WORKSTATION`), so both `VerifyVersionInfoW` probes return FALSE on a Server system.

Since NSIS reloads the plugin dozens of times during one install, the patch is re-applied on every load (188 hits in the verified run). Two debugger artifacts are handled explicitly:

- `NtClose` on an invalid handle raises `STATUS_INVALID_HANDLE (0xC0000008)` **only when a debugger is attached** — swallowed with `DBG_CONTINUE` (without this the installer crashes).
- `DebugSetProcessKillOnExit(false)` so the installer tree survives the patcher.

Nothing is written to disk; the patch lives only in the install-time memory image.

## Usage

```text
csc /nologo /platform:x86 /out:atrust_debug_patch.exe atrust_debug_patch.cs   (any Windows Server has csc.exe)
atrust_debug_patch.exe "C:\path\to\aTrustInstaller.exe"                        (keep it running in background)
```

When the log shows `*** aTrustHelper.dll neutralized ***`, click through the installer UI (accept the license, hit install). Verify:

```powershell
Get-Service aTrustService                                  # Running
Get-CimInstance Win32_SystemDriver | ? Name -like 'aTrust*'   # aTrustNetflt_1 Running
Select-String "$env:APPDATA\Sangfor\aTrustInstaller\aTrustInstaller.log" -Pattern 'successfully installed'
```

**No AI agent required** — but [`docs/AI_AGENT_PROMPT.md`](docs/AI_AGENT_PROMPT.md) is a ready-to-paste, self-contained Chinese prompt that lets any command-executing AI coding agent (Claude Code / Cursor / Codex CLI / ...) perform the whole procedure on another machine, including the version-drift fallback.

## Verified

- Windows Server 2022 Datacenter (build 20348) + aTrust **2.5.16.31**
- Result: `aTrustService` running, kernel filter driver `aTrustNetflt_1` (`SdpNetFilter1.sys`) loaded and running, client processes (`aTrustAgent`, `aTrustXtunnel`) resident
- The decompiled check, byte offsets and full evidence chain: [`docs/REPORT.md`](docs/REPORT.md)
- Offline validation that the signature scan locates the patch sites uniquely: `tools/validate_scan.ps1`

## Files

```
src/atrust_debug_patch.cs   the debugger-timing patcher (C#, compiles with built-in csc.exe, no deps)
tools/validate_scan.ps1     offline signature-scan validator against a captured aTrustHelper.dll
tools/pe_exports.ps1        PE export-table parser (for locating isWinServer on new versions)
tools/pe_imports.ps1        PE import-table parser
tools/pe_analyze.ps1        export RVA + IAT-annotated hexdump helper for a captured DLL
docs/REPORT.md              full technical report (mechanism, byte-level analysis, evidence)
docs/AI_AGENT_PROMPT.md     self-contained Chinese prompt for AI agents on other machines
```

## Disclaimer

- For **authorized use on machines you administer** (e.g., your organization's own servers installing your organization's VPN client). Respect the vendor's EULA and your organization's policies.
- Sangfor does not officially support aTrust on Windows Server; the client installs kernel network-filter drivers. Validate on a non-production machine first and keep the uninstaller path (`C:\Program Files (x86)\Sangfor\aTrust\uninstall.exe`) in mind. The blocking check is a policy gate, not a proven incompatibility — the filter driver loads and runs fine on Server 2022 in the verified environment — but no warranty is provided.
- No Sangfor binaries, installers, or proprietary files are included in this repository; you supply your own installer.
- Not affiliated with Sangfor. "aTrust" is a trademark of Sangfor Technologies.

## License

MIT — see [LICENSE](LICENSE).
