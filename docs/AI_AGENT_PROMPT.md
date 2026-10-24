# 任务:在这台 Windows Server 上安装深信服 aTrust 客户端(完整方案已验证,请严格照做)

> 使用说明(给最终用户):把本文件全部内容复制粘贴给任意**能执行命令**的 AI 编程工具(Claude Code / ZCode / Cursor / Codex CLI 等,需管理员权限终端)。纯聊天 AI 无法完成本任务。本方案已在 Windows Server 2022 Datacenter + aTrust 2.5.16.31 上完整验证成功。

---

## 你(AI 工具)要完成的事

在 Windows Server(2016/2019/2022 等)上安装深信服 aTrust 客户端。安装包运行后会因"检测到服务器系统"主动拒绝安装(日志表现为 `The program does not support installation on the server system!` + `SetErrorLevel=7`)。这是厂商策略性拦截,不是兼容性问题。解决方案是用**调试器时序补丁器**在拦截 DLL 加载瞬间修改 2 个字节。你的任务是按下述流程复现,不要自创方案。

## 背景(已逆向验证的机制,直接采信,无需重新逆向)

1. 安装包结构:外层启动器 → 内层 NSIS 安装器(载荷加密)→ 运行时把插件 `aTrustHelper.dll`(约 959KB,x86)解压到 `%TEMP%\nsXXXX.tmp\` 并加载。
2. 拦截点:`aTrustHelper.dll` 导出函数 `isWinServer`。其逻辑(已用 Ghidra 反编译逐行确认):
   ```c
   mask = VerSetConditionMask(0, VER_PRODUCT_TYPE /*0x80*/, VER_EQUAL /*1*/);
   osvi1.wProductType = 2;  // VER_NT_DOMAIN_CONTROLLER
   if (VerifyVersionInfoW(&osvi1, VER_PRODUCT_TYPE, mask)) -> 返回"是Server"
   osvi2.wProductType = 3;  // VER_NT_SERVER
   if (VerifyVersionInfoW(&osvi2, VER_PRODUCT_TYPE, mask)) -> 返回"是Server"
   否则返回"非Server"
   ```
   NSIS 脚本拿到"是Server"就拒绝安装。
3. `VerifyVersionInfoW` 的产品类型来自系统全局(KUSER_SHARED_DATA,开机固定),注册表/兼容性模式都骗不了;插件 DLL 每次运行重新解压、且被 NSIS 反复加载/卸载——所以**改安装包、改临时文件、轮询式注入全部不可行**,唯一可靠方案是调试器在 `LOAD_DLL_DEBUG_EVENT`(进程冻结、DLL 代码尚未执行)时补丁。
4. 补丁内容:把两处比较目标立即数 `02`/`03` 改为 `01`(VER_NT_WORKSTATION),两次查询即返回 FALSE → `isWinServer` 判定"非 Server" → 安装放行。2.5.16.31 的两处 RVA 为 `0x3EB87` 和 `0x3EBFA`(v2 补丁器默认用特征码自动定位,与版本无关)。

## 步骤 0:前置检查与安全网

1. 确认管理员权限终端(后续要写 Program Files、装服务/驱动)。
2. 尝试建还原点(失败不影响继续,云桌面通常不支持):
   ```powershell
   try { Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'before-aTrust' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop; 'restore point created' } catch { 'restore point not supported - continuing' }
   ```
3. 若本机之前有安装失败的残留:杀掉 `aTrustInstaller*`/`installer.exe` 残留进程,删除 `%APPDATA%\aTrustInstall_*` 目录和 `%TEMP%\ns*.tmp` 目录。

## 步骤 1:编译补丁器

把下面 C# 源码存为 `atrust_debug_patch.cs`(ASCII 即可):

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

// atrust_debug_patch v2 - patch aTrustHelper.dll isWinServer() at DLL-load time
// under a debugger so the aTrust installer proceeds on Windows Server.
class AtrustDebugPatch
{
    static readonly byte[] PatA = { 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x02, 0x00, 0x33, 0xC0, 0x89 };
    static readonly byte[] PatB0 = { 0xC7, 0x85 };
    static readonly byte[] PatB1 = { 0x00, 0x00, 0x03, 0x00, 0x33, 0xC0, 0x89 };

    const uint DEBUG_PROCESS = 0x1;
    const uint DBG_CONTINUE = 0x00010002;
    const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    const uint LOAD_DLL_DEBUG_EVENT = 6;
    const uint EXCEPTION_DEBUG_EVENT = 1;
    const uint EXCEPTION_BREAKPOINT = 0x80000003;
    const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    const uint STATUS_INVALID_HANDLE = 0xC0000008;
    const uint PROCESS_VM_READ = 0x10, PROCESS_VM_WRITE = 0x20, PROCESS_VM_OPERATION = 0x8;

    [StructLayout(LayoutKind.Sequential)]
    struct DEBUG_EVENT
    {
        public uint dwDebugEventCode, dwProcessId, dwThreadId;
        public IntPtr f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12,
                     f13, f14, f15, f16, f17, f18, f19, f20, f21, f22, f23, f24;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO { public uint cb; public string lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inh, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, ref PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WaitForDebugEvent(out DEBUG_EVENT e, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DebugSetProcessKillOnExit(bool kill);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr sz, out IntPtr rd);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr sz, out IntPtr wr);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    static string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "atrust_debug_patch.log");
    static void Log(string s)
    {
        string line = DateTime.Now.ToString("HH:mm:ss.fff") + "  " + s;
        Console.WriteLine(line);
        try { File.AppendAllText(logPath, line + Environment.NewLine); } catch { }
    }

    static Dictionary<uint, IntPtr> procHandles = new Dictionary<uint, IntPtr>();
    static List<uint> fixedRvas = null;
    static int patchedLoads = 0;

    static int Main(string[] args)
    {
        if (args.Length < 1) { Console.WriteLine("usage: atrust_debug_patch.exe <installer.exe> [--rva rva1,rva2]"); return 2; }
        string exe = Path.GetFullPath(args[0]);
        for (int i = 1; i < args.Length - 1; i++)
            if (string.Equals(args[i], "--rva", StringComparison.OrdinalIgnoreCase))
            {
                fixedRvas = new List<uint>();
                foreach (var p in args[i + 1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                    fixedRvas.Add(Convert.ToUInt32(p.Trim().Replace("0x", ""), 16));
            }
        Log("debug patcher v2 starting; target=" + exe + (fixedRvas != null ? " fixed-rva mode" : " signature-scan mode"));

        var si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();
        if (!CreateProcessW(exe, "\"" + exe + "\"", IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, ref pi))
        { Log("CreateProcess failed err=" + Marshal.GetLastWin32Error()); return 3; }
        DebugSetProcessKillOnExit(false);
        Log("debuggee pid=" + pi.dwProcessId);
        procHandles[pi.dwProcessId] = pi.hProcess;

        var ev = new DEBUG_EVENT();
        var deadline = DateTime.UtcNow.AddMinutes(90);
        while (DateTime.UtcNow < deadline)
        {
            if (!WaitForDebugEvent(out ev, 500)) continue;
            uint status = DBG_CONTINUE;
            switch (ev.dwDebugEventCode)
            {
                case CREATE_PROCESS_DEBUG_EVENT:
                    procHandles[ev.dwProcessId] = ev.f2;
                    Log("create process pid=" + ev.dwProcessId);
                    break;
                case LOAD_DLL_DEBUG_EVENT:
                    TryPatch(ev.dwProcessId, ev.f2);
                    break;
                case EXCEPTION_DEBUG_EVENT:
                    uint code = (uint)ev.f1.ToInt64();
                    if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP || code == STATUS_INVALID_HANDLE)
                        status = DBG_CONTINUE;
                    else
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    break;
                case EXIT_PROCESS_DEBUG_EVENT:
                    procHandles.Remove(ev.dwProcessId);
                    Log("exit process pid=" + ev.dwProcessId);
                    if (procHandles.Count == 0)
                    {
                        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                        Log("all debuggees exited; patched module loads=" + patchedLoads);
                        return patchedLoads > 0 ? 0 : 1;
                    }
                    break;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
        }
        Log("timeout; patched module loads=" + patchedLoads);
        return patchedLoads > 0 ? 0 : 1;
    }

    static void TryPatch(uint pid, IntPtr dllBase)
    {
        IntPtr h;
        if (!procHandles.TryGetValue(pid, out h) || dllBase == IntPtr.Zero) return;
        IntPtr got;
        List<long> patchSites = fixedRvas != null ? ValidateFixedSites(h, dllBase) : ScanForSites(h, dllBase);
        if (patchSites == null) return;

        foreach (long site in patchSites)
        {
            if (!WriteProcessMemory(h, (IntPtr)((long)dllBase + site), new byte[] { 0x01 }, (IntPtr)1, out got))
            { Log("WRITE FAILED pid=" + pid + " rva=0x" + site.ToString("X")); return; }
            Log("PATCHED pid=" + pid + " base=0x" + dllBase.ToString("X") + " rva=0x" + site.ToString("X") + " -> 0x01");
        }
        patchedLoads++;
        Log("*** aTrustHelper.dll neutralized (isWinServer now compares VER_NT_WORKSTATION) ***");
    }

    static List<long> ValidateFixedSites(IntPtr h, IntPtr dllBase)
    {
        var sites = new List<long>();
        bool first = true;
        foreach (uint rva in fixedRvas)
        {
            byte[] b = new byte[1]; IntPtr got;
            if (!ReadProcessMemory(h, (IntPtr)((long)dllBase + rva), b, (IntPtr)1, out got)) return null;
            byte expect = first ? (byte)0x02 : (byte)0x03;
            if (b[0] != expect && b[0] != 0x01) { Log("fixed rva 0x" + rva.ToString("X") + " byte=0x" + b[0].ToString("X2") + " mismatch"); return null; }
            sites.Add(rva); first = false;
        }
        return sites;
    }

    static List<long> ScanForSites(IntPtr h, IntPtr dllBase)
    {
        IntPtr got;
        byte[] hdr = new byte[0x400];
        if (!ReadProcessMemory(h, dllBase, hdr, (IntPtr)hdr.Length, out got)) return null;
        if (hdr[0] != (byte)'M' || hdr[1] != (byte)'Z') return null;
        int pe = BitConverter.ToInt32(hdr, 0x3C);
        if (pe <= 0 || pe + 0x100 > hdr.Length) return null;
        if (hdr[pe] != (byte)'P' || hdr[pe + 1] != (byte)'E') return null;
        int nSec = BitConverter.ToUInt16(hdr, pe + 6);
        int szOpt = BitConverter.ToUInt16(hdr, pe + 20);
        int secTab = pe + 24 + szOpt;
        if (secTab + 40 > hdr.Length) return null;

        byte[] text = null; long textRva = 0;
        for (int i = 0; i < nSec && secTab + (i + 1) * 40 <= hdr.Length; i++)
        {
            string name = System.Text.Encoding.ASCII.GetString(hdr, secTab + i * 40, 8).TrimEnd('\0');
            if (name == ".text")
            {
                textRva = BitConverter.ToUInt32(hdr, secTab + i * 40 + 12);
                uint vsize = BitConverter.ToUInt32(hdr, secTab + i * 40 + 8);
                if (vsize == 0 || vsize > 0x200000) return null;
                text = new byte[vsize];
                if (!ReadProcessMemory(h, (IntPtr)((long)dllBase + textRva), text, (IntPtr)vsize, out got) || got.ToInt64() != vsize) return null;
                break;
            }
        }
        if (text == null) return null;

        var sites = new List<long>();
        for (int i = 0; i + PatA.Length <= text.Length; i++)
        {
            bool m = true;
            for (int k = 0; k < PatA.Length; k++) if (text[i + k] != PatA[k]) { m = false; break; }
            if (m) sites.Add(textRva + i + 5);
        }
        int bCount = 0;
        for (int i = 0; i + 13 <= text.Length; i++)
        {
            if (text[i] != PatB0[0] || text[i + 1] != PatB0[1]) continue;
            bool m = true;
            for (int k = 0; k < PatB1.Length; k++) if (text[i + 6 + k] != PatB1[k]) { m = false; break; }
            if (m) { sites.Add(textRva + i + 8); bCount++; }
        }
        if (sites.Count - bCount == 0 || bCount == 0) return null;
        sites.Sort();
        return sites;
    }
}
```

编译(aTrust 安装器是 x86,补丁器必须同为 x86):

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /platform:x86 /out:atrust_debug_patch.exe atrust_debug_patch.cs
```

(若该路径无 csc.exe,试 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`;Windows Server 默认自带 .NET Framework。)

## 步骤 2:在补丁器下启动安装包

```
atrust_debug_patch.exe "C:\path\to\aTrustInstaller.exe"
```

- 在**后台/独立窗口**保持运行(不要提前关闭),日志在补丁器同目录 `atrust_debug_patch.log`。
- 数秒内日志应出现 `*** aTrustHelper.dll neutralized ***`——说明补丁已生效(插件每次被 NSIS 重载都会重新补,出现多次属正常)。
- 同时安装日志 `%APPDATA%\Sangfor\aTrustInstaller\aTrustInstaller.log` 里**不再出现** "The program does not support installation on the server system!"。

## 步骤 3:安装界面交互

安装窗口(标题"安装aTrust")弹出后:
1. 截图确认界面(屏幕上需勾选"我已阅读并同意《用户协议》"复选框,再点"立即安装";个别定制包可能无复选框或自动开始)。
2. 若你(AI)能模拟鼠标(`SetCursorPos` + `mouse_event`,坐标按截图实际位置):先点复选框,再点安装按钮。
3. 若你无法操作 UI,明确告诉用户:"安装窗口已弹出,请手动勾选协议并点击立即安装",期间补丁器保持运行。
4. 安装为静默推进(解压约 200MB、装服务与驱动,几分钟),窗口自动关闭后补丁器也会自行退出。

## 步骤 4:验证安装成功

```powershell
Get-Service aTrustService                                   # 应为 Running
Get-CimInstance Win32_SystemDriver | Where-Object Name -like 'aTrust*'   # aTrustNetflt_1 应为 Running
Get-Process | Where-Object Name -like 'aTrust*'             # aTrustAgent / aTrustXtunnel 应存在
Select-String -Path "$env:APPDATA\Sangfor\aTrustInstaller\aTrustInstaller.log" -Pattern 'successfully installed'  # 应有命中
Test-Path 'C:\Program Files (x86)\Sangfor\aTrust\uninstall.exe'   # 应为 True
```

全部通过即完成。开始菜单会出现"启动aTrust"。

## 兜底:补丁器报 signature not found / 日志无 neutralized(说明 aTrust 版本变了,特征码不同)

1. 直接双击/启动一次安装包(不经补丁器),让它把插件解压出来,出现拒绝提示后强杀 `aTrustInstaller*` 和 `%APPDATA%\aTrustInstall_*` 里派生的 `installer.exe` 进程。
2. 从 `%TEMP%\ns*.tmp\aTrustHelper.dll` 取出 DLL(959KB 左右、x86)。
3. 解析其 PE:导出表找 `isWinServer` 的 RVA,反汇编/dump 该函数字节(约 400 字节)。要找的是两条紧跟 `OSVERSIONINFOEXW` 初始化(sizeof 立即数 `1C 01 00 00`)之后的、向栈上 `+0x11A` 位置写产品类型的指令:
   - `C7 45 F8 00 00 02 00 ...`(mov dword[ebp-8], 0x20000 → 02 在 `C7` 后第 5 字节)
   - `C7 85 xx xx xx xx 00 00 03 00 ...`(03 在 `C7` 后第 8 字节)
   若编译器变体导致指令形态不同,找"把立即数 2 和 3 写入 OSVERSIONINFOEXW 结构 wProductType 偏移"的两条指令,记下 `02`/`03` 两个字节的 RVA。
4. 用 `--rva` 模式重跑(免重编译):
   ```
   atrust_debug_patch.exe "installer.exe" --rva 0x第一个,0x第二个
   ```
5. 仍找不到就停下,如实报告 DLL 版本信息(文件 SHA-256、导出表),说明需要人工逆向。

## 必读:已知坑(均已在工具中处理,不要"修复"它们)

- **被调试进程的 `NtClose`(无效句柄)会抛 `0xC0000008`**——无调试器时只是返回错误。源码中该异常码必须 `DBG_CONTINUE` 吞掉,否则安装器崩溃(已在 EXCEPTION_DEBUG_EVENT 分支处理)。
- **`DebugSetProcessKillOnExit(false)` 必须保留**——否则补丁器退出会杀死整个安装进程树。
- 插件被 NSIS **反复加载/卸载**(一次安装可重载上百次),每次 LOAD_DLL 都要重新补——这是设计行为。
- 不要用 `CREATE_SUSPENDED` 启动(外层启动器还会派生内层安装器,suspend 外层没用)。
- 不要修改安装包文件、不要重打包、不要改注册表 ProductType、不要用轮询式注入(时序必输)。

## 回滚

开始菜单 `aTrust\卸载aTrust`,或运行 `C:\Program Files (x86)\Sangfor\aTrust\uninstall.exe`。补丁只存在于安装过程的内存中,落盘文件无任何修改,卸载即完全恢复。

## 已验证环境

- Windows Server 2022 Datacenter(10.0.20348)+ aTrust 2.5.16.31(aTrustHelper.dll SHA-256 `a97b712176b48037a53e3ffc12c8d1cd5e0916c681b06de520d3c7af368359c4`),安装后 aTrustService、内核驱动 aTrustNetflt_1(SdpNetFilter1.sys)均正常运行。
