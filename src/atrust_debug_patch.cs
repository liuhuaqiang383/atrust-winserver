using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

// atrust_debug_patch v2 — 让深信服 aTrust 安装包在 Windows Server 上放行安装。
// 原理:aTrustHelper.dll 的 isWinServer() 用 VerifyVersionInfoW(VER_PRODUCT_TYPE,
// VER_EQUAL) 判断系统产品类型是否为 2(域控)/3(服务器)。本工具以 DEBUG_PROCESS
// 启动安装器,在整个进程树的每次 DLL 加载事件(进程冻结、DLL 代码尚未执行)时,
// 扫描 .text 特征码定位这两处比较目标立即数,把 02/03 改为 01(VER_NT_WORKSTATION),
// 使两次查询都返回 FALSE。
//
// 用法: atrust_debug_patch.exe <安装包.exe> [--rva 0x3EB87,0x3EBFA]
//   默认:特征码自适应扫描(版本无关)
//   --rva:跳过扫描,直接补丁指定 RVA(逗号分隔两个,分别对应 02 和 03)
//
// 编译: csc /nologo /platform:x86 /out:atrust_debug_patch.exe atrust_debug_patch.cs
//   (aTrust 安装器是 x86;若未来出现 x64 安装器,改 /platform:x64 或 anycpu)
class AtrustDebugPatch
{
    // 2.5.16.31 上验证的两条指令序列(设置 OSVERSIONINFOEXW.wProductType):
    //  A: C7 45 F8 00 00 02 00 33 C0 89        mov dword[ebp-8],0x00020000 ; xor eax,eax ; mov ...
    //     (低16位 wSuiteMask=0,byte+2 即 wProductType=02 → 补丁索引 5)
    //  B: C7 85 xx xx xx xx 00 00 03 00 33 C0 89   mov dword[ebp-disp32],0x00030000 ; ...
    //     (中间4字节为任意栈偏移;补丁索引 8)
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
    const uint OUTPUT_DEBUG_STRING_EVENT = 8;
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
    static List<uint> fixedRvas = null;   // --rva 模式
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
        Log("debug patcher v2 starting; target=" + exe + (fixedRvas != null ? " fixed-rva mode: " + string.Join(",", fixedRvas.ConvertAll(r => "0x" + r.ToString("X"))) : " signature-scan mode"));

        var si = new STARTUPINFO(); si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();
        if (!CreateProcessW(exe, "\"" + exe + "\"", IntPtr.Zero, IntPtr.Zero, false, DEBUG_PROCESS, IntPtr.Zero, null, ref si, ref pi))
        { Log("CreateProcess failed err=" + Marshal.GetLastWin32Error()); return 3; }
        DebugSetProcessKillOnExit(false);   // 调试器退出不得杀死安装进程树
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
                        status = DBG_CONTINUE;   // NtClose(无效句柄) 仅在被调试时抛 0xC0000008,吞掉
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
        List<long> patchSites = fixedRvas != null
            ? ValidateFixedSites(h, dllBase)
            : ScanForSites(h, dllBase);
        if (patchSites == null) return;

        foreach (long site in patchSites)
        {
            byte want = 0x01;
            if (!WriteProcessMemory(h, (IntPtr)((long)dllBase + site), new byte[] { want }, (IntPtr)1, out got))
            { Log("WRITE FAILED pid=" + pid + " rva=0x" + site.ToString("X")); return; }
            Log("PATCHED pid=" + pid + " base=0x" + dllBase.ToString("X") + " rva=0x" + site.ToString("X") + " -> 0x01");
        }
        patchedLoads++;
        Log("*** aTrustHelper.dll neutralized (isWinServer now compares VER_NT_WORKSTATION) ***");
    }

    // --rva 模式:校验两个指定 RVA 处确为 02/03,防止填错
    static List<long> ValidateFixedSites(IntPtr h, IntPtr dllBase)
    {
        var sites = new List<long>();
        bool first = true;
        foreach (uint rva in fixedRvas)
        {
            byte[] b = new byte[1]; IntPtr got;
            if (!ReadProcessMemory(h, (IntPtr)((long)dllBase + rva), b, (IntPtr)1, out got)) return null;
            byte expect = first ? (byte)0x02 : (byte)0x03;
            if (b[0] != expect && b[0] != 0x01) { Log("fixed rva 0x" + rva.ToString("X") + " byte=0x" + b[0].ToString("X2") + " (expect 0x" + expect.ToString("X2") + ") - mismatch, skip"); return null; }
            sites.Add(rva); first = false;
        }
        return sites;
    }

    // 默认模式:解析内存中 PE 的 .text 段,双特征码定位补丁点
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
        if (secTab + 40 > hdr.Length) return null;   // 段表超出已读头部,不处理

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
            if (m) sites.Add(textRva + i + 5);   // 02 的位置
        }
        int bCount = 0;
        for (int i = 0; i + 13 <= text.Length; i++)
        {
            if (text[i] != PatB0[0] || text[i + 1] != PatB0[1]) continue;
            bool m = true;
            for (int k = 0; k < PatB1.Length; k++) if (text[i + 6 + k] != PatB1[k]) { m = false; break; }
            if (m) { sites.Add(textRva + i + 8); bCount++; }   // 03 的位置
        }
        bool hasA = sites.Count > bCount;
        if (!hasA || bCount == 0) return null;   // 必须两条都命中,否则不是目标镜像
        sites.Sort();
        return sites;
    }
}
