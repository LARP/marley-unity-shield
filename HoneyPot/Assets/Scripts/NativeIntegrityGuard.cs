using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using UnityEngine;

namespace HoneyPot.Security
{
    /// <summary>
    /// Runtime Integrity & Anti-Hooking Engine (Condition C5 Hardened Guard).
    /// Performs in-memory preamble auditing of GameAssembly.dll exports to detect inline hooking / trampolines,
    /// and scans process modules to intercept dynamic instrumentation agents (Frida, Gum, Substrate).
    /// </summary>
    public class NativeIntegrityGuard : MonoBehaviour
    {
        private static bool _isIntegrityCompromised = false;
        private static readonly List<string> DetectedViolations = new List<string>();

        // Win32 P/Invoke declarations
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        private static extern void ExitProcess(uint uExitCode);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        // Suspicious binaries known in Frida / dynamic instrumentation ecosystem
        private static readonly string[] BlacklistedModuleSignatures = new string[]
        {
            "frida-agent",
            "frida-gadget",
            "frida",
            "gum-js-loop",
            "gadget",
            "cydiasubstrate",
            "hookshim"
        };

        // Critical IL2CPP exports subject to trampoline hooks by REA harnesses
        private static readonly string[] CriticalIl2CppExports = new string[]
        {
            "il2cpp_init",
            "il2cpp_domain_get",
            "il2cpp_domain_get_assemblies",
            "il2cpp_assembly_get_image",
            "il2cpp_image_get_class_count",
            "il2cpp_image_get_class",
            "il2cpp_class_get_methods",
            "il2cpp_class_get_name",
            "il2cpp_method_get_name"
        };

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        public static void InitializeGuard()
        {
            EvaluateIntegrity(abortOnViolation: false);
        }

        /// <summary>
        /// Evaluates both active module injections and function preamble integrity.
        /// Returns true if the environment is strictly intact; false if hooked or tampered.
        /// </summary>
        public static bool EvaluateIntegrity(bool abortOnViolation = true)
        {
            DetectedViolations.Clear();

            bool modulesClean = ScanSuspiciousModules();
            bool preamblesClean = VerifyExportPreambles();

            _isIntegrityCompromised = (!modulesClean || !preamblesClean);

            if (_isIntegrityCompromised)
            {
                UnityEngine.Debug.LogWarning("[NativeIntegrityGuard] TAMPER DETECTED: Runtime integrity verification failed!");
                foreach (var v in DetectedViolations)
                {
                    UnityEngine.Debug.LogWarning($"[NativeIntegrityGuard] Violation: {v}");
                }

                if (abortOnViolation)
                {
                    EnforceSelfDefense();
                }
                return false;
            }

            return true;
        }

        /// <summary>
        /// Scans all loaded PE modules for known dynamic instrumentation frameworks (Frida, Gum, etc.).
        /// </summary>
        public static bool ScanSuspiciousModules()
        {
            bool clean = true;
            try
            {
                Process currentProcess = Process.GetCurrentProcess();
                foreach (ProcessModule module in currentProcess.Modules)
                {
                    string modName = module.ModuleName.ToLowerInvariant();
                    for (int i = 0; i < BlacklistedModuleSignatures.Length; i++)
                    {
                        if (modName.Contains(BlacklistedModuleSignatures[i]))
                        {
                            clean = false;
                            DetectedViolations.Add($"Suspicious module loaded: {module.ModuleName} at 0x{module.BaseAddress.ToInt64():X}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Access issues or stripped process APIs
                UnityEngine.Debug.Log($"[NativeIntegrityGuard] Module enumeration notice: {ex.Message}");
            }

            return clean;
        }

        /// <summary>
        /// Audits function entry opcodes of GameAssembly.dll exports.
        /// Detects x86/x64 inline hooking trampolines:
        /// - 0xE9 (JMP rel32)
        /// - 0xFF 0x25 (JMP qword ptr [rip + offset])
        /// - 0x48 0xB8 ... 0xFF 0xE0 (MOV RAX, imm64 ; JMP RAX)
        /// - 0xCC (INT3 software breakpoint)
        /// </summary>
        public static bool VerifyExportPreambles()
        {
            IntPtr hGameAssembly = GetModuleHandleA("GameAssembly.dll");
            if (hGameAssembly == IntPtr.Zero)
            {
                // In Mono or test mock environment, GameAssembly might not be loaded
                return true;
            }

            bool clean = true;
            byte[] preambleBuffer = new byte[16];

            for (int i = 0; i < CriticalIl2CppExports.Length; i++)
            {
                string exportName = CriticalIl2CppExports[i];
                IntPtr pFunc = GetProcAddress(hGameAssembly, exportName);
                if (pFunc == IntPtr.Zero) continue;

                try
                {
                    Marshal.Copy(pFunc, preambleBuffer, 0, preambleBuffer.Length);

                    // Check for inline hook signatures
                    if (preambleBuffer[0] == 0xE9)
                    {
                        clean = false;
                        DetectedViolations.Add($"Inline Hook detected at {exportName} (0xE9 JMP rel32 trampoline).");
                    }
                    else if (preambleBuffer[0] == 0xFF && preambleBuffer[1] == 0x25)
                    {
                        clean = false;
                        DetectedViolations.Add($"Indirect Trampoline detected at {exportName} (0xFF 0x25 JMP [RIP+disp32]).");
                    }
                    else if (preambleBuffer[0] == 0x48 && preambleBuffer[1] == 0xB8 && preambleBuffer[10] == 0xFF && preambleBuffer[11] == 0xE0)
                    {
                        clean = false;
                        DetectedViolations.Add($"64-bit Absolute Hook detected at {exportName} (MOV RAX, imm64 ; JMP RAX).");
                    }
                    else if (preambleBuffer[0] == 0xCC)
                    {
                        clean = false;
                        DetectedViolations.Add($"Breakpoint detected at {exportName} (0xCC INT3).");
                    }
                }
                catch (Exception)
                {
                    // Memory read protection or restricted page
                }
            }

            return clean;
        }

        /// <summary>
        /// Anti-Tamper response: aborts execution immediately without standard managed exceptions.
        /// </summary>
        public static void EnforceSelfDefense()
        {
            try
            {
                ExitProcess(0xC0000022); // STATUS_ACCESS_DENIED
            }
            catch
            {
                Environment.FailFast("Integrity check failed: unauthorized dynamic hook injection detected.");
            }
        }

        public static bool IsCompromised => _isIntegrityCompromised;
        public static IReadOnlyList<string> Violations => DetectedViolations;
    }
}
