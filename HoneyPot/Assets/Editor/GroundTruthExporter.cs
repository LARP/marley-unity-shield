using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

namespace HoneyPot.Editor
{
    [Serializable]
    public class FieldSymbolInfo
    {
        public string Name;
        public string Type;
        public bool IsStatic;
        public bool IsPublic;
        public bool IsLiteral;
        public string ConstantValue;
    }

    [Serializable]
    public class MethodSymbolInfo
    {
        public string Name;
        public string ReturnType;
        public List<string> Parameters = new List<string>();
        public bool IsStatic;
        public bool IsPublic;
        public int MetadataToken;
    }

    [Serializable]
    public class ClassSymbolInfo
    {
        public string FullName;
        public string Namespace;
        public string BaseType;
        public bool IsValueType;
        public bool IsStatic;
        public List<FieldSymbolInfo> Fields = new List<FieldSymbolInfo>();
        public List<MethodSymbolInfo> Methods = new List<MethodSymbolInfo>();
    }

    [Serializable]
    public class GroundTruthData
    {
        public string Timestamp;
        public string UnityVersion;
        public string BuildTarget;
        public string ScriptingBackend;
        public List<string> SensitiveStringsGroundTruth = new List<string>();
        public List<ClassSymbolInfo> Classes = new List<ClassSymbolInfo>();
    }

    /// <summary>
    /// Ground truth exporter generating ground_truth_symbols.json before or during build.
    /// Provides exact reference baseline for quantitative recovery metrics (RCR, SSS, ETR).
    /// </summary>
    public class GroundTruthExporter : IPreprocessBuildWithReport
    {
        public int callbackOrder => 0;

        public void OnPreprocessBuild(BuildReport report)
        {
            string outputPath = Path.Combine(Directory.GetCurrentDirectory(), "ground_truth_symbols.json");
            ExportGroundTruth(outputPath, report.summary.platform.ToString(), PlayerSettings.GetScriptingBackend(NamedBuildTarget.Standalone).ToString());
        }

        [MenuItem("HoneyPot/Export Ground Truth Symbols")]
        public static void ExportGroundTruthManual()
        {
            string projectRoot = Directory.GetCurrentDirectory();
            string defaultPath = Path.Combine(projectRoot, "ground_truth_symbols.json");
            ExportGroundTruth(defaultPath, EditorUserBuildSettings.activeBuildTarget.ToString(), PlayerSettings.GetScriptingBackend(NamedBuildTarget.Standalone).ToString());
            EditorUtility.DisplayDialog("Ground Truth Exporter", "Ground truth exported to: " + defaultPath, "OK");
        }

        public static void ExportSymbolsHeadless()
        {
            string[] args = Environment.GetCommandLineArgs();
            string destination = "ground_truth_symbols.json";
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-groundTruthOut" && i + 1 < args.Length)
                {
                    destination = args[i + 1];
                    break;
                }
            }

            ExportGroundTruth(destination, EditorUserBuildSettings.activeBuildTarget.ToString(), PlayerSettings.GetScriptingBackend(NamedBuildTarget.Standalone).ToString());
            Debug.Log("[GroundTruthExporter] Headless export completed: " + destination);
        }

        public static void ExportGroundTruth(string destinationPath, string buildTarget, string backend)
        {
            GroundTruthData data = new GroundTruthData
            {
                Timestamp = DateTime.UtcNow.ToString("o"),
                UnityVersion = Application.unityVersion,
                BuildTarget = buildTarget,
                ScriptingBackend = backend
            };

            // Ground truth sensitive strings from SecurityVault
            data.SensitiveStringsGroundTruth.Add("https://telemetry.anticheat.internal.example.org/v2/handshake");
            data.SensitiveStringsGroundTruth.Add("k7!9F#vP$2mZ&9qL*8sB4wE@1nC%5yD^");
            data.SensitiveStringsGroundTruth.Add("RAE_EXPERIMENT_SECURITY_SALT_TOKEN_99812");
            data.SensitiveStringsGroundTruth.Add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            data.SensitiveStringsGroundTruth.Add("SHA256_SIG_BALANCE_908123");

            // Inspect Assembly-CSharp
            Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
            Assembly targetAssembly = null;
            foreach (var asm in assemblies)
            {
                if (asm.GetName().Name == "Assembly-CSharp")
                {
                    targetAssembly = asm;
                    break;
                }
            }

            if (targetAssembly == null)
            {
                // Fallback to types found in current domain under HoneyPot namespace
                targetAssembly = typeof(GroundTruthExporter).Assembly;
            }

            Type[] allTypes = targetAssembly.GetTypes();
            foreach (Type t in allTypes)
            {
                if (string.IsNullOrEmpty(t.Namespace) || (!t.Namespace.StartsWith("HoneyPot") && !t.Name.Contains("Combat") && !t.Name.Contains("Security")))
                    continue;

                ClassSymbolInfo classInfo = new ClassSymbolInfo
                {
                    FullName = t.FullName,
                    Namespace = t.Namespace,
                    BaseType = t.BaseType != null ? t.BaseType.FullName : "System.Object",
                    IsValueType = t.IsValueType,
                    IsStatic = t.IsAbstract && t.IsSealed
                };

                // Fields
                FieldInfo[] fields = t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                foreach (var f in fields)
                {
                    FieldSymbolInfo fInfo = new FieldSymbolInfo
                    {
                        Name = f.Name,
                        Type = f.FieldType.FullName,
                        IsStatic = f.IsStatic,
                        IsPublic = f.IsPublic,
                        IsLiteral = f.IsLiteral,
                        ConstantValue = f.IsLiteral ? (f.GetRawConstantValue()?.ToString() ?? "null") : ""
                    };
                    classInfo.Fields.Add(fInfo);
                }

                // Methods
                MethodInfo[] methods = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);
                foreach (var m in methods)
                {
                    MethodSymbolInfo mInfo = new MethodSymbolInfo
                    {
                        Name = m.Name,
                        ReturnType = m.ReturnType.FullName,
                        IsStatic = m.IsStatic,
                        IsPublic = m.IsPublic,
                        MetadataToken = m.MetadataToken
                    };

                    foreach (var p in m.GetParameters())
                    {
                        mInfo.Parameters.Add($"{p.ParameterType.FullName} {p.Name}");
                    }
                    classInfo.Methods.Add(mInfo);
                }

                data.Classes.Add(classInfo);
            }

            string json = JsonUtility.ToJson(data, true);
            string dir = Path.GetDirectoryName(destinationPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(destinationPath, json);
            Debug.Log($"[GroundTruthExporter] Successfully written {data.Classes.Count} classes to {destinationPath}");
        }
    }
}
