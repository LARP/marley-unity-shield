using System;
using System.IO;
using System.Linq;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

namespace HoneyPot.Editor
{
    public static class BuildPipelineAutomation
    {
        public static void PerformBuild()
        {
            string[] args = Environment.GetCommandLineArgs();
            string condition = "C0";
            string outputExePath = "output/builds/C0/HoneyPot.exe";

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-buildCondition" && i + 1 < args.Length)
                {
                    condition = args[i + 1].ToUpper();
                }
                else if (args[i] == "-buildOutputPath" && i + 1 < args.Length)
                {
                    outputExePath = args[i + 1];
                }
            }

            Debug.Log($"[BuildPipelineAutomation] Configuring build for condition {condition} -> {outputExePath}");

            string outputDir = Path.GetDirectoryName(outputExePath);
            if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            NamedBuildTarget targetGroup = NamedBuildTarget.Standalone;

            switch (condition)
            {
                case "C0": // Mono basic
                    PlayerSettings.SetScriptingBackend(targetGroup, ScriptingImplementation.Mono2x);
                    PlayerSettings.stripEngineCode = false;
                    PlayerSettings.SetManagedStrippingLevel(targetGroup, ManagedStrippingLevel.Disabled);
                    PlayerSettings.SetIl2CppCompilerConfiguration(targetGroup, Il2CppCompilerConfiguration.Debug);
                    break;

                case "C1": // IL2CPP basic
                    PlayerSettings.SetScriptingBackend(targetGroup, ScriptingImplementation.IL2CPP);
                    PlayerSettings.stripEngineCode = false;
                    PlayerSettings.SetManagedStrippingLevel(targetGroup, ManagedStrippingLevel.Disabled);
                    PlayerSettings.SetIl2CppCompilerConfiguration(targetGroup, Il2CppCompilerConfiguration.Release);
                    break;

                case "C2": // IL2CPP Stripped
                    PlayerSettings.SetScriptingBackend(targetGroup, ScriptingImplementation.IL2CPP);
                    PlayerSettings.stripEngineCode = true;
                    PlayerSettings.SetManagedStrippingLevel(targetGroup, ManagedStrippingLevel.High);
                    PlayerSettings.SetIl2CppCompilerConfiguration(targetGroup, Il2CppCompilerConfiguration.Master);
                    break;

                case "C3": // IL2CPP Metadata Custom (Prepared for post-build encryption/scrambling)
                case "C4": // IL2CPP Header Patched
                    PlayerSettings.SetScriptingBackend(targetGroup, ScriptingImplementation.IL2CPP);
                    PlayerSettings.stripEngineCode = true;
                    PlayerSettings.SetManagedStrippingLevel(targetGroup, ManagedStrippingLevel.High);
                    PlayerSettings.SetIl2CppCompilerConfiguration(targetGroup, Il2CppCompilerConfiguration.Master);
                    break;

                default:
                    Debug.LogError($"[BuildPipelineAutomation] Unknown condition: {condition}");
                    EditorApplication.Exit(1);
                    return;
            }

            // Export ground truth in output folder as well
            string groundTruthPath = Path.Combine(outputDir, "ground_truth_symbols.json");
            GroundTruthExporter.ExportGroundTruth(groundTruthPath, BuildTarget.StandaloneWindows64.ToString(), condition);

            // Collect enabled scenes
            string[] scenes = EditorBuildSettings.scenes
                .Where(s => s.enabled)
                .Select(s => s.path)
                .ToArray();

            if (scenes.Length == 0)
            {
                // Fallback: look for scenes in Assets
                scenes = Directory.GetFiles("Assets", "*.unity", SearchOption.AllDirectories);
            }

            BuildPlayerOptions buildPlayerOptions = new BuildPlayerOptions
            {
                scenes = scenes,
                locationPathName = outputExePath,
                target = BuildTarget.StandaloneWindows64,
                options = BuildOptions.None
            };

            BuildReport report = BuildPipeline.BuildPlayer(buildPlayerOptions);
            BuildSummary summary = report.summary;

            if (summary.result == BuildResult.Succeeded)
            {
                Debug.Log($"[BuildPipelineAutomation] SUCCESS condition={condition} size={summary.totalSize} bytes to {outputExePath}");
                EditorApplication.Exit(0);
            }
            else
            {
                Debug.LogError($"[BuildPipelineAutomation] FAILED condition={condition} with result={summary.result}");
                EditorApplication.Exit(1);
            }
        }
    }
}
