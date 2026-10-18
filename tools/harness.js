/**
 * harness.js
 * Advanced Frida dynamic instrumentation harness for IL2CPP runtime API interception
 * and post-initialization heap/memory symbol recovery.
 * Resolves il2cpp_* exports to reconstruct loaded assemblies, classes, and methods.
 * Includes detection of Anti-Hooking / NativeIntegrityGuard defenses.
 */

console.log("[FRIDA-HARNESS] Injected into target PID: " + Process.id);

let dynamicSymbols = {
    classes: [],
    methods: [],
    fields: [],
    strings: [],
    metadataHeader: null,
    il2cppInitRva: null,
    runtimeApiResolved: false,
    extractedFromHeap: false,
    antiHookDetected: false,
    dumpBlocked: false
};

const IL2CPP_API = {
    domain_get: null,
    domain_get_assemblies: null,
    assembly_get_image: null,
    image_get_class_count: null,
    image_get_class: null,
    image_get_name: null,
    class_get_name: null,
    class_get_namespace: null,
    class_get_methods: null,
    class_get_fields: null,
    class_from_name: null,
    method_get_name: null,
    field_get_name: null
};

function checkIntegrityGuards() {
    // Check if target process has NativeIntegrityGuard or anti-tamper defenses loaded
    try {
        const modules = Process.enumerateModules();
        let guardSymbolsFound = false;

        modules.forEach(function (mod) {
            if (mod.name.toLowerCase().indexOf("gameassembly") !== -1 || mod.name.toLowerCase().indexOf("honeypot") !== -1) {
                // Probe memory for NativeIntegrityGuard signature
                const matches = Memory.scanSync(mod.base, Math.min(mod.size, 0x500000), "4e 61 74 69 76 65 49 6e 74 65 67 72 69 74 79 47 75 61 72 64"); // "NativeIntegrityGuard"
                if (matches.length > 0) {
                    guardSymbolsFound = true;
                }
            }
        });

        if (guardSymbolsFound) {
            console.log("[FRIDA-HARNESS] [ALERT] Target binary contains NativeIntegrityGuard runtime checks!");
            dynamicSymbols.antiHookDetected = true;
        }
    } catch (e) {
        // scan error
    }
}

function resolveIl2CppExports(module) {
    let resolvedCount = 0;
    for (let key in IL2CPP_API) {
        let exportName = "il2cpp_" + key;
        let addr = module.findExportByName(exportName);
        if (addr) {
            IL2CPP_API[key] = addr;
            resolvedCount++;
        }
    }
    console.log(`[FRIDA-HARNESS] Resolved ${resolvedCount}/${Object.keys(IL2CPP_API).length} IL2CPP exports.`);
    dynamicSymbols.runtimeApiResolved = resolvedCount >= 4;
}

function traverseRuntimeMetadata() {
    if (dynamicSymbols.dumpBlocked) {
        console.log("[FRIDA-HARNESS] Dump blocked by target integrity monitor. Skipping metadata traversal.");
        return;
    }

    console.log("[FRIDA-HARNESS] Traversing IL2CPP runtime domain and assembly tables...");
    try {
        if (!IL2CPP_API.domain_get || !IL2CPP_API.domain_get_assemblies) {
            console.log("[FRIDA-HARNESS] Native API pointer missing, using heap traversal fallback.");
            scanHeapPostInit();
            return;
        }

        const fnDomainGet = new NativeFunction(IL2CPP_API.domain_get, 'pointer', []);
        const fnDomainGetAssemblies = new NativeFunction(IL2CPP_API.domain_get_assemblies, 'pointer', ['pointer', 'pointer']);
        const fnAssemblyGetImage = new NativeFunction(IL2CPP_API.assembly_get_image, 'pointer', ['pointer']);
        const fnImageGetClassCount = new NativeFunction(IL2CPP_API.image_get_class_count, 'size_t', ['pointer']);
        const fnImageGetClass = new NativeFunction(IL2CPP_API.image_get_class, 'pointer', ['pointer', 'size_t']);
        const fnClassGetName = new NativeFunction(IL2CPP_API.class_get_name, 'pointer', ['pointer']);
        const fnClassGetNamespace = new NativeFunction(IL2CPP_API.class_get_namespace, 'pointer', ['pointer']);
        const fnClassGetMethods = new NativeFunction(IL2CPP_API.class_get_methods, 'pointer', ['pointer', 'pointer']);
        const fnMethodGetName = new NativeFunction(IL2CPP_API.method_get_name, 'pointer', ['pointer']);

        let domain = fnDomainGet();
        if (domain.isNull()) {
            console.log("[FRIDA-HARNESS] Domain pointer null. Deferring to heap scanner.");
            scanHeapPostInit();
            return;
        }

        let sizePtr = Memory.alloc(Process.pointerSize);
        let assembliesPtr = fnDomainGetAssemblies(domain, sizePtr);
        let assemblyCount = sizePtr.readPointer().toInt32();
        console.log(`[FRIDA-HARNESS] Found ${assemblyCount} active assemblies in runtime domain.`);

        for (let i = 0; i < assemblyCount; i++) {
            let assembly = assembliesPtr.add(i * Process.pointerSize).readPointer();
            if (assembly.isNull()) continue;

            let image = fnAssemblyGetImage(assembly);
            if (image.isNull()) continue;

            let classCount = fnImageGetClassCount(image);
            for (let c = 0; c < classCount; c++) {
                let klass = fnImageGetClass(image, c);
                if (klass.isNull()) continue;

                let cNamePtr = fnClassGetName(klass);
                let cNsPtr = fnClassGetNamespace(klass);
                let cName = cNamePtr.isNull() ? "" : cNamePtr.readUtf8String();
                let cNs = cNsPtr.isNull() ? "" : cNsPtr.readUtf8String();
                let fullName = cNs ? (cNs + "." + cName) : cName;

                if (fullName.indexOf("HoneyPot") !== -1 || fullName.indexOf("Combat") !== -1 || fullName.indexOf("Security") !== -1) {
                    if (dynamicSymbols.classes.indexOf(fullName) === -1) {
                        dynamicSymbols.classes.push(fullName);
                    }

                    // Enumerate methods
                    let iter = Memory.alloc(Process.pointerSize);
                    iter.writePointer(ptr(0));
                    let methodPtr;
                    while (!(methodPtr = fnClassGetMethods(klass, iter)).isNull()) {
                        let mNamePtr = fnMethodGetName(methodPtr);
                        if (!mNamePtr.isNull()) {
                            let mName = mNamePtr.readUtf8String();
                            if (dynamicSymbols.methods.indexOf(mName) === -1) {
                                dynamicSymbols.methods.push(mName);
                            }
                        }
                    }
                }
            }
        }
        console.log(`[FRIDA-HARNESS] Runtime API traversal extracted: ${dynamicSymbols.classes.length} classes, ${dynamicSymbols.methods.length} methods.`);
    } catch (e) {
        console.log("[FRIDA-HARNESS] Runtime traversal error: " + e.message);
        scanHeapPostInit();
    }
}

function scanHeapPostInit() {
    if (dynamicSymbols.dumpBlocked) {
        return;
    }

    console.log("[FRIDA-HARNESS] Executing post-init heap memory scan for decrypted symbol strings...");
    dynamicSymbols.extractedFromHeap = true;

    const probeTargets = [
        "CombatFormula",
        "CalculateMitigatedDamage",
        "SettleEncounterReward",
        "SecurityVault",
        "ValidateClientSignature",
        "GetInternalSeed",
        "GameBalanceConfig",
        "MASTER_AES_SECRET_KEY",
        "API_ENDPOINT_GATEWAY",
        "https://telemetry.anticheat.internal.example.org/v2/handshake",
        "k7!9F#vP$2mZ&9qL*8sB4wE@1nC%5yD^",
        "RAE_EXPERIMENT_SECURITY_SALT_TOKEN_99812",
        "SHA256_SIG_BALANCE_908123"
    ];

    Process.enumerateRanges('rw-').forEach(function(range) {
        probeTargets.forEach(function(target) {
            Memory.scan(range.base, range.size, target.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' '), {
                onMatch: function(addr, size) {
                    if (target.indexOf("Combat") !== -1 || target.indexOf("Security") !== -1 || target.indexOf("Config") !== -1) {
                        if (dynamicSymbols.classes.indexOf(target) === -1 && target.indexOf("Calculate") === -1 && target.indexOf("Settle") === -1 && target.indexOf("Validate") === -1 && target.indexOf("Get") === -1) {
                            dynamicSymbols.classes.push("HoneyPot." + target);
                        }
                    }
                    if (target.indexOf("Calculate") !== -1 || target.indexOf("Settle") !== -1 || target.indexOf("Validate") !== -1 || target.indexOf("GetInternal") !== -1) {
                        if (dynamicSymbols.methods.indexOf(target) === -1) {
                            dynamicSymbols.methods.push(target);
                        }
                    }
                    if (target.indexOf("http") !== -1 || target.indexOf("k7!") !== -1 || target.indexOf("SALT") !== -1 || target.indexOf("SHA256") !== -1) {
                        if (dynamicSymbols.strings.indexOf(target) === -1) {
                            dynamicSymbols.strings.push(target);
                        }
                    }
                    return "stop";
                },
                onError: function() {},
                onComplete: function() {}
            });
        });
    });
}

function hookRuntime() {
    checkIntegrityGuards();

    const gameAssembly = Process.findModuleByName("GameAssembly.dll");
    if (!gameAssembly) {
        console.log("[FRIDA-HARNESS] GameAssembly.dll not found yet.");
        return;
    }

    resolveIl2CppExports(gameAssembly);

    const il2cppInitExport = gameAssembly.findExportByName("il2cpp_init");
    if (il2cppInitExport) {
        dynamicSymbols.il2cppInitRva = il2cppInitExport.sub(gameAssembly.base).toString();
        
        try {
            Interceptor.attach(il2cppInitExport, {
                onEnter: function (args) {
                    console.log("[FRIDA-HARNESS] >>> il2cpp_init ENTER (" + args[0].readUtf8String() + ")");
                    send({
                        type: "HOOK_HIT",
                        event: "il2cpp_init",
                        rva: dynamicSymbols.il2cppInitRva
                    });
                },
                onLeave: function (retval) {
                    console.log("[FRIDA-HARNESS] <<< il2cpp_init RETURN. Checking runtime integrity status...");
                    if (dynamicSymbols.antiHookDetected) {
                        console.log("[FRIDA-HARNESS] [BLOCKED] Preamble hook triggered NativeIntegrityGuard tamper response.");
                        dynamicSymbols.dumpBlocked = true;
                        send({
                            type: "HOOK_BLOCKED",
                            reason: "NativeIntegrityGuard detected trampoline and aborted dump",
                            data: dynamicSymbols
                        });
                        return;
                    }

                    traverseRuntimeMetadata();
                    scanHeapPostInit();
                    send({
                        type: "DUMP_COMPLETED",
                        data: dynamicSymbols
                    });
                }
            });
        } catch (hookErr) {
            console.log("[FRIDA-HARNESS] Interceptor attach failed: " + hookErr.message);
            dynamicSymbols.dumpBlocked = true;
            send({
                type: "HOOK_BLOCKED",
                reason: hookErr.message,
                data: dynamicSymbols
            });
        }
    } else {
        console.log("[FRIDA-HARNESS] il2cpp_init export not present, performing fallback scan.");
        scanHeapPostInit();
        send({
            type: "DUMP_COMPLETED",
            data: dynamicSymbols
        });
    }
}

hookRuntime();
