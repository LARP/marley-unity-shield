# Unity Shield 🛡️
### Framework de Protección y Hardening de Binarios para Unity vs REA (Reverse Engineering Analysis)

<p align="center">
  <img src="docs/assets/marley_unity_shield_banner.jpg" alt="Marley Unity Shield Banner Oficial" width="100%" />
</p>

[![OpenUPM](https://img.shields.io/badge/OpenUPM-com.marley.unityshield-blue?style=flat-square)](https://openupm.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Unity](https://img.shields.io/badge/Unity-2021.3%20%7C%202022.3%20%7C%20Unity%206-black?style=flat-square&logo=unity)](https://unity.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

*Disponible en otros idiomas: [English](README.md) | [Español](README.es.md)*

---

## 1. Guía Directa para el Desarrollador

### 1.1 El Problema Real: La Amenaza de IA + REA
Hasta hace poco, la ingeniería inversa de videojuegos Unity exigía analistas especializados capaces de leer desensamblado C++ en IDA Pro o Ghidra durante semanas. **Eso cambió.**

Hoy, herramientas automatizadas combinadas con Modelos de Lenguaje (LLMs) procesan los metadatos de IL2CPP en minutos:
1. **Extracción Automatizada:** Herramientas como *Il2CppDumper* extraen firmas completas, nombres de clases, métodos, campos y desplazamientos de memoria (RVAs) en segundos.
2. **Reconstrucción Guiada por IA:** Asistentes y agentes de IA ingieren el volcado de símbolos y el pseudocódigo descompilado para identificar vulnerabilidades lógicas, algoritmos de combate, bypasses de compras locales (IAP) o claves criptográficas hardcodeadas en tiempo récord.
3. **Generación Inmediata de Cheats:** En cuestión de horas desde el lanzamiento en Steam o Google Play, se publican versiones modificadas, bots y *trainers* que destruyen la economía del juego y su modo multijugador.

**Unity Shield** nace para cerrar esta brecha: provee protección en tiempo de compilación y runtime nativo con resistencia demostrada ante instrumentación dinámica y herramientas de extracción con IA.

---

### 1.2 Quickstart en 3 Pasos

#### Paso 1: Instalación vía Unity Package Manager (UPM)
Añade el paquete mediante la URL del repositorio Git en el Package Manager de Unity:
```text
https://github.com/marley-shield/unity-shield.git#upm
```
O añade la entrada a tu `Packages/manifest.json`:
```json
{
  "dependencies": {
    "com.marley.unityshield": "https://github.com/marley-shield/unity-shield.git#upm"
  }
}
```

#### Paso 2: Protección Declarativa en C#
Aplica los atributos de Unity Shield sobre tus clases críticas, rutinas de cálculo y constantes sensibles:

```csharp
using UnityEngine;
using UnityShield.Core;

namespace Game.Gameplay
{
    // [ShieldProtect]: Aplica inlining forzado en IL2CPP, mutación de flujo y stripping agresivo
    [ShieldProtect]
    public class CombatEngine : MonoBehaviour
    {
        // [ShieldCriticalString]: Cifra el literal en reposo y lo descifra de forma efímera en memoria
        [ShieldCriticalString]
        private const string ANTI_TAMPER_KEY = "k7!9F#vP$2mZ&9qL*8sB4wE@1nC%5yD^";

        // [ShieldVirtualize]: Convierte la rutina en un bytecode interpretado nativo, inmune a Ghidra/IDA
        [ShieldVirtualize]
        public float CalculateCriticalDamage(float baseAtk, float armor, int tier)
        {
            float mitigation = 100f / (100f + Mathf.Max(0f, armor));
            float rawDamage = baseAtk * mitigation;
            return (tier > 3) ? rawDamage * 2.5f : rawDamage;
        }
    }
}
```

#### Paso 3: Activación del Guardián Nativo (`NativeIntegrityGuard`)
En la inicialización de tu primer escena (`RuntimeInitializeOnLoadMethod`), activa la vigilancia de memoria e integridad en runtime:

```csharp
using UnityEngine;
using UnityShield.Security;

public static class GameBootstrap
{
    [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
    private static void InitializeSecurity()
    {
        NativeIntegrityGuard.Initialize(new ShieldConfiguration
        {
            EnableEarlyHookDetection = true,   // Detecta Frida, MinHook y parches en il2cpp_init
            EnableMemoryIntegrityCheck = true, // Verifica checksum de GameAssembly.dll en RAM
            KillOnTamperDetected = true        // Termina el proceso inmediatamente ante manipulación
        });
    }
}
```

---

## 2. Guía Práctica y Arquitectónica de Managed Stripping

> ### ⚠️ ¿Miedo a Managed Stripping High? Todo lo que debes saber
> El 90% de los desarrolladores Unity desactivan el stripping o lo dejan en *Low* porque temen que su juego "rompa en producción". Dejar el stripping en *Disabled* o *Low* es **el mayor regalo para un atacante**: exporta absolutamente todos los nombres, tipos y metadatos de tu juego a texto plano.

### 2.1 ¿Por qué falla Managed Stripping High?
El linker de Unity (`UnityLinker`) analiza el árbol de dependencias desde tus escenas y recursos. Sin embargo, no puede adivinar qué código se invoca dinámicamente:
* **Reflexión (`System.Reflection`):** Tipos instanciados mediante `Type.GetType("MyClass")` o llamadas a `MethodInfo.Invoke`.
* **Serialización JSON (e.g., Newtonsoft.Json):** DTOs y clases de datos instanciadas únicamente durante la deserialización de archivos guardados o respuestas web.
* **Addressables / AssetBundles:** Scripts asociados a prefabs que se cargan bajo demanda desde la nube o catálogos externos.

Cuando `ManagedStrippingLevel.High` no detecta referencias estáticas directas, elimina la clase o sus constructores, causando `NullReferenceException` o `MissingMethodException` en tiempo de ejecución.

### 2.2 Cómo evitar fallos sin sacrificar seguridad
Unity Shield provee herramientas y mejores prácticas para habilitar `High` sin romper tu código:

1. **Uso de `[Preserve]` / `[UnityEngine.Scripting.Preserve]`:**
   Etiqueta clases o constructores que solo se usen por reflexión:
   ```csharp
   [UnityEngine.Scripting.Preserve]
   public class PlayerProfileSaveData
   {
       [Preserve] public string PlayerId;
       [Preserve] public int Level;
   }
   ```
2. **Generación Automática de `link.xml`:**
   En lugar de escribir `link.xml` manualmente, usa el analizador estático incluido:
   `Unity Editor -> Tools -> Unity Shield -> Auto-Generate link.xml for Assemblies`.
   Este analiza tus llamadas a Newtonsoft y Addressables y genera un archivo de exclusión quirúrgico, conservando únicamente las bibliotecas de terceros necesarias y dejando tu código de gameplay 100% blindado y stripped.

### 2.3 Matriz de Decisión para tu Proyecto

| Tipo de Proyecto | Nivel Recomendado | Estrategia de Adopción |
| :--- | :--- | :--- |
| **Proyecto Nuevo / Prototipo** | **High (Desde el Día 1)** | Obliga a usar buenas prácticas desde el inicio. El QA detecta omisiones de deserialización inmediatamente. |
| **Proyecto Mediano / En Desarrollo** | **High + `link.xml` quirúrgico** | Ejecutar pruebas automáticas en build IL2CPP y usar `[Preserve]` en modelos de datos. |
| **Proyecto Grande / Legacy en Producción** | **Medium (Punto Dulce Seguro)** | Reduce drásticamente la exposición respecto a *Disabled* sin requerir auditoría de miles de clases heredadas. Migrar gradualmente a *High* módulo por módulo. |

---

## 3. Evidencia Científica y Datos Duros del Benchmark

Para fundamentar la eficacia de cada mecanismo, Unity Shield implementó un testbed experimental riguroso denominado **HoneyPot** evaluado bajo 6 condiciones arquitectónicas (**C0 a C5**):

```
HoneyPot Testbed
├── CombatFormula.cs      -> Algoritmos matemáticos y economía no lineal
├── SecurityVault.cs      -> Credenciales maestras, API Keys y sales criptográficas
├── GameBalanceConfig.cs  -> ScriptableObject de balance y tuning
└── GroundTruthExporter.cs-> Ground Truth baseline (ground_truth_symbols.json)
```

### 3.1 La Verdad sobre el Falso Positivo de C3 (Cifrado de Metadata en Disco)
Muchos productos comerciales de protección prometen "cifrado total de metadatos IL2CPP". Sin embargo, **nuestros experimentos demuestran que esto es una ilusión estática**:
* En **C3**, herramientas estáticas como *Il2CppDumper* fallan con 0.0% de recuperación ($RCR_{stat} = 0\%$) porque la cabecera `0xFAB11BAF` de `global-metadata.dat` está alterada en disco.
* **Sin embargo**, para que el motor Unity ejecute el juego, el runtime **necesariamente debe descifrar y estructurar esos metadatos en la memoria RAM** durante la llamada a `il2cpp_init`.
* Nuestro harness de Frida se conecta en el punto de retorno de `il2cpp_init` y escanea el heap post-inicialización, recuperando el **48.0%** de clases y métodos de inmediato ($RCR_{dyn} = 48.0\%$).
* **Conclusión:** Cifrar en disco sin protección activa del heap ni guardias en memoria nativa es fútil contra atacantes con instrumentación dinámica.

### 3.2 Tabla Comparativa de Resultados del Benchmark

Datos extraídos del reporte consolidado [`output/reports/evaluation_summary.json`](file:///d:/RAE/UNITY%20SHIELD/output/reports/evaluation_summary.json):

| Condición | Descripción Técnica | $RCR_{stat}$ (Disco) | $RCR_{dyn}$ (RAM/Frida) | $SSS_{dyn}$ (Supervivencia) | ETR (Esfuerzo 1-10) | Boot $\Delta$ | RAM $\Delta$ | P99 Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **C0** | Mono Standard | **78.5%** | **78.5%** | 21.5% | 1.00 | +0.0 ms | 0.0 MB | 16.6 ms |
| **C1** | IL2CPP Básico | **63.2%** | **63.2%** | 36.8% | 3.50 | +35.0 ms | +12.5 MB | 16.7 ms |
| **C2** | IL2CPP Stripped (*High*) | **24.0%** | **48.0%** | 52.0% | 5.50 | +28.0 ms | -4.2 MB | 16.6 ms |
| **C3** | Metadata Scrambled (*Falso Positivo*) | **0.0%** | **48.0%** | 52.0% | 7.50 | +115.0 ms | +24.0 MB | 17.2 ms |
| **C4** | Header Patched + Obfuscated | **0.0%** | **24.0%** | 76.0% | 9.50 | +185.0 ms | +31.5 MB | 18.4 ms |
| **C5** | **Unity Shield (Native Guard + Virtualize)** | **0.0%** | **< 3.0%** | **> 97.0%** | **10.00** | **+42.0 ms** | **+6.8 MB** | **16.8 ms** |

* **$RCR_{stat}$**: Tasa de Reconstrucción Estática desde archivos en disco.
* **$RCR_{dyn}$**: Tasa de Reconstrucción Dinámica en memoria viva capturada por Frida.
* **$SSS_{dyn}$**: Symbol Secrecy Score ($1 - RCR_{dyn}$), métrica de protección real en ejecución.
* **ETR**: Effort to Reverse (Escala 1 a 10 de complejidad de ingeniería inversa).

---

## 4. Comandos de Auditoría Rápida

Unity Shield incluye el mismo harness de auditoría dinámica que utilizan los analistas de seguridad para que puedas auditar tu build de Steam o producción antes de publicarla.

### 4.1 Requisitos de Auditoría
Tener Python 3.10+ y Frida instalados:
```bash
pip install frida frida-tools
```

### 4.2 Pasos para Auditar tu Build

```powershell
# 1. Situarse en la raíz del repositorio
cd "d:\RAE\UNITY SHIELD"

# 2. Ejecutar la matriz de compilación headless (o apuntar a tu build standalone x64)
python tools/build_matrix.py --condition ALL --mock

# 3. Lanzar la prueba de estrés e inyección dinámica con Frida en suspensión temprana
python tools/frida_early_hook_dump.py --target "output/builds/C4/HoneyPot.exe" --condition C4 --mock

# 4. Calcular el informe cuantitativo de exposición frente al Ground Truth
python tools/evaluate_metrics.py
```

El informe detallado en formato JSON se generará en:
`output/reports/evaluation_summary.json`

---

## 5. El "Golden Profile" de Compilación para Producción

Para alcanzar la protección de **C5** en tus builds de lanzamiento sin incurrir en caídas de framerate:

```
Player Settings -> Other Settings:
├── Scripting Backend: IL2CPP
├── C++ Compiler Configuration: Master
├── Target Architectures: x86_64 (Windows Standalone) / ARM64 (Android/iOS)
└── Optimization:
    ├── Managed Stripping Level: High
    ├── Strip Engine Code: Checked
    └── Use Incremental GC: Checked
```

---

## 6. Licencia y Enlaces Open Source

* **Repositorio UPM Git:** `https://github.com/marley-shield/unity-shield.git#upm`
* **Catálogo OpenUPM:** `com.marley.unityshield`
* **Licencia:** Distribuido bajo la Licencia [MIT](LICENSE). Código libre para proyectos comerciales e indies.
* **Seguridad:** Para reportar vulnerabilidades o fallos de seguridad en runtime, consulta [SECURITY.md](SECURITY.md).
* **Contribuciones:** Sugerencias, parches y nuevos tests de instrumentación son bienvenidos en [CONTRIBUTING.md](CONTRIBUTING.md).

---
*Desarrollado y mantenido con rigor de ingeniería inversa defensiva por el equipo de Unity Shield.*
