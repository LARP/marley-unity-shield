# Contributing to Marley Unity Shield

Thank you for your interest in contributing to **Marley Unity Shield** (`marley-unity-shield`)! We welcome contributions from researchers, game developers, reverse engineers, and security analysts.

## Code of Conduct

By participating in this project, you agree to uphold open, civil, and constructive collaboration. Research contributions must adhere to defensive principles and ethical disclosure standards.

## How Can I Contribute?

### 1. Reporting Bugs & Issues
- Check the issue tracker to ensure the bug or feature hasn't already been reported.
- Clearly describe the environment (OS, Unity version, Python/Frida versions).
- Provide minimal reproducible steps and logs from `output/reports/` or Frida console.

### 2. Proposing Experimental Conditions or Hardening Techniques
- If proposing new compiler flags, metadata transformations, or runtime protections (e.g., C6, C7), provide formal hypotheses ($H_n$) and quantitative benchmarking criteria ($RCR$, $SSS$, $ETR$, Overhead).
- Ensure new test cases can be verified using the automated evaluation harness (`tools/evaluate_metrics.py`).

### 3. Submitting Pull Requests
1. Fork the repository `marley-games/marley-unity-shield`.
2. Create a feature branch: `git checkout -b feature/defense-mechanism-name`.
3. Follow existing code styles:
   - **C# / Unity:** Standard Unity C# conventions, clean separation between `HoneyPot/Assets/Scripts` (Runtime) and `HoneyPot/Assets/Editor` (Pipeline).
   - **Python:** PEP 8 compliance, explicit type hints, modular CLI arguments.
   - **JavaScript / Frida:** Modern ECMAScript, error-handled memory scans, clean interception hooks.
4. Verify tests and evaluation scripts:
   ```powershell
   python tools/build_matrix.py --condition ALL --mock
   python tools/evaluate_metrics.py
   ```
5. Commit using Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`).
6. Submit a Pull Request targeting `main` with a clear explanation of modifications.

## Package Architecture
- **UPM Package:** Core reusable scripts are distributed via the UPM package manifest at `Packages/com.marley.unityshield/package.json`.
- **HoneyPot Project:** Serves as the reference target testbed for experimental validation.
- **Tools:** Standalone orchestration and dynamic instrumentation suite.
