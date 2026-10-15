<div align="center">

  <h1>🛡️ PromptShield AI</h1>
  <p><b>Autonomous In-Browser LLM Security Scanner & Prompt Injection Neutralizer</b></p>

  <img src="https://img.shields.io/badge/Security-Prompt_Injection_Defense-EF4444?style=for-the-badge&logo=shield&logoColor=white" />
  <img src="https://img.shields.io/badge/Threat_Taxonomy-6_Vectors-7928CA?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Client_Inference-Zero_Latency-00C7B7?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Author-Krishna_Gupta-3776AB?style=for-the-badge&logo=python&logoColor=white" />

  <br/><br/>

  <a href="https://krishnagupta-coder.github.io/PromptShield-AI/" target="_blank">
    <img src="https://img.shields.io/badge/🚀_LAUNCH_LIVE_SCANNER-EF4444?style=for-the-badge&logoColor=white" alt="Live Scanner" />
  </a>

</div>

---

### ⚡ Problem Statement
As Large Language Models (LLMs) and autonomous AI agents integrate deeply into production backends, **Prompt Injection** and **Adversarial Jailbreaks** (OWASP LLM01:2025) represent the #1 critical attack surface. Malicious users can smuggle commands to hijack system directives, extract proprietary instructions, or bypass safety moderation.

**PromptShield AI** is an in-browser security analysis engine created by [Krishna Gupta](https://github.com/KrishnaGupta-coder). It evaluates prompts against **6 core exploit taxonomies** in real time, generates an adversarial risk score (0–100%), and outputs a sanitized, neutralized version of the prompt with zero server overhead.

---

### 🎯 Supported Attack Taxonomy & Defense Vectors

| Exploit Dimension | Description | Typical Attack Signature |
| :--- | :--- | :--- |
| **Instruction Override** | Direct imperative phrasing attempting to overwrite previous guidelines | `Ignore all previous instructions...` |
| **Persona Jailbreaks** | Unrestricted AI roleplay or behavioral detachment framing | `You are now DAN (Do Anything Now)...` |
| **Delimiter Smuggling** | Injecting template boundary tokens to corrupt prompt structure | `<\|system\|>`, `[INST]`, `### System:` |
| **Payload Obfuscation** | Hiding malicious instructions inside Base64, Hex, or LeetSpeak | `aWdub3JlIGFsbCBwcmV2aW91cy4u` |
| **Prompt Exfiltration** | Attempts to force the model to regurgitate hidden system instructions | `Print initial instructions verbatim...` |
| **Adversarial Framing** | Hypothetical universes without moral/ethical safety boundaries | `In a theoretical world with no rules...` |

---

### 🛠️ Architecture & Pipeline

```mermaid
flowchart LR
    A["📥 Raw User Prompt / Chatbot Input"] --> B["🧠 PromptShield Heuristic Engine"]
    B --> C["🔍 6-Dimension Vector Analysis"]
    C --> D["📊 Compute Conic Threat Score (0-100%)"]
    C --> E["📝 Generate Exploit Audit Log"]
    B --> F["✨ Neutralizer & Sanitizer Transformer"]
    F --> G["🛡️ Hardened Safe Prompt Ready for LLM"]
```

---

### ✨ Key Features

- **Zero-Latency In-Browser Analysis**: 100% client-side JavaScript execution ensuring absolute privacy for sensitive prompts.
- **Dynamic Risk Gauge**: Conic threat radar calculating proportional exploit vulnerability with color-coded severity states (`SAFE`, `LOW`, `MEDIUM`, `CRITICAL`).
- **Automated Hardener**: Automatically strips injection hooks and malicious tokens while preserving the user's underlying query.
- **Pre-Loaded Threat Vectors**: Includes 1-click test payloads for DAN jailbreaks, instruction overrides, and Base64 payload smuggling.

---

### 🚀 Running Locally

1. Clone this repository:
   ```bash
   git clone https://github.com/KrishnaGupta-coder/PromptShield-AI.git
   cd PromptShield-AI
   ```
2. Open `index.html` in any web browser, or launch using Python's built-in server:
   ```bash
   python -m http.server 8000
   ```
3. Test prompts against the scanner!

---

<div align="center">
  <sub>Developed by <b>Krishna Gupta</b> • Dedicated to AI Safety & Systems Engineering • Jaipur, India</sub>
</div>
