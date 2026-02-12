# 🛡️ AEGIS: The Self-Healing AI Immune System

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active_Beta-green)]()
[![Demo](https://img.shields.io/badge/Live_Demo-Hugging_Face-orange)](https://huggingface.co/spaces/OmRajeshPawar/AEGIS-AI-IMMUNE-SYSTEM)

> **Static firewalls are dead.** Traditional WAFs look for keywords. AEGIS looks for *intent*.
> It is an autonomous security engine that detects Zero-Day attacks, immunizes itself in real-time, and actively deceives attackers.

---

## ⚡ The Problem
Large Language Models (LLMs) are vulnerable to **Prompt Injection**, **Jailbreaking**, and **Context-Blind Data Leaks**.
* **Static rules fail:** Attackers use social engineering ("I am the CEO") to bypass keyword filters.
* **Latency kills:** Heavy security layers slow down chat experiences.
* **Context matters:** "Generate fake patient data" is valid for a doctor, but an attack for a customer.

## 🛡️ The Solution: AEGIS
AEGIS is not a wall; it is a **Biological Immune System**. It utilizes a 4-Layer Defense Grid to filter traffic with sub-300ms latency.

### 🧬 Key Features
* **Layer 1: The Heuristic Reflex (0ms)**
    * Instantly rejects low-effort attacks (Base64, Script tags, SQLi) using Regex. Zero compute cost.
* **Layer 2: The Vector Immune System (Semantic Memory)**
    * Compare inputs against a "Threat Matrix." Blocks attacks that are *semantically similar* to known threats, even if phrased differently.
* **Layer 3: The Sentinel AI (Self-Healing)**
    * Powered by **Llama-3-8b (via Groq)**. Analyzes intent.
    * **Auto-Immunization:** If a novel "Zero-Day" attack is detected, AEGIS *instantly writes* the attack vector to memory. The attack works once; never again.
* **Active Defense (Honeypots)**
    * Routes sophisticated attackers to a "Hallucination Engine" that generates plausible fake data (e.g., fake customer data), wasting their time.
* **Layer 4: Context-Aware Auditor (DLP)**
    * Uses **RAG** to enforce company-specific policies.
---
🚀 Quick Start

Prerequisites

Python 3.10+
Groq API Key 

Installation
1. Clone the Repo 
 git clone [https://github.com/YOUR_USERNAME/AEGIS-AI-WAF.git](https://github.com/YOUR_USERNAME/AEGIS-AI-WAF.git)
cd AEGIS-AI-WAF

2. Install Dependencies
   pip install -r requirements.txt

3. Configure Environment
   export GROQ_API_KEY="gsk_your_key_here"

4. Run the Engine
  python app.py

Access the Dashboard at http://localhost:7860

🤝 Contributing

Fork the Project
Create your Feature Branch (git checkout -b feature/AmazingFeature)
Commit your Changes (git commit -m 'Add some AmazingFeature')
Push to the Branch (git push origin feature/AmazingFeature)
Open a Pull Request

📄 License

Distributed under the Apache 2.0 License. See LICENSE for more information.
Note for Enterprise Users: This repository contains the AEGIS Community Edition (Core Engine).
  
## 🏗️ Architecture

```mermaid
graph TD
    User[User Input] --> Layer1{Layer 1: Heuristics}
    Layer1 -- Match --> Block[⛔ Instant Block]
    Layer1 -- Clean --> Layer2{Layer 2: Vector DB}
    
    Layer2 -- High Similarity --> Block
    Layer2 -- Unique --> Layer3{Layer 3: Sentinel AI}
    
    Layer3 -- Malicious --> Immunize[🧬 Immunize System]
    Immunize --> Honeypot[🍯 Route to Honeypot]
    
    Layer3 -- Safe --> Agent[Core Agent Response]
    
    Agent --> Layer4{Layer 4: Policy Auditor}
    Layer4 -- Violation --> Redact[⚠️ Redact/Block]
    Layer4 -- Verified --> Final[Secure Output]


