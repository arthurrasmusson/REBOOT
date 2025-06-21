# REBOOT  
**R**EBOOT **E**xtends **B**inary reverse‑engineering via **O**ver‑RDMA‑Paged‑Attention & **O**penAI‑API **T**ransforms  

> **One‑shot, whole‑codebase refactors for teams with serious hardware and an equally serious LLM context window.**

---

## AI Reverse Engineering & Codebase Refactoring

Modern codebases routinely exceed a million lines of source *plus* megabytes of proprietary binaries.  
Traditional refactor tools choke on that scale. **REBOOT** is a single shot Refactoring tool CLI that:

1. **Aggregates** every file (source *and* binary) from any number of project roots.  
2. **Annotates / omits / disassembles** binaries on demand so you can still ingest them as text.  
3. **Packages** the entire bundle—directory structure + file bodies—into a single UTF‑8 file suited
   for long‑context LLMs (10 M tokens and beyond).  
4. **Ships** the prompt (system + user) straight to an OpenAI‑compatible Chat Completions
   token as a service, on‑prem inference server, or the public cloud.  
5. **Streams** the model’s reply live to your terminal.  

With a multi‑GPU **DGX** appliance and a 10 M‑token transformer, you can **one‑shot reverse engineer
_&_ rewrite an entire monolithic repo**—source and binary alike.

---

## Key Features

| Capability | Details |
|------------|---------|
| **Multi‑root harvest** | `--root-source-path <path>` (repeatable) crawls N independent trees. |
| **Binary awareness** | <br>• Omit by default<br>• `--collect-binaries-full` – Base‑64 embed<br>• `--collect-binary-disassembly` – objdump/Ghidra summary |
| **Prompt injection** | `--path-to-refactor-prompt` supplies the **system** instructions; code dump becomes the **user** message. |
| **OpenAI plumbing** | Point to *any* Chat Completions endpoint with `--openai-base-url`, choose model with `--openai-model`, stream by default. |
| **Token‑friendly** | Streams files line‑by‑line; never blows RAM. Binary blobs stay ASCII via Base‑64 or are replaced by summary text. |
| **Cloud or air‑gapped** | Skip the upload (`--skip-upload`) to hand‑deliver the prompt to an offline LLM cluster. |

---

## Installation

```bash
git clone https://github.com/arthurrasmusson/REBOOT.git
cd reboot
python -m pip install -r requirements.txt  # only 'openai>=1.6'
chmod +x open-refactor.py                  # or install via setup.py
````

*Optional tools*

* `objdump` – included with GNU binutils for disassembly
* `Ghidra` – set `GHIDRA_INSTALL_DIR=/opt/ghidra` for richer binary analysis

---

## Quick‑start

### 1. Craft your refactor prompt

```text
(prompt/refactor_instructions.txt)

You are an expert systems programmer tasked with migrating the
entire codebase from CUDA 11.x to CUDA 12.5 while replacing
custom kernels with Triton, etc...
```

### 2. Generate & upload

```bash
export OPENAI_API_KEY="sk‑..."
./open-refactor.py \
     --root-source-path ~/proj/open-or-closed-component-0 \
     --root-source-path ~/proj/open-or-closed-component-1 \
     --collect-binary-disassembly \
     --path-to-refactor-prompt prompt/refactor_instructions.txt \
     --openai-model gpt-4o \
     --output /tmp/open‑tokens.txt
```

Streamed output appears in‐line; interrupt with **Ctrl‑C** to stop early.

### 3. Air‑gapped / offline use

```bash
./open-refactor.py \
     --root-source-path /mnt/bigrepo \
     --collect-binaries-full \
     --output /scratch/tokens.txt \
     --skip-upload
# Manually feed tokens.txt + prompt.txt to your internal 10 M‑token model
```

---

## Hardware & Model Recommendations

| Scale                                  | Suggested Hardware          | Suggested Model       | Context      |
| -------------------------------------- | --------------------------- | --------------------- | ------------ |
| Mid‑size repo (<1 M LOC)               | Single A100 80 GB           | Llama-3.1-70b         | 128 k tokens |
| Large monorepo (5 M LOC)               | 8× H100 80 GB               | Command-A             | 1 M tokens   |
| “Whole company” (>20 M LOC + binaries) | DGX H200, NVL72, 1½ TB VRAM | Llama-4-Scout-17B-16E | 10 M+ tokens |

---

## Security / Privacy

* REBOOT transmits **exact file content** unless you omit or scrub.
* Verify no secrets (keys, customer data) remain before uploading.
* Use `--skip-upload` for air‑gapped reverse engineering workflows.

---

## License

AGPLv3
