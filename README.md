# REBOOT  
**R**Eboot **E**xtends **B**inary reverse-engineering via **O**ver-RDMA-Paged-Attention & **O**penAI-API **T**ransforms  

---

## 0 . AI for Reverse Engineering

* **What?** &nbsp;`open-refactor.py` crawls one or more source trees, flattens every
  file (including binaries) into a single UTF-8 bundle and, if you choose,
  fires that bundle—plus your **system prompt**—at any OpenAI-compatible Chat
  Completions endpoint.

* **New in v0.3**  
  Full **Ghidra headless** integration.  Supply an optional *GhidraScript* and
  REBOOT will run a custom post-script for each binary, inserting the output
  straight into the LLM prompt.

* **Who?** &nbsp;Reverse-engineers, platform migration teams, or anyone with a
  long-context model (GPT-4o-long, Claude 200 k, bespoke 10 M-token model on a
  DGX H200) who wants to do **one-shot refactors or audits**.

---

## 1 . Feature Matrix

| Category | Highlights |
|----------|------------|
| **Harvest** | Multi-root crawl, per-file headers, VCS-dirs ignored, streaming I/O, <br>binary choices: omit / Base-64 embed / objdump / **Ghidra headless**. |
| **Ghidra Support** | Detects `GHIDRA_INSTALL_DIR`.  Executes `support/analyzeHeadless` with:<br>• `-analysisTimeoutPerFile 30` s<br>• Temporary project auto-deleted.<br>Optional environment hooks:<br>`GHIDRA_SCRIPT=/path/MyScript.py` & `GHIDRA_SCRIPT_ARGS="--foo 1"` |
| **Token Budget** | Exact counts with `tiktoken` (< 10 MB files), heuristic fallback. Aborts if (input + output) > context (unless `--allow-overflow`). |
| **Upload** | Any OpenAI-compatible base URL, streaming on by default. |
| **Security** | No network unless you call the API.  Air-gapped mode with `--skip-upload`. |

---

## 2 . Prerequisites

| Purpose | Package / Tool | Install |
|---------|----------------|---------|
| Chat API | `openai>=1.6` | `pip install --upgrade openai` |
| Accurate token counting | `tiktoken>=0.5` *(recommended)* | `pip install tiktoken` |
| **Disassembly (basic)** | `objdump` (GNU binutils) | apt/yum/brew/pkg-manager |
| **Disassembly (deep)** | **Ghidra 10.3+** | Download zip → `export GHIDRA_INSTALL_DIR=/opt/ghidra` |
| (Optional) Custom analysis | Write a [GhidraScript](https://ghidra-sre.org/ClassDocumentation/) and set `GHIDRA_SCRIPT`, `GHIDRA_SCRIPT_ARGS`. |

Python ≥ 3.8 required.

---

## 3 . Installation

```bash
git clone https://github.com/arthurrasmusson/REBOOT.git
cd reboot
python -m pip install -r requirements.txt          # pulls openai + tiktoken
````

---

## 4 . Using Ghidra Integration

### 4.1 Environment Variables

| Var                  | Required | Description                                                                             |
| -------------------- | -------- | --------------------------------------------------------------------------------------- |
| `GHIDRA_INSTALL_DIR` | **Yes**  | Path containing `support/analyzeHeadless`                                               |
| `GHIDRA_SCRIPT`      | No       | Path to your custom `.py`/`.java` script (must be inside a dir added to `-scriptPath`). |
| `GHIDRA_SCRIPT_ARGS` | No       | Extra CLI args for your script.  Split with shell quoting (`shlex`).                    |

### 4.2 Example: include function list only

```python
# scripts/function_list.py
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SymbolType

class FunctionList(GhidraScript):
    def run(self):
        for sym in self.currentProgram.symbolTable.getSymbolIterator(True):
            if sym.getSymbolType() == SymbolType.FUNCTION:
                print(sym.getName())
```

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra
export GHIDRA_SCRIPT=~/scripts/function_list.py
open-refactor.py \
    --root-source-path ~/fw/blobs \
    --collect-binary-disassembly \
    --output /tmp/fw_tokens.txt
```

The output block for every binary now begins with:

```
[Ghidra analyzeHeadless]
func_init
func_main
...
```

If Ghidra is missing or fails, REBOOT **automatically falls back** to `objdump -d`.

---

## 5 . Binary Handling Strategy

| Flag                           | Ghidra present? | Result in bundle                         | Token cost control |
| ------------------------------ | --------------- | ---------------------------------------- | ------------------ |
| *(default)*                    | N/A             | `[note that this file was omitted]`      | Minimal            |
| `--collect-binary-disassembly` | **yes**         | Ghidra headless output (capped at 20 kB) | Moderate           |
| `--collect-binary-disassembly` | **no**          | `objdump -d` output (20 kB cap)          | Moderate           |
| `--collect-binaries-full`      | Irrelevant      | Base-64 blob of entire binary            | High               |

*Cap size with `max_bytes` parameter inside the script if you customise.*

---

## 6 . Typical Workflows

### 6.1 Full-fat refactor with Ghidra, push to OpenAI

```bash
export OPENAI_API_KEY=sk-...
export GHIDRA_INSTALL_DIR=/opt/ghidra
open-refactor.py \
  --root-source-path ~/projects/legacy-fw \
  --collect-binary-disassembly \
  --path-to-refactor-prompt prompts/port_to_rust.txt \
  --openai-model gpt-4o-long \
  --max-output-tokens 8192
```

### 6.2 Air-gapped analysis for internal 10 M-token model

```bash
open-refactor.py \
  --root-source-path /mnt/monorepo \
  --collect-binary-disassembly \
  --output /scratch/monorepo_tokens.txt \
  --skip-upload
# --------------------------------------------
# Copy tokens + prompt into your on-prem model
```

---

## 7 . Token Budget Example

```
[Token budget]  System:  312   +  User: 5,912,088  +  Overhead: 8
  =  INPUT 5,912,408  |  Planned output 8,192  =>  TOTAL 5,920,600 tokens
[*] Unknown context window for model 'my-10m-token-model'; proceed with caution.
```

Add `--allow-overflow` if your model truly supports 10 M tokens.

---

## 8 . Roadmap

* `.rebootignore` file pattern support.
* Automatic chunking / retrieval-augmented generation.
* Parallel disassembly for large firmware sets.

---

## 9 . License

AGPLv3

---

## 10 . Reverse Acronym

> **R**Eboot **E**xtends **B**inary reverse-engineering via **O**ver-RDMA-Paged-Attention & **O**penAI-API **T**ransforms

