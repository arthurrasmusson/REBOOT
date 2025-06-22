#!/usr/bin/env python3
"""
open-refactor.py
================

REBOOT – Reverse‑engineering tool that **R**EBOOT **E**xtends **B**inary
reverse‑engineering via **O**ver‑RDMA‑Paged‑Attention & **O**penAI‑API **T**ransforms.

This CLI performs three major tasks:

1. **Harvest** – Crawl one or more source‑tree roots, emitting a single
   UTF‑8 file that contains:
      • A directory‑tree listing for each root.  
      • The full text of every “text” file.  
      • Optional binary inclusions (base‑64) or disassemblies.  

2. **Analyse** – Estimate the token cost (system + user + overhead +
   anticipated completion) for the chosen LLM, compare with known context
   windows, and warn/abort if overflow is detected.

3. **Transform** – Optionally upload the prompt (system prompt read from a
   text file + harvested code as the user message) to any OpenAI‑compatible
   Chat Completions endpoint, streaming the reply to stdout.

---------------------------------------------------------------------------
* The script is **self‑contained** (std‑lib only) except for the following
  _optional_ extras:
    • `openai>=1.6`   – for API calls.
    • `tiktoken>=0.5` – for accurate token counting; falls back to heuristic.
    • `objdump` / `Ghidra` – to create binary disassembly summaries.

* Designed to run on Linux/macOS/Windows with Python ≥ 3.8.

* Memory‑safe: streams files line‑by‑line; never loads huge blobs unless
  needed for token precision and they are <10 MB.
"""

# --------------------------------------------------------------------------- #
#                               Import section                                #
# --------------------------------------------------------------------------- #
from __future__ import annotations

import argparse          # Command‑line argument parsing.
import base64            # Base‑64 encoding for binary blobs.
import math              # Heuristic token estimation fallback.
import os                # Filesystem & environment access.
import pathlib           # Path manipulations with pathlib.Path.
import subprocess        # Invoking objdump / Ghidra headless.
import sys               # Stdout/stderr, exit().
import textwrap          # Help text formatting.
import time              # Simple timing for API calls.
from typing import Iterable, List, Optional

# Optional third‑party libraries ------------------------------------------------
try:
    import tiktoken      # Precise token counts for many OpenAI/Anthropic models.
except ImportError:
    tiktoken = None      # Fallback: heuristic.

# openai import is deferred until first API use (keeps offline workflows clean).


# --------------------------------------------------------------------------- #
#                         Configuration / Constant tables                     #
# --------------------------------------------------------------------------- #
# File extensions that should be treated as binary by default.  Modify as
# required for your environment.
BINARY_EXTS = {
    ".so", ".a", ".o", ".exe", ".dll", ".dylib", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".class", ".jar", ".war",
    ".pb", ".pt", ".onnx", ".npz",
}

# Encodings to attempt (in order) when reading text files.  A final fallback
# with UTF‑8+replacement happens automatically.
ENCODINGS_TO_TRY = ("utf-8", "latin-1", "utf-16")

# Approximate context‑window sizes (tokens) for common OpenAI models.
# Extend this dict with your own model IDs as needed.
MODEL_CONTEXT: dict[str, int] = {
    "gpt-4":           8_192,
    "gpt-4o-mini":    32_000,
    "gpt-4o":        128_000,
    "gpt-4o-long": 1_000_000,
    # "my‑custom‑10m": 10_240_000,
}

# Per‑message formatting overhead in the Chat Completions protocol.
# With 2 messages (system + user) about 4 tokens each = 8 total.
CHAT_FORMAT_OVERHEAD = 8


# --------------------------------------------------------------------------- #
#                           Token‑count helper functions                      #
# --------------------------------------------------------------------------- #
def _rough_tokens_from_chars(n_chars: int) -> int:
    """
    Very cheap heuristic: For English source code + comments, 1 token ≈ 4 chars.
    Good enough when tiktoken isn't installed or the file is huge.
    """
    return math.ceil(n_chars / 4)


def tokens_in_text(text: str, model: str) -> int:
    """
    Return token count for *text* given a *model* name.

    • If `tiktoken` is available, we use the model‑specific encoding if known,
      else fall back to the `cl100k_base` encoding.
    • Otherwise we estimate via `_rough_tokens_from_chars`.
    """
    if tiktoken:
        try:
            enc = tiktoken.encoding_for_model(model)
        except KeyError:
            enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    return _rough_tokens_from_chars(len(text))


def estimate_file_tokens(path: pathlib.Path, model: str) -> int:
    """
    Estimate tokens contributed by the file at *path* for the specified *model*.
    We attempt precise counting only if:
        • `tiktoken` is present, AND
        • file size < 10 MB  (so we don't blow RAM for multi‑GB binaries)
    Otherwise we rely on the heuristic.
    """
    size = path.stat().st_size
    if size < 10_000_000 and tiktoken:
        try:
            txt = path.read_text(encoding="utf-8", errors="ignore")
            return tokens_in_text(txt, model)
        except Exception:
            # Non‑UTF‑8 or binary – fall through to heuristic
            pass
    return _rough_tokens_from_chars(size)


# --------------------------------------------------------------------------- #
#                       Filesystem / binary handling helpers                  #
# --------------------------------------------------------------------------- #
def is_binary_path(path: pathlib.Path) -> bool:
    """
    Identify if *path* should be treated as binary.

    Heuristics:
      1. Extension is in `BINARY_EXTS`.
      2. First 8 KiB contains a NUL byte (common in binaries).
      3. Any IOError while reading -> treat as binary for safety.
    """
    if path.suffix.lower() in BINARY_EXTS:
        return True
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(8192)
    except Exception:
        return True


def yield_directory_listing(root: pathlib.Path) -> Iterable[str]:
    """
    Generator yielding **relative** paths of every directory and file inside
    *root*, excluding version‑control metadata directories.

    Each dir is yielded once ('.' for root), followed by its files.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        # Exclude VCS directories _in‑place_ so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in {".git", ".svn", ".hg"}]

        rel_dir = pathlib.Path(dirpath).relative_to(root)
        yield str(rel_dir) if rel_dir != pathlib.Path(".") else "."
        for fn in filenames:
            rel_file = pathlib.Path(dirpath, fn).relative_to(root)
            yield str(rel_file)


def stream_text_file(src: pathlib.Path, dst) -> None:
    """
    Copy *src* to output file‑handle *dst* line‑by‑line, trying multiple text
    encodings first, then falling back to UTF‑8 with replacement characters.

    This approach avoids loading entire large files into RAM and works for
    diverse encodings.
    """
    for enc in ENCODINGS_TO_TRY:
        try:
            with open(src, "r", encoding=enc, errors="strict") as f:
                for line in f:
                    dst.write(line)
            return
        except UnicodeDecodeError:
            continue  # try next encoding

    # Final fallback: decode with replacement chars so nothing crashes
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            dst.write(line)


def collect_binary_full(src: pathlib.Path, dst) -> None:
    """
    Embed the entire *src* binary into *dst* as **Base‑64**.

    This keeps the master file UTF‑8‑friendly while preserving raw bytes.
    """
    with open(src, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("ascii")
    dst.write(encoded + "\n")


def collect_binary_disassembly(
    src: pathlib.Path,
    dst,
    *,
    max_bytes: int = 20_000,
) -> None:
    """
    Dump a **succinct disassembly summary** of *src* into the already-opened
    text stream *dst*.

    Priority order
    --------------
    1. **Ghidra headless (analyzeHeadless)** – richest analysis.
       * Enabled automatically when:
         • The environment variable **`GHIDRA_INSTALL_DIR`** points to a
           valid Ghidra installation **and**
         • `support/analyzeHeadless` is executable.
       * Optional power-user controls via environment:
         • **`GHIDRA_SCRIPT`** – path to a *GhidraScript* (.py or .java).
           The script is invoked with `-scriptPath` / `-postScript`.
         • **`GHIDRA_SCRIPT_ARGS`** – additional arguments passed to the
           post-script (space-separated, will be *shlex* split).
       * The function creates a _temporary_ project in `/tmp` (or OS temp dir)
         and deletes it afterwards via `-deleteProject`.

    2. **objdump –d** – portable, fast.  Used when Ghidra is unavailable or
       fails for any reason.

    3. Failure placeholder – writes a diagnostic so the caller still gets a
       syntactically valid output file.

    Parameters
    ----------
    src : pathlib.Path
        Path to the binary file being summarised.
    dst : IO[str]
        Destination text stream (UTF-8) – e.g. the master output file.
    max_bytes : int, optional
        Hard cap on bytes written to *dst* for the disassembly.  Prevents
        exploding token counts.  Default is 20 000.

    Environment Variables Summary
    -----------------------------
    GHIDRA_INSTALL_DIR   – **required** for Ghidra mode  
    GHIDRA_SCRIPT        – optional user GhidraScript (file path)  
    GHIDRA_SCRIPT_ARGS   – optional extra args for the post-script  
    """
    import tempfile
    import shlex

    ghidra_home = os.getenv("GHIDRA_INSTALL_DIR")

    # ------------------------------------------------------------------ #
    # Attempt Ghidra headless analysis first.
    # ------------------------------------------------------------------ #
    if ghidra_home:
        headless = pathlib.Path(ghidra_home, "support", "analyzeHeadless")
        if headless.exists() and os.access(headless, os.X_OK):
            with tempfile.TemporaryDirectory(prefix="reboot_ghidra_") as tmpdir:
                project_dir = pathlib.Path(tmpdir)
                project_name = "tmp"
                cmd: list[str] = [
                    str(headless),
                    str(project_dir),
                    project_name,
                    "-import", str(src),
                    "-analysisTimeoutPerFile", "30",
                    "-deleteProject",
                ]

                # --------- Optional user GhidraScript support ---------- #
                user_script = os.getenv("GHIDRA_SCRIPT")
                if user_script:
                    script_path = pathlib.Path(user_script).expanduser().resolve()
                    cmd += ["-scriptPath", str(script_path.parent)]
                    # Split script args respecting quotes
                    post_args = shlex.split(os.getenv("GHIDRA_SCRIPT_ARGS", ""))
                    cmd += ["-postScript", script_path.name, *post_args]
                # ------------------------------------------------------- #

                try:
                    proc = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        check=False,
                        timeout=120,             # generous but bounded
                    )
                    ghidra_out = proc.stdout[:max_bytes]
                    dst.write("[Ghidra analyzeHeadless]\n")
                    dst.write(ghidra_out)
                    if len(proc.stdout) > max_bytes:
                        dst.write("\n[truncated …]\n")
                    return
                except subprocess.TimeoutExpired:
                    dst.write("(Ghidra timed out – falling back to objdump)\n")
                except Exception as exc:
                    dst.write(f"(Ghidra failed: {exc!r} – falling back to objdump)\n")
        else:
            dst.write("(Ghidra headless helper not executable – falling back to objdump)\n")

    # ------------------------------------------------------------------ #
    # Fallback: objdump disassembly.
    # ------------------------------------------------------------------ #
    try:
        proc = subprocess.run(
            ["objdump", "-d", str(src)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=30,
        )
        snippet = proc.stdout[:max_bytes] or "(objdump produced no output)\n"
        dst.write("[objdump -d]\n")
        dst.write(snippet)
        if len(proc.stdout) > max_bytes:
            dst.write("\n[truncated …]\n")
    except FileNotFoundError:
        dst.write("(objdump not found; no disassembly produced)\n")
    except subprocess.TimeoutExpired:
        dst.write("(objdump timed out; no disassembly produced)\n")
    except Exception as exc:
        dst.write(f"(objdump failed: {exc!r})\n")


# --------------------------------------------------------------------------- #
#                      Core routine to process a single root                  #
# --------------------------------------------------------------------------- #
def process_root(
    root: str,
    out_fp,
    *,
    collect_bin_full: bool,
    collect_bin_dis: bool,
) -> None:
    """
    Walk an individual *root* directory and append formatted output to *out_fp*.

    Parameters
    ----------
    root : str
        Filesystem path to the root directory (user‑supplied).
    out_fp : IO[str]
        Already‑opened file object (text mode, UTF‑8) for writing.
    collect_bin_full : bool
        If True, embed base‑64 of every binary file.
    collect_bin_dis : bool
        If True, include objdump summary instead of omitting binaries.

    Notes
    -----
    • `collect_bin_full` and `collect_bin_dis` are mutually exclusive – the CLI
      enforces that beforehand.
    • Version‑control directories (.git, .svn, .hg) are skipped entirely.
    """
    root_path = pathlib.Path(root).expanduser().resolve()
    print(f"[*] Walking {root_path}", file=sys.stderr)

    # ------------------------------------------------------------------ #
    # Write section header with directory listing.
    # ------------------------------------------------------------------ #
    out_fp.write(f"[{root_path}] - root source path\n\n")
    out_fp.write("*Directory structure for this root source path*\n")
    for line in yield_directory_listing(root_path):
        out_fp.write(line + "\n")
    out_fp.write("\n")  # blank line separating listing from file blocks

    # ------------------------------------------------------------------ #
    # Walk tree again to dump each file's content or placeholder.
    # ------------------------------------------------------------------ #
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in {".git", ".svn", ".hg"}]
        for fn in filenames:
            fpath = pathlib.Path(dirpath, fn)
            rel = fpath.relative_to(root_path)
            out_fp.write(f"{rel}\n")  # file header

            if is_binary_path(fpath):
                # ------------------- Binary file handling ------------------ #
                if collect_bin_full:
                    collect_binary_full(fpath, out_fp)
                elif collect_bin_dis:
                    collect_binary_disassembly(fpath, out_fp)
                else:
                    out_fp.write("[note that this file was omitted]\n")
            else:
                # ------------------- Text file handling -------------------- #
                try:
                    stream_text_file(fpath, out_fp)
                except Exception as e:
                    out_fp.write(f"[could not read file: {e}]\n")
            out_fp.write("\n")  # blank line between files


# --------------------------------------------------------------------------- #
#                     OpenAI Chat Completions integration                      #
# --------------------------------------------------------------------------- #
def send_to_openai(
    tokens_file: pathlib.Path,
    prompt_file: pathlib.Path,
    *,
    base_url: str,
    model: str,
    api_key: Optional[str],
    timeout: int,
    stream: bool,
    max_output_tokens: int,
) -> None:
    """
    Submit `tokens_file` as **user** message and `prompt_file` as **system**
    message to an OpenAI‑compatible endpoint.  Stream reply to stdout.

    Parameters
    ----------
    tokens_file : pathlib.Path
        Path to the aggregated code dump (user message).
    prompt_file : pathlib.Path
        Path to the refactor instructions (system message).
    base_url : str
        Base REST URL for the Chat Completions endpoint.
    model : str
        Model identifier.
    api_key : str | None
        API key.  If None, the `OPENAI_API_KEY` env var must exist.
    timeout : int
        Total seconds before the request is aborted.
    stream : bool
        If True, print tokens as they stream; else wait for full response.
    max_output_tokens : int
        Desired maximum tokens in the model's completion.
    """
    # Lazy import keeps offline usage clean.
    try:
        import openai
    except ImportError:
        sys.exit(
            "openai‑python is not installed.  "
            "Install with `pip install --upgrade openai>=1.6`."
        )

    # Configure client ------------------------------------------------------- #
    openai.base_url = base_url
    if api_key:
        openai.api_key = api_key
    elif not os.getenv("OPENAI_API_KEY"):
        sys.exit("API key missing.  Set OPENAI_API_KEY or pass --openai-api-key.")

    # Prepare messages ------------------------------------------------------- #
    system_prompt = prompt_file.read_text(encoding="utf-8")
    user_payload = tokens_file.read_text(encoding="utf-8")

    print("\n[+] Submitting prompt & code to OpenAI …", file=sys.stderr)
    start = time.time()

    # Chat Completions call --------------------------------------------------- #
    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload},
            ],
            stream=stream,
            timeout=timeout,
            max_tokens=max_output_tokens,
        )
    except Exception as exc:
        sys.exit(f"[!] OpenAI request failed: {exc}")

    # Stream or print full result ------------------------------------------- #
    if stream:
        for chunk in response:
            delta = chunk.choices[0].delta.content or ""
            print(delta, end="", flush=True)
        print("\n[+] Completed in %.1f s" % (time.time() - start), file=sys.stderr)
    else:
        # Non‑stream response – present the single message content
        print(response.choices[0].message.content)
        print("\n[+] Completed in %.1f s" % (time.time() - start), file=sys.stderr)


# --------------------------------------------------------------------------- #
#                           Command‑line interface                            #
# --------------------------------------------------------------------------- #
def parse_args(argv: List[str]) -> argparse.Namespace:
    """
    Build an argument parser and return the populated Namespace.
    Grouped into original harvest options & new OpenAI/token options.
    """
    epilog = textwrap.dedent(
        """
        Examples
        --------
        1) Harvest only (no upload):
           ./open-refactor.py --root-source-path ~/proj1 --root-source-path ~/proj2

        2) Harvest + upload with streaming:
           export OPENAI_API_KEY=sk-...
           ./open-refactor.py \\
               --root-source-path ~/proj1 --root-source-path ~/proj2 \\
               --collect-binary-disassembly \\
               --path-to-refactor-prompt prompt.txt \\
               --openai-model gpt-4o

        3) Prepare file for an offline model (no upload):
           ./open-refactor.py --root-source-path /mnt/monorepo --skip-upload
        """
    )

    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Aggregate multiple source trees and optionally push to an "
        "OpenAI-compatible LLM for one-shot refactoring.",
        epilog=epilog,
    )

    # ---------------- Harvest options ---------------- #
    p.add_argument(
        "--root-source-path",
        dest="roots",
        action="append",
        required=True,
        metavar="PATH",
        help="Add a source‑tree root (repeat this flag multiple times).",
    )
    p.add_argument(
        "--collect-binaries-full",
        action="store_true",
        help="Embed binary files as base‑64 instead of omitting them.",
    )
    p.add_argument(
        "--collect-binary-disassembly",
        action="store_true",
        help="Include objdump/Ghidra disassembly summary of binaries.",
    )
    p.add_argument(
        "--output",
        default="open-refactor-input-tokens.txt",
        help="Output filename for the aggregated text "
        "[default: %(default)s]",
    )

    # ---------------- OpenAI options ----------------- #
    p.add_argument(
        "--path-to-refactor-prompt",
        metavar="PROMPT.txt",
        help="Path to the system prompt containing refactor instructions. "
        "If omitted, no upload is attempted.",
    )
    p.add_argument(
        "--openai-base-url",
        default="https://api.openai.com/v1",
        help="Base URL for the Chat Completions API.",
    )
    p.add_argument(
        "--openai-model",
        default="gpt-4o",
        help="Model name at the endpoint [default: %(default)s]",
    )
    p.add_argument(
        "--openai-api-key",
        help="API key (overrides OPENAI_API_KEY env var).",
    )
    p.add_argument(
        "--openai-timeout",
        type=int,
        default=600,
        metavar="SEC",
        help="Timeout for the HTTP request [default: %(default)s]",
    )
    p.add_argument(
        "--openai-no-stream",
        action="store_true",
        help="Disable server‑side streaming; wait for full response.",
    )
    p.add_argument(
        "--skip-upload",
        action="store_true",
        help="Perform harvest but do NOT send to OpenAI (dry run).",
    )

    # ---------------- Token control ------------------ #
    p.add_argument(
        "--max-output-tokens",
        type=int,
        default=4096,
        metavar="TOK",
        help="Expected maximum tokens the model will generate "
        "[default: %(default)s]",
    )
    p.add_argument(
        "--allow-overflow",
        action="store_true",
        help="Proceed even if (input + output) exceeds the model's "
        "known context window.",
    )

    return p.parse_args(argv)


# --------------------------------------------------------------------------- #
#                                    main                                     #
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> None:
    """
    Entry point:

    1. Parse CLI.
    2. Harvest source trees into a single output file.
    3. Compute token budget and warn/abort if overflow.
    4. Optionally send prompt to OpenAI.
    """
    args = parse_args(argv or sys.argv[1:])

    # CLI sanity checks ------------------------------------------------------ #
    if args.collect_binaries_full and args.collect_binary_disassembly:
        sys.exit(
            "--collect-binaries-full and --collect-binary-disassembly "
            "are mutually exclusive."
        )

    # Stage 1 – Harvest ------------------------------------------------------ #
    out_path = pathlib.Path(args.output).expanduser().resolve()
    with open(out_path, "w", encoding="utf-8") as out_fp:
        for root in args.roots:
            process_root(
                root,
                out_fp,
                collect_bin_full=args.collect_binaries_full,
                collect_bin_dis=args.collect_binary_disassembly,
            )

    print(f"[*] Aggregation completed → {out_path}", file=sys.stderr)

    # Stage 2 – Token estimation -------------------------------------------- #
    sys_prompt_tokens = 0
    if args.path_to_refactor_prompt:
        prompt_path = pathlib.Path(args.path_to_refactor_prompt).expanduser()
        if not prompt_path.is_file():
            sys.exit(f"[!] Prompt file not found: {prompt_path}")
        sys_prompt_tokens = estimate_file_tokens(prompt_path, args.openai_model)

    user_tokens = estimate_file_tokens(out_path, args.openai_model)
    total_input = sys_prompt_tokens + user_tokens + CHAT_FORMAT_OVERHEAD
    total_needed = total_input + args.max_output_tokens

    # Report to the user
    print(
        (
            "\n[Token budget]  System: {:,}  +  User: {:,}  +  Overhead: {}"
            "  =  INPUT {:,}  |  Planned output {:,}  =>  TOTAL {:,} tokens"
        ).format(
            sys_prompt_tokens,
            user_tokens,
            CHAT_FORMAT_OVERHEAD,
            total_input,
            args.max_output_tokens,
            total_needed,
        ),
        file=sys.stderr,
    )

    ctx_window = MODEL_CONTEXT.get(args.openai_model)
    if ctx_window:
        if total_needed > ctx_window:
            msg = (
                f"[!] WARNING: total tokens ({total_needed:,}) exceed the "
                f"context window of {args.openai_model} ({ctx_window:,})."
            )
            if args.allow_overflow:
                print(msg + "  --allow-overflow specified; continuing.",
                      file=sys.stderr)
            else:
                sys.exit(msg + "  Choose a longer‑context model or "
                               "use --allow-overflow.")
    else:
        print(
            "[*] Unknown context window for this model; proceed with caution.",
            file=sys.stderr,
        )

    # Stage 3 – Optional upload --------------------------------------------- #
    if args.path_to_refactor_prompt and not args.skip_upload:
        send_to_openai(
            tokens_file=out_path,
            prompt_file=pathlib.Path(args.path_to_refactor_prompt).expanduser(),
            base_url=args.openai_base_url,
            model=args.openai_model,
            api_key=args.openai_api_key,
            timeout=args.openai_timeout,
            stream=not args.openai_no_stream,
            max_output_tokens=args.max_output_tokens,
        )
    elif args.path_to_refactor_prompt and args.skip_upload:
        print("[*] --skip-upload specified; not calling OpenAI.", file=sys.stderr)
    else:
        print("[*] No prompt file supplied; upload phase skipped.",
              file=sys.stderr)


# Standard boilerplate ------------------------------------------------------- #
if __name__ == "__main__":
    main()

