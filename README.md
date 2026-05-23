## Overview

This research project is a low-level proof of concept (PoC) designed to study Windows operating system internals, custom memory mapping, and advanced execution flow control. Built using a **C++ controller** and a **C# Native AOT payload**, the framework demonstrates how to interact directly with the OS kernel, manipulate memory structures, and monitor system telemetry at the hardware level.

This repository serves as an educational resource for systems programmers, security engineering professionals, and reverse engineers interested in deep Windows architecture and native code optimization.

---

## Architecture

The framework consists of two core components engineered to minimize operational overhead and bypass standard high-level OS abstractions:

1. **The Loader (C++)**: Hand-crafted native executable that reads, parses, and manually prepares the binary module in memory without relying on standard, heavy OS loader APIs.
2. **The Core Module/Payload (C# Native AOT)**: A highly optimized, standalone binary compiled directly to native x64 assembly, bypassing the .NET runtime (CLR) dependency to achieve an incredibly small memory footprint and high execution speed.

---

## Technical Features & Concepts Demonstrated

* **InDirect System Calls (Dynamic Syscall Resolution)**
Bypasses standard user-mode API wrappers by dynamically reading system call numbers (SSNs) directly from the OS memory subsystem and executing native `syscall` instructions. This demonstrates a deep understanding of the transition between user mode and kernel mode.
* **Hardware-Assisted Instrumentation via VEH (Vectored Exception Handling)**
Implements non-invasive debugging and execution tracking using CPU Debug Registers (`DR0`-`DR7`). By capturing hardware exceptions globally via VEH, the framework can inspect and safely modify thread contexts (`RIP`, `RAX` registers) on the fly without patching executable memory bytes.
* **Process Environment Block (PEB) & Callback Manipulation**
Demonstrates advanced control flow redirection by interacting with internal Windows structures, such as the `KernelCallbackTable` within the PEB. This allows execution tracking within existing application routines without creating noisy or resource-heavy system threads.
* **Call Stack Telemetry Obfuscation (Indirect Execution Paths)**
Implements logic to mask the true origin of system calls. By routing execution through legitimate, pre-existing system modules, the project helps analyze how modern operating systems trace and validate call stack history.
* **Dynamic Header Management & Cloaking**
Demonstrates how to manually modify PE (Portable Executable) structures in memory after loading. Erasing signature markers (like `MZ` or `PE` magic bytes) shows how memory optimization and footprint reduction can affect automated system scanners.
* **Custom Linker Configurations & Binary Consolidation**
Utilizes aggressive compilation techniques to modify the executable's structural footprint. By merging standard binary sections (such as `.text`, `.rdata`, and `.pdata`) into a single custom section, the project explores how binary entropy and structure impact static analysis tools.

---

## Key Competencies Highlighted

* **Advanced C++ & C# Native AOT** cross-language integration.
* Deep knowledge of **x64 Processor Architecture** (Registers, Debug Registers, Calling Conventions).
* Mastery of **Windows Internals** (PE file format parsing, PEB structure, Native API).
* Experience with low-level **Memory Protection States** and instruction cache synchronization (`NtFlushInstructionCache`).

---

## Disclaimer

*This repository is intended solely for educational, academic, and defensive research purposes. *
