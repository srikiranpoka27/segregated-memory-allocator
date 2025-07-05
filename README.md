# Segregated Memory Allocator in C

## Overview

This project implements a custom dynamic memory allocator for the x86-64 architecture written entirely in C. It includes its own versions of `malloc`, `free`, and `realloc`, as well as tools to measure heap utilization and fragmentation. The allocator is designed from scratch, without relying on system-provided memory allocation helpers or instructor-supplied functions.

## Features

- **Segregated Free Lists:** Memory blocks are categorized into multiple size classes, each managed using a circular, doubly linked list. This design allows for fast lookups and efficient memory reuse.
- **Quick Lists:** Recently freed small blocks are placed into size-specific quick lists for rapid reuse, improving performance on short-lived allocations.
- **First-Fit Placement Policy:** Allocation is satisfied by the first fitting block in the appropriate list, minimizing fragmentation.
- **Immediate and Deferred Coalescing:** Large blocks are coalesced immediately upon free, while small blocks use deferred coalescing via quick list flushing.
- **Block Splitting:** Blocks are split during allocation when necessary, avoiding the creation of unusable "splinters".
- **Alignment:** All allocations are 16-byte aligned to support natural alignment of all primitive types.
- **Prologue/Epilogue Headers:** Special padding blocks at the start and end of the heap eliminate edge case handling during allocation and coalescing.
- **Header/Footer Obfuscation:** To detect corruption and invalid frees, block metadata is obfuscated using a randomly generated key.

## Memory Statistics

The allocator includes support for tracking:
- **Internal Fragmentation**
- **Peak Heap Utilization**

These statistics help in evaluating the efficiency of memory usage over time.
