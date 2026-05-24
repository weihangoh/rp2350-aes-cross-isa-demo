# Randomized self-directed cross-ISA AES-CTR for RP2350 / Pico 2 W

This is an experimental research demo.

Core 0 runs an Arm host. Core 1 executes exactly one AES primitive per launch. Each primitive writes its output state to shared SRAM, decides the next AES state, randomly chooses the next ISA, writes that continuation to shared SRAM, and triggers a watchdog reboot. Core 0 only relaunches core 1 according to the continuation.

## Memory map

- Worker blob load: `0x20060000`
- Shared AES context: `0x20070000`

## Build order

From the project root:

```bat
cd arm_worker
rmdir /s /q build
cmake -G Ninja -S . -B build
cmake --build build

cd ..\riscv_worker
rmdir /s /q build
cmake -G Ninja -S . -B build
cmake --build build

cd ..\arm_host
rmdir /s /q build
cmake -G Ninja -S . -B build
cmake --build build
```

Flash:

```text
arm_host/build/arm_host.uf2
```

## Expected output

The board will repeatedly reset/re-enumerate USB while AES primitives execute. At completion, the host prints a summary and event log.

A successful run ends with:

```text
AES-CTR verification      = PASS
```

## Notes

This is not production crypto. Keys and round keys are intentionally stored in SRAM for experimental visibility. The PRNG is deterministic for reproducible routing decisions and is not used for cryptographic key material.

## License

Licensed under the Apache License, Version 2.0.

SPDX-License-Identifier: Apache-2.0

See `LICENSE` for the full license text.
