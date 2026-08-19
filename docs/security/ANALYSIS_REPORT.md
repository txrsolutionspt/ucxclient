# Security & Bug Analysis Report: ucxclient
## u-connectXpress AT Command Client Library

**Analysis Type:** Embedded Software Security Review
**Target:** u-connectXpress AT Command Client (ucxclient)
**Scope:** C codebase for NORA-W36, NORA-B26 wireless modules
**Platforms:** POSIX, Windows, STM32F4, Zephyr RTOS, Bare-metal

---

## Methodology

Every finding below was verified by manual trace-through of the actual code paths
(buffer indices, cursor arithmetic, mutex ownership, and call sites), not by pattern
matching alone. Only issues that hold up under this verification are included. Several
initially-suspected problems (an "off-by-one" in the RX character handler, an strcat
sequence in the WiFi scan example, the binary-transfer length handling, an in-place
integer-list parser, and the URC queue's dequeue locking) were traced in full and found
to be **correctly bounded / memory-safe** — they are intentionally omitted here.

---

## Findings

### 1. MEDIUM — XMODEM block send does not validate `dataLen <= blockSize`

**File:** `src/u_cx_xmodem.c`, function `xmodemSendBlock()` (lines ~137–162)

```c
uint8_t packet[U_CX_XMODEM_HEADER_SIZE + U_CX_XMODEM_BLOCK_SIZE_1K + U_CX_XMODEM_CRC_SIZE]; // 1029 bytes
...
memset(&packet[3], 0x1A, blockSize);
if (dataLen > 0) {
    memcpy(&packet[3], pData, dataLen);  // dataLen is not checked against blockSize
}
```

`dataLen` is the value returned by the caller-supplied `uCxXmodemDataCallback_t`
callback (a public API type — see `inc/u_cx_xmodem.h`), and `blockSize` is always 1024
or 128. Nothing in `uCxXmodemSend()` or `xmodemSendBlock()` verifies that the callback's
returned `bytesRead` does not exceed the `maxLen` (`requestLen`) it was given. If a
custom callback implementation returns a length greater than `blockSize`, `memcpy()`
writes past the end of the fixed-size local `packet` buffer — a stack buffer overflow —
and also reads past the end of the caller's source buffer.

**Impact:** Stack buffer overflow triggered by a misbehaving/buggy `uCxXmodemDataCallback_t`
implementation. Exploitability is limited to whoever supplies the data callback (i.e. the
integrating application), not an external UART attacker, since the UART side of this
path only exchanges single-byte XMODEM control characters (ACK/NAK/CAN/C).

**Recommendation:**
```c
if (dataLen > blockSize) {
    U_CX_LOG_LINE_I(U_CX_LOG_CH_ERROR, pConfig->instance,
                    "XMODEM: data callback returned more than blockSize");
    return -1;
}
```

---

### 2. LOW–MEDIUM — `strtol()` results used without checking for overflow (`ERANGE`)

**Files:**
- `src/u_cx_at_client.c` (extended AT error code parsing, ~line 131):
  ```c
  int code = (int)strtol(pCodeStr, &pEnd, 10);
  if (isdigit((int) * pCodeStr) && (*pEnd == 0)) {
      pClient->status = U_CX_EXTENDED_ERROR_OFFSET - code;
  }
  ```
- `src/u_cx_at_params.c` ('d' integer-parameter case in `uCxAtUtilParseParamsVaList()`, ~line 215):
  ```c
  *pI = (int32_t)strtol(pParam, &pEnd, 10);
  if (((*pParam != '-') && !isdigit((int)*pParam)) || (*pEnd != 0)) {
      return -ret;
  }
  ```

Neither call site checks `errno == ERANGE` or validates the parsed value against the
target type's range before narrowing (`long` → `int` / `int32_t`). A malformed or
out-of-range numeric field in an AT response (e.g. an extended error code or integer
parameter with an excessive number of digits) is silently accepted with an
implementation-defined truncated value instead of being rejected as a parse error.

**Impact:** Data-integrity issue, not memory-unsafe by itself — a bogus AT
status/parameter value could be accepted and acted on instead of triggering an error
path. Practical exploitability requires the ability to inject or corrupt UART traffic
between host and module (physical access, or a malfunctioning/compromised module).

**Recommendation:**
```c
errno = 0;
long value = strtol(pParam, &pEnd, 10);
if (errno == ERANGE || value < INT32_MIN || value > INT32_MAX) {
    return -ret; // reject out-of-range value
}
```

---

### 3. LOW — `uint16_t` truncation of available URC payload space

**File:** `src/u_cx_at_urc_queue.c`, function `uCxAtUrcQueueEnqueueGetPayloadPtr()` (~line 104-111)

```c
uint16_t uCxAtUrcQueueEnqueueGetPayloadPtr(uCxAtUrcQueue_t *pUrcQueue, uint8_t **ppPayload)
{
    ...
    return (uint16_t)getUnusedBuf(pUrcQueue);
}
```

`getUnusedBuf()` returns a `size_t`. If the URC queue buffer is configured with
`bufferLen >= 65536` bytes and enough of it is unused, the truncation to `uint16_t`
wraps (e.g. exactly 65536 unused bytes truncates to 0), causing the caller to believe no
space is available when in fact there is plenty.

**Impact:** Incorrect (overly conservative) space calculation — causes valid binary URC
payloads to be dropped instead of stored. Not an overflow (the truncation only ever
under-reports available space), and only reachable if a developer configures a URC
buffer of 64 KB or larger, which is unusual for the memory budgets typical of the
targeted embedded platforms.

**Recommendation:** Cap the reported value explicitly, or change the return type to
`size_t`/change the payload-size fields to accommodate larger buffers if that is a
supported configuration:
```c
size_t unused = getUnusedBuf(pUrcQueue);
return (uint16_t)(unused > UINT16_MAX ? UINT16_MAX : unused);
```

---

### 4. LOW — RX buffer silently discards data on overflow instead of surfacing an error

**File:** `src/u_cx_at_client.c`, function `parseIncomingChar()` (~lines 193-201)

```c
} else if (isprint(ch)) {
    pRxBuffer[pClient->rxBufferPos++] = ch;
    if (pClient->rxBufferPos == pClient->pConfig->rxBufferLen) {
        // Overflow - discard everything and start over
        U_CX_LOG_LINE_I(U_CX_LOG_CH_WARN, pClient->instance,
                        "RX buffer overflow (%lu bytes), discarding data",
                        (unsigned long)pClient->pConfig->rxBufferLen);
        pClient->rxBufferPos = 0;
    }
}
```

This is memory-safe (the write index is always within bounds, and the buffer position
is reset before any further byte can be written out of range), but a line longer than
`rxBufferLen` is silently dropped and parsing restarts mid-stream, with only a warning
log. The AT command waiting on that response has no direct signal that its response was
truncated/discarded — it will simply run until the command timeout.

**Impact:** Availability/robustness limitation rather than a security vulnerability: an
undersized `rxBufferLen` relative to expected AT responses (or a module sending an
unexpectedly long line) degrades to command timeouts rather than a clear, immediate
error.

**Recommendation:** Consider surfacing a distinct error/status (not just a log line) when
this discard path triggers, so callers can distinguish "overflow discard" from a normal
timeout.

---

### 5. LOW / Informational — Assertion-based checks compile out under `NDEBUG`

**Files:** throughout `src/`, via `U_CX_AT_PORT_ASSERT`, defined in `ports/u_port.h`:
```c
# define U_CX_AT_PORT_ASSERT(COND) assert(COND)
```

Standard `assert()` is compiled to a no-op when `NDEBUG` is defined, which is common in
release firmware builds. The checks guarded by `U_CX_AT_PORT_ASSERT` throughout the
codebase (e.g. `uCxStringToIpAddress`, URC queue invariants) are consistently
programmer-contract checks (non-NULL arguments, internal invariants) rather than
validation of untrusted AT-response content — actual response/parameter content
validation uses explicit `if`/`return -1` paths, not assertions. This is the
conventional and appropriate use of `assert()` in C, but it is worth documenting
explicitly: if a port's `U_CX_AT_PORT_ASSERT` is mapped to plain `assert()` and built
with `NDEBUG`, those programmer-error guards disappear silently rather than failing
loudly in the field.

**Recommendation:** No code change required; document that release builds should either
avoid `NDEBUG` for this library or supply a custom `U_CX_AT_PORT_ASSERT` (as the porting
layer already allows) that remains active in production.

---

### 6. LOW — Linear O(n) URC dequeue (already flagged as TODO in source)

**File:** `src/u_cx_at_urc_queue.c`, `uCxAtUrcQueueDequeueEnd()` (~line 169)

```c
// TODO: Replace with ring buffer to improve performance
memmove(pUrcQueue->pBuffer, &pUrcQueue->pBuffer[totEntrySize], (size_t)remainingData);
```

Each dequeue compacts the remaining queue contents with `memmove()`, which is O(n) in
the amount of buffered URC data. Under high URC throughput with many entries queued,
this could become a measurable CPU cost. This is not a correctness or security issue —
it is a known, self-documented performance limitation.

---

## Summary

| # | Severity | Finding | File |
|---|----------|---------|------|
| 1 | MEDIUM | XMODEM `xmodemSendBlock()` missing `dataLen <= blockSize` check | src/u_cx_xmodem.c |
| 2 | LOW-MEDIUM | `strtol()` used without `ERANGE`/range validation | src/u_cx_at_client.c, src/u_cx_at_params.c |
| 3 | LOW | `uint16_t` truncation of URC payload space for buffers ≥64KB | src/u_cx_at_urc_queue.c |
| 4 | LOW | RX overflow silently discards data instead of signaling an error | src/u_cx_at_client.c |
| 5 | LOW/Info | Assertion-based checks compile out under `NDEBUG` | ports/u_port.h + call sites |
| 6 | LOW | Linear O(n) URC dequeue (self-flagged TODO) | src/u_cx_at_urc_queue.c |

No critical or high-severity memory-safety vulnerabilities were confirmed. The AT
client's RX handling, binary-transfer length negotiation, and URC queue locking were
each traced in detail and found to be correctly bounded.
