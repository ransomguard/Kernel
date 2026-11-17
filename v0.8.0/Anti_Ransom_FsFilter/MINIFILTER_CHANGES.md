# Minifilter integration changes

## Capability boundary

This reconstructed component is **observation only**. It emits bounded file-operation
telemetry into the existing main-driver queue. It does not deny or pend file I/O,
suspend or terminate a process, preserve pre-write bytes, or perform recovery.

The endpoint agent must keep automatic live enforcement disabled until file
containment and its Windows VM validation have been implemented. In particular,
host network isolation does not prevent local encryption while a JEV request is
pending. Do not describe this component as a completed Track B protection path.

The proposed first test folder is `C:\RansomGuardLab\Protected`; the current
minifilter observes qualifying operations on attached NTFS disk volumes, **not only
that folder**. A protected-directory enforcement policy is not implemented here.

## Implemented behavior

- Registers `IRP_MJ_WRITE` and `IRP_MJ_SET_INFORMATION` pre-operation callbacks.
- Emits `EVENT_TYPE_FILE_WRITE` for eligible nonpaging, normal-minor IRP writes.
  Small writes are observed too; entropy sampling requires at least 512 bytes.
- Emits `EVENT_TYPE_FILE_RENAME` for `FileRenameInformation` and
  `FileRenameInformationEx` requests.
- Creates or opens `\Callback\ArwFileEvent`. The main driver can load before or
  after this minifilter. `ExNotifyCallback` is synchronous; the 2232-byte nonpaged
  event remains valid through the call and is then freed. No pointer is retained
  by this sender. The existing receiver must continue copying before returning.
- Uses the existing `ARW_FILE_EVENT` / `ARW_EVENT_ANY` wire size and version. No
  struct layout changes were made by this component.
- Preserves the optional `EnableUnloadProtection` registry setting, default off.
  It is read at load time only. This work does not change host security settings.

### Event semantics

All emitted records carry `ARW_FILE_FLAG_PREOP_OBSERVATION`. They describe an
**attempt**, including an operation that may subsequently fail or be denied by
another component. There is no post-operation completion record in this ABI.

| Field | Meaning |
|---|---|
| `FilePath` | Source file path obtained with `FLT_FILE_NAME_OPENED` before the operation. It may use an opened/short-name spelling; it is not a canonical security identity. |
| `NewExtension` | For rename only: the parsed destination extension without a leading dot. No complete destination path is carried by this ABI. |
| `FilePathLength`, `NewExtensionLength` | UTF-16 byte counts excluding the trailing NUL. |
| `ARW_FILE_FLAG_PATH_UNAVAILABLE` | The source path was not obtained. An empty path must not be used as a recovery target. |
| `ARW_FILE_FLAG_EXT_UNAVAILABLE` | The rename destination extension could not be obtained. This differs from a successfully parsed extensionless destination. |
| `ARW_FILE_FLAG_PATH_TRUNCATED`, `ARW_FILE_FLAG_EXT_TRUNCATED` | The wire buffer could not hold the complete value. A truncated path must not authorize recovery or deletion. |
| `ARW_FILE_FLAG_HIGH_ENTROPY` | One copied sample met the threshold; this is a weak signal and never an automatic malicious verdict. Absence of the flag also includes a missing sample. |

The source name is copied before rename, and only the attempted destination's
extension is parsed. The code deliberately uses **opened**, not normalized-final,
names and does not claim post-rename identity or name-tunneling correction.
Consumers must not infer a completed rename or reconstruct the destination by
replacing the old extension. Moves, extensionless names, overwrite semantics,
alternate streams, and intervening renames require additional evidence.

The unchanged ABI contains PID but not process creation time in a file event.
The agent must correlate lifecycle events and reject ambiguous identities; a
partial/lost stream cannot authorize destructive recovery or termination.

## Bounded work and loss accounting

- No per-I/O worker queue, pended I/O, or remote request is introduced.
- Maximum concurrent sender events: **32** (2232 bytes each).
- Fixed one-second observation budgets: **512 write** and **256 rename** records.
  The budgets are separate to leave rename capacity during a write burst.
- Rename names are copied into immutable paged buffers before the destination
  query. Each copy is at most 65534 bytes and holds one of the same 32 event slots;
  allocation count and copied bytes are therefore bounded.
- There is no per-PID or per-file lifetime accumulator. Operations beyond a budget
  are intentionally omitted. This is sampling/rate limiting, not a complete
  change journal and not a lossless audit log.
- Rate, in-flight capacity, allocation, unsupported-path and metadata failures are
  counted. `KdPrint` logs diagnostic counters at powers of two and unload-time
  totals to avoid producing one debug line per drop. These counters are not yet
  exposed in the main driver's status ABI and are not durable across unload.
- The notification count means only that `ExNotifyCallback` was called. That API
  has no receiver acknowledgement: an absent sink receives nothing, and the main
  driver's own queue can independently drop a record. Its queue counters remain
  a separate observation source. No exactly-once delivery is claimed.

## Entropy change and PID-reuse fix

The former implementation accumulated high-entropy writes by PID and terminated
after the 51st qualifying write. Natural process exit did not clear this table;
the creation-time check at termination only covered the later worker race.

That accumulator and all minifilter termination code were removed. `EntropyDetect`
now contains only a pure, bounded Q8 entropy calculation. A sample is first copied
into a 512-byte local buffer; MDLs are decoded/mapped when present, raw user buffers
are probed and copied under SEH only in the requestor context, and unavailable
samples do not suppress the path observation. No process identity state survives
the callback, so PID reuse cannot inherit entropy counts or a termination verdict.

There is no broad `python.exe`, executable-name, or recovery-folder exemption.
Since this driver no longer terminates or blocks, restoration writes cannot
trigger its old entropy-based termination path. A future enforcing minifilter
still needs authenticated, narrowly scoped recovery authorization.

## Known limitations

- NTFS disk volumes only; no ReFS/FAT/SMB coverage claim.
- Fast I/O, paging/memory-mapped write paths and non-normal write minor functions
  are not covered by the write observer. They are counted as unsupported.
- Delete/disposition, truncate/end-of-file, create/overwrite and hard-link events
  are not implemented. Rename coverage is limited to the two stated classes.
- Name queries may fail or return noncanonical opened names. Paths cannot serve
  as stable identities or trusted restore instructions.
- These are pre-operation attempts with no success status or bytes-written field.
- Global budgets can drop observations from busy normal workloads. This telemetry
  alone is unsuitable for proving that no damage occurred or all files recovered.
- No pre-write snapshot, write denial, safe I/O pending/cancellation, process-tree
  containment, WFP control, or network-release decision is implemented here.
- Live collection can itself observe the endpoint agent's file writes. The agent
  must avoid recursively reacting to its own journal writes; no blanket trust
  exemption is established in this driver.

## Code inspection checklist

- [x] Every operation path returns `FLT_PREOP_SUCCESS_NO_CALLBACK` and writes a
  NULL completion context; no asynchronous buffer or work item survives.
- [x] No call to `ZwTerminateProcess`, old PID accumulation, or remote API remains.
- [x] All sender events use nonpaged storage and are freed after notification.
- [x] Name objects and bounded rename copies have cleanup paths on every failure.
- [x] Name queries and paged accesses run at IRQL no greater than APC_LEVEL; no
  spin lock is held while querying names, copying buffers, or notifying receivers.
- [x] Raw sample reads use requestor-context checks, probing and SEH. A private
  copied sample is used for the statistic.
- [x] Rename length, UTF-16 alignment, struct-prefix size and allocation maximum
  are checked before copying. Truncation reserves a NUL and does not split a
  surrogate pair.
- [x] `FltUnregisterFilter` precedes release of the sender's callback-object
  reference during unload; initialization failures release acquired resources.
- [ ] Compile Debug and Release x64 with the selected Windows WDK/SDK. The current
  environment has not executed a WDK driver build.
- [ ] Load both driver orders in a disposable Windows VM and verify file-event
  arrival, payload sizes, lengths, flags, sink unload/reload and loss counters.
- [ ] Exercise ordinary writes, denied writes and failed renames: events must be
  labeled attempts, and file contents must be unchanged by this driver itself.
- [ ] Check relative/root-directory rename, `FileRenameInformationEx`, extensionless
  targets, long UTF-16 names, low resources, busy workloads and unload activity.
- [ ] Driver Verifier/WinDbg validation of IRQL, pool lifetime and concurrent unload.
- [ ] Implement and validate actual file containment before enabling automatic
  JEV-driven termination/recovery or presenting this as complete protection.

## Primary API references

- [Pre-operation buffer access](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/accessing-user-buffers-in-a-preoperation-callback-routine)
- [FltDecodeParameters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltdecodeparameters)
- [FltGetFileNameInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation)
- [FltGetDestinationFileNameInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetdestinationfilenameinformation)
- [FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [FltParseFileNameInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltparsefilenameinformation)
- [ExNotifyCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exnotifycallback)
