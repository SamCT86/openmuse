# Native Windows backend

Experimental backend under validation. No independent security review is claimed.

## Scope

Windows 11 x64 (or equivalent newer Server builds), Python 3.11-3.13, fixed local
NTFS volumes. File reads/writes and audit append use a dedicated Windows backend.
POSIX behavior is unchanged. Network shares, removable drives, non-NTFS,
reparse-point workspaces/ancestors/targets, hard-linked files, device namespaces,
alternate data streams and DOS path aliases fail closed.

Native SecretVault and MemoryStore refuse initialization because Windows ACL privacy is not yet
implemented. The secret-service demo also refuses native serving. This is not a
full runtime port. Windows installs include tzdata for scheduler timezone rules.

Native isolated workers and the default bounded container runner refuse execution:
Windows Job Object resource enforcement is not implemented. Use WSL for those.
The experimental AF_UNIX secret-return demo is not included in the native gate.
It remains a non-isolating prototype on POSIX, not a production security boundary.

## File boundary

The backend opens a fixed drive and holds every directory handle while walking
one validated component at a time with `NtCreateFile` and `RootDirectory`.
Each returned handle is inspected before use. Reparse points and unexpected file
types are rejected. Directory handles omit write/delete sharing. Write targets
are opened without sharing and without truncation; file type, link count and
filesystem are checked before truncating and writing through the same handle.
No `resolve()`/check/open fallback is used. Existing symlink/junction workspaces
are deliberately rejected rather than resolved.

Windows-specific validation rejects backslash input separators, `:`, UNC/device
paths, absolute paths, empty/dot/dot-dot components, trailing dot/space aliases,
control characters, tilde/8.3 aliases, CONIN$/CONOUT$ and reserved DOS names.
This includes aliases in workspace/audit ancestors. Use a long-name path for
the working directory; a Windows TEMP value containing RUNNER~1 is refused. Unicode UTF-16 names are supported.

## Audit boundary

Append uses a retained NTFS file handle and `LockFileEx` over a consistent full
range, with an explicit 10-second contention deadline. Tail validation, chain
append and flush happen while locked. `FlushFileBuffers` completes before unlock.
A partial tail, failed lock, timeout or sync failure is not reported as success.
No thread-only or no-op lock fallback exists.

The chain is keyed with HMAC-SHA256; the key lives in the OS credential store
(Windows Credential Manager on this backend) and never in the workspace, so
forging records requires key access, not just write access to the log - see
[Keyed audit chain](keyed-audit.md). Verification refuses leaf symlinks;
on Windows it also uses the anchored handle walk. POSIX verification does not
pin ancestor directories, so use a trusted directory.

Native file/audit creation inherits directory ACLs; it does not match POSIX
0o600 privacy. Keep workspace and audit directories private using Windows ACLs.
This backend does not enforce confidentiality against other local accounts.
SecretVault, MemoryStore and secret-service stay unsupported until ACL privacy
is implemented. Antivirus/indexer sharing violations at handle open fail closed
without retry. The 10-second audit timeout covers acquired-handle lock contention,
not failed opens; callers may retry the whole operation after resolving contention.

## Gates and limitations

Native CI measures supported tests on Windows runners for Python 3.11-3.13,
installed wheel/entrypoints, scripted approval demo and audit verifier.
POSIX branch coverage and native backend branch coverage are measured separately.
Native-only assertions cover audit thread/process contention, crash lock release,
partial tail, lock/sync failures, ancestor/leaf pinning, junction/symlink/hardlink
refusal and attempted hardlink creation during exclusive writes.

A passed CI matrix is regression evidence, not an external security audit. Storage
failure injection cannot reproduce every disk-full or power-loss condition. WSL
remains recommended for the complete runtime and unsupported worker modes.

Sources: [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile),
[CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea),
[LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).
