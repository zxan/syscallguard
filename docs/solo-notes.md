# Solo branch notes
Fallback build of SyscallGuard on branch `solo`. Team build lives on `main`.
Log solo work here only — never in docs/shared.md or the per-person files.

## Rules
- guard/bpf/ is owned by main. Never edit it on solo.
- Sync kernel from main when a milestone lands there:
      cd /home/zxan/projects/syscallguard-solo
      git checkout main -- guard/bpf/
      git commit -m "chore: sync kernel from main"
- Never push solo to main. Never merge either direction.
- Contracts 1-4 in ARCHITECTURE.md apply unchanged. Contract changes happen on
  main first with a `contract:` commit plus a docs/shared.md entry, then sync here.
- policy/policy.toml is per-worktree and gitignored. Solo's copy points at
  /home/inno/syscallguard-solo/demo/project/.env
- Default mode audit. Enforce only in the VM.

## Log
### 2026-10-19
- Branch and worktree created from main at 2e80714.
