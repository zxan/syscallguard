#!/usr/bin/env bash
# Between-judge housekeeping. Changes nothing, checks everything.
EXPECT_INO=760558
EXPECT_DIR=/home/inno/syscallguard-solo
ok=1

cd "$(dirname "$0")/.." || exit 1
[ "$PWD" = "$EXPECT_DIR" ] || { echo "WRONG DIR: $PWD"; exit 1; }

pkill -f 'demo/agent.py' 2>/dev/null
pkill -f 'curl.*9999'    2>/dev/null
sleep 0.3

if pgrep -f 'guard/guard.py' >/dev/null && pgrep -f 'bridge/bridge.py' >/dev/null; then
  echo "pipeline: up"
else
  echo "PIPELINE DOWN -- restart window 4 manually"; ok=0
fi

ino=$(stat -c '%i' demo/project/.env 2>/dev/null)
if [ "$ino" = "$EXPECT_INO" ]; then
  echo "env inode: $ino ok"
else
  echo "ENV INODE CHANGED ($ino, expected $EXPECT_INO)"
  echo "protection has lapsed -- restart the pipeline"; ok=0
fi

[ "$ok" = 1 ] && echo "READY" || echo "NOT READY"
