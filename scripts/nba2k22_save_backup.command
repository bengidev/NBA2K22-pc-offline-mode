#!/bin/zsh
set -euo pipefail

GAME_DIR="${NBA2K22_DIR:-${0:A:h}}"
SAVE_DIR="$GAME_DIR/data/steam/steam_settings/1644960/remote"
BACKUP_ROOT="$GAME_DIR/_save_backups"

usage() {
  echo "Usage:"
  echo "  $0 backup [label]    - Backup save files (default label: timestamp)"
  echo "  $0 restore <name>    - Restore save files from _save_backups/<name>"
  echo "  $0 list              - List available backups"
  echo ""
  echo "Tip: Set NBA2K22_DIR=/path/to/NBA2K22 if running from outside the game folder."
}

if [[ ! -d "$SAVE_DIR" ]]; then
  echo "Error: Save directory not found: $SAVE_DIR" >&2
  exit 1
fi

mkdir -p "$BACKUP_ROOT"

cmd="${1:-backup}"
case "$cmd" in
  backup)
    label="${2:-$(date +%Y%m%d_%H%M%S)}"
    dest="$BACKUP_ROOT/$label"
    if [[ -e "$dest" ]]; then
      dest="$BACKUP_ROOT/${label}_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$dest"
    cp -a "$SAVE_DIR/" "$dest/"
    echo "Backup created: $dest"
    ;;
  restore)
    name="${2:-}"
    if [[ -z "$name" ]]; then
      echo "Error: specify backup name to restore." >&2
      usage
      exit 1
    fi
    src="$BACKUP_ROOT/$name"
    if [[ ! -d "$src" ]]; then
      echo "Error: Backup not found: $src" >&2
      exit 1
    fi
    safety="$BACKUP_ROOT/pre_restore_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$safety"
    cp -a "$SAVE_DIR/" "$safety/"
    cp -a "$src/" "$SAVE_DIR/"
    echo "Restored from: $src (previous state saved to: $safety)"
    ;;
  list)
    ls -1t "$BACKUP_ROOT"
    ;;
  *)
    usage
    exit 1
    ;;
esac
