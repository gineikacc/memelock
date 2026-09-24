# mule (memelock)

Fullscreen X11 screen lock with a raylib snow background. UI title is **mule**; binary/repo still `memelock`.

Unlocks only via PAM (`pam_start("login")` + `pam_authenticate`). WM close is swallowed; keyboard is grabbed on the root window so awesomewm kill/hotkeys do not fire.

## Build

```sh
make          # gcc -Wall -Wextra -O2
make clean
```

Depends on: raylib, X11 (+ Xrandr/Xinerama/Xi/Xcursor), PAM (`libpam`, `libpam_misc`), GL, pthread.

## Run

```sh
./memelock -h
./memelock --snow-speed=10 --snow-tint=ice
```

| Flag | Meaning |
|------|---------|
| `-h`, `--help` | usage and exit |
| `--snow-speed=N` | fall-speed multiplier (default `1.0`) |
| `--snow-tint=MODE` | `white` \| `ice` \| `mix` (default `mix`) |

Unknown flags print usage and exit 1.

## Password input

- Keys come from **our** X connection (`XGrabKeyboard` + `owner_events=False`), not raylib/GLFW.
- `Ctrl+U` clear line, `Ctrl+W` delete word, `Ctrl+H` backspace.
- Enter submits; wrong password shows a red box for ~1.5s.
- **Shift** types normally (caps/symbols). **Ctrl/Alt/Super** do not insert password characters (only the Ctrl binds above).

## Background simulation

| Piece | Behavior |
|-------|----------|
| Snow | Ramps in from 1 flake; spawn interval ≈ avg fall time / `SNOW_COUNT` (200). Deposit height `size² × 3` (up to full screen). Per-flake near-white tint; pile columns store **float** RGB (round only at draw — integer truncation used to turn the pile black). |
| Lava | On flake respawn, 1/500 → ~20px droplet. No melt (removed). Hits screen bottom → obsidian. |
| Obsidian | Dark purple core + random shell ring; sinks into pile; never merges. |

Removed on purpose (do not re-add without asking): water particles, snow floating, lava melting.

Heightmap helpers for future work (unused, `PILE_HOOK`): `pile_remove`, `pile_push`, `pile_blast`.

## UI

Centered dark boxes (no outline) behind prompt (`mule`), password `*`, error, hint.

## Layout

- `memelock.c` — single translation unit
- `Makefile` — build
- `AGENTS.md` — session notes / docket

Git is local only (no remote). Home dotfiles repo ignores this directory.
