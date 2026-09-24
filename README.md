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
| `-b`, `-b=N` | background blur radius (default `5`) |
| `-d`, `-d=N` | background darken, `-255..255` (default `-25`) |
| `--weather` / `--no-weather` | weather widget on/off at start (default **on**) |
| `--city=NAME[,CC]` | weather location by city (`Vilnius`, `Paris,FR`) |
| `--lat=` / `--lon=` | exact weather coordinates (wins over city) |
| `--layout[=PATH]` | live-reload weather layout file (default `~/.cache/memelock/layout.txt`) |
| `--snow-speed=N` | fall-speed multiplier (default `1.0`) |
| `--snow-tint=MODE` | `white` \| `ice` \| `mix` (default `mix`) |

While locked: **Ctrl+R** toggles the weather widget (Ctrl+W still deletes word).

## Weather widget (bottom-left)

- **Open-Meteo** (no API key): next **7 hours** + **7 days** (columns line up; no separate “today” row)
- Hours: label · temp · rain% — **night hours show label only** (no temp, no %)
- Days: label · **high** · rain% (no lows)
- Temp digits colored by weather (clear=yellow, overcast=gray, rain=blue, snow=ice, storm=violet)
- Location order: `--lat/--lon` → `--city=` → cached IP geolocation (`ipapi.co`)
- Cached under `~/.cache/memelock/`; refreshes ~every 15 min in a background thread

### Layout file (optional)

With `--layout` (or `--layout=PATH`), edits to the file hot-reload ~6×/sec:

```
# ~/.cache/memelock/layout.txt
margin=16
pad=6
col_gap=2
row_gap=0
block_gap=8
font_label=24
font_temp=36
font_pop=18
min_col_w=40
bg_alpha=190
```

Rows are font-tight (pitch = font size + `row_gap`). `block_gap` is the only gap between the hours and days columns. `row_h` / `day_row_h` still accepted as extra px after each row (default 0). Unknown keys are ignored; missing file → built-in defaults.

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
