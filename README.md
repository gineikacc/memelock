# mule (memelock)

Fullscreen X11 screen lock with a raylib snow background. UI title is **mule** (help text only; no on-screen center title); binary/repo still `memelock`.

Unlocks only via PAM (`pam_start("login")` + `pam_authenticate`). WM close is swallowed; keyboard is grabbed on the root window so awesomewm kill/hotkeys do not fire.

## Build

```sh
make          # gcc -Wall -Wextra -O2  (memelock.c + dvd_logo.c)
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
| `-d`, `-d=N` | background darken `0..255` (default `160`; **0 = none, 255 = pitch black**) |
| `--min-blur=N` | minimum blur radius `0..64` (default `5`; floor for `-b` and live keys, **Ctrl+H** raises it at runtime; **0 = full-res original**, darken still applies) |
| `--weather` / `--no-weather` | weather widget on/off at start (default **on**) |
| `--city=NAME[,CC]` | weather location by city (`Vilnius`, `Paris,FR`) |
| `--lat=` / `--lon=` | exact weather coordinates (wins over city) |
| `--layout[=PATH]` | live-reload weather layout file (default `~/.cache/memelock/layout.txt`) |
| `--snow` / `--no-snow` | snow spawning on/off at start (default **on**) |
| `--meteors` / `--no-meteors` | falling meteors on/off at start (default **on**) |
| `--dvd` / `--no-dvd` | DVD logo bounce at start (default **off**) |
| `--snow-speed=N` | snowfall speed multiplier (default `1.0`) |
| `--dvd-speed=N` | DVD logo speed multiplier (default `1.0`; independent of `--snow-speed`) |
| `--snow-tint=MODE` | `white` \| `ice` \| `mix` (default `mix`) |
| `--no-clock` | hide the top-center clock (default **on**) |
| `--fade-password=N` | idle seconds before the `*` box fades (default `5`; `0` = off) |
| `--wind=0` | disable ambient wind gusts |
| `--microwave` / `--no-microwave` | pixel microwave timer (default **visible, idle**) |
| `--quotes` / `--no-quotes` | blockquote under the clock (default **on**) |
| `--stocks[=A,B,C]` / `--stock=SYM` | stock list top-right (default **off**; repeat `--stock` or comma-list; bare `--stocks` → `^GSPC` `INTC` `TSLA`; first load **blocks** until fetched) |
| `--raylib-log` | enable raylib's own log output (off by default) |
| `--crash-key` | enable **Ctrl+K** deliberate crash (testing the supervisor only) |
| `--no-supervisor` | run the lock directly, no monitor process |
| `--supervisor-log=PATH` | supervisor event log (default `~/.cache/memelock/supervisor.log`) |

Every normal run is supervised: `memelock` starts as a small monitor that
spawns the lock as a child and respawns it if it exits non-zero or dies on a
signal (clean unlock = exit 0, monitor exits too). 5 abnormal deaths within
60s (a crash loop, or a bad flag) makes the monitor give up with exit 1
instead of looping forever. Lifecycle lines (starts, exit statuses, signals,
uptimes) append to the supervisor log; `--help` and `--no-supervisor` never
fork. `kill -TERM` on the monitor forwards to the child and shuts down
without respawning, so killing the lock child alone re-locks but stopping the
monitor stops everything.

While locked: **Ctrl+R** toggles the weather widget, **Ctrl+S** toggles snow spawn, **Ctrl+X** clears the pile, **Ctrl+M** toggles meteors, **Ctrl+,** / **Ctrl+.** step blur, **Ctrl+B** blur field, **Ctrl+H** raises the min-blur floor, **Ctrl+Shift+,** / **Ctrl+Shift+.** darken ±5, **Ctrl+D** darken field (digits only, 0..255), **Ctrl+V** toggles the DVD logo, **Ctrl+T** microwave hide, **Ctrl++** / **Ctrl+KP+** microwave **+30**, **Ctrl+Q** next quote, **Ctrl+O** stocks. **Ctrl+K** crashes the lock on purpose, but only when started with `--crash-key` (supervisor test). Fields: top-left, Enter commits, Esc cancels. Blur/darken recompute runs on a worker — old frame stays until ready.

Center stack: top-center **clock** + date + **blockquote** (left bar, left-justified; narrow column → ~2–3 lines, very short stays 1 line; author or muted **unknown**; random pick each start). Soft rounded password panel (**starts faded out**; after idle the `*` box fades **fully** — no hint). No center title text. Microwave: **keyboard only** — Ctrl+T hides, Ctrl++ / KP+ adds +30 (no mouse on this lock). Timer text only while counting down (none at 0). When the timer ends: one cozy dink + warm done glow.

## Weather widget (bottom-left)

- **Open-Meteo** (no API key): **7 hours starting at the current hour** (wall clock, in the forecast's own timezone — a stale cache can no longer pin the rows to the hour it was fetched) + **7 days** (columns line up; no separate “today” row)
- Hours: label · temp · rain% — **night hours show label only** (no temp, no %)
- Days: label · **high** · rain% (no lows)
- Temp digits colored by weather (clear=yellow, overcast=gray, rain=blue, snow=ice, storm=violet)
- Location order: `--lat/--lon` → `--city=` → cached IP geolocation (`ipapi.co`)
- Cached under `~/.cache/memelock/`; refreshes ~every 15 min in a background thread, and a cache older than that is refetched immediately at startup

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

## Window visibility

- The lock window is **not** shown in the tag's client list: it asks the WM to skip taskbar/pager (`_NET_WM_STATE_SKIP_TASKBAR` + `SKIP_PAGER`). Sent as an EWMH `ClientMessage` to the root — a bare property write is ignored by awesome (also written to `_NET_WM_STATE` for tools that read the property).

## Password input

- Keys come from **our** X connection (`XGrabKeyboard` + `owner_events=False`), not raylib/GLFW.
- `Ctrl+U` clear line, `Ctrl+W` delete word (plain Backspace deletes too — the old `Ctrl+H` backspace alias is gone).
- `Ctrl+S` toggle snow spawn, `Ctrl+X` clear pile.
- `Ctrl+M` toggle meteors (on by default; stops new spawns, in-flight ones still land).
- `Ctrl+,` / `Ctrl+.` blur −/+, `Ctrl+Shift+,` / `Ctrl+Shift+.` darken ±5.
- `Ctrl+H` raises the `--min-blur` floor by 1 (no decrease keybind — the floor only tightens while locked; current blur lifts with it).
- `Ctrl+B` blur field, `Ctrl+D` darken field (field takes keys while open).
- `Ctrl+V` toggles the DVD logo (off by default / `--dvd`).
- `Ctrl+T` microwave hide, `Ctrl++` / `Ctrl+KP+` microwave +30, `Ctrl+Q` next quote, `Ctrl+O` stocks.
- Enter submits (async PAM — snow keeps moving; “checking…” while in flight); wrong password shows a soft rose box for ~1.5s.
- Idle: the `*` box starts faded out and stays that way until a password key; it also fades after `--fade-password` seconds idle (any key brings it back; fully invisible when idle — no residual frame or hint).
- **Shift** types normally (caps/symbols). **Ctrl/Alt/Super** do not insert password characters (only the Ctrl binds above).

## Background simulation

| Piece | Behavior |
|-------|----------|
| Snow | Ramps in from 1 flake; spawn interval ≈ avg fall time / `SNOW_COUNT` (200). Deposit height `size² × 3` (up to full screen). Per-flake near-white tint; pile columns store **float** RGB (round only at draw — integer truncation used to turn the pile black). Spawn off → landed flakes park dormant; Ctrl+X wipes the pile. Occasional **wind gusts** ramp in ~500ms and ease out over ~3s, sideways only; gaps **+10s** vs older defaults (`--wind=0` off). |
| Background | Full-res capture in `bg_full`. Blur 0 → native image (darken still applies). Blur > 0 → ≤960 (+ ÷2/÷4 for large r) → 3× box → darken + dither. CPU work on a worker thread; main only swaps the texture. Darken absolute `0..255`. |
| DVD logo | Off by default (`--dvd` / Ctrl+V). Official Commons mark embedded in `dvd_logo.c` (PD-textlogo, 512×226 white PNG, tinted by palette); 364 px/s (× `--dvd-speed`). **AABB collision == drawn rect** (half-extents from texture aspect). Near-corner snap within 96px of inner corner — but never a corner on the wall just hit (that path skims the edge), and every heading stays **≥25° off both axes**, so no bounce runs parallel to an edge; both-wall hit = corner → `dvd_corner_hit` + bounce out. |
| Clock + quote | Top-center `HH:MM` + date; **blockquote** under it (left bar, left-justified; **narrow column** ~2–3 lines, very short stays 1 line; author / muted **unknown**, random each start; **DriveBird** free API cache `~/.cache/memelock/quotes.json`, offline builtins). `--no-clock` / `--no-quotes`. Font is humanist sans with Latin-1 + punctuation codepoints (`:` `“”` etc.). |
| Microwave | Bottom-right pixel art; visible idle by default. **+30** via **Ctrl++ / Ctrl+KP+** (keyboard only — no mouse). Timer text only while counting down (none at 0/idle/done); at 0 → cozy dink (soft-attack wave) + done glow. Ctrl+T hides. |
| Stocks | Opt-in `--stocks` / `--stocks=A,B` / `--stock=SYM` (default `^GSPC`, `INTC`, `TSLA`); Yahoo chart API, cache `stocks.json` (keyed **by symbol**), top-right list. **First load blocks**; missing symbols are fetched (grew list / legacy `i0` cache) and *everything* is refetched when the cache is older than 15 min. Refresh on worker, wall-clock scheduled. Ctrl+O toggles. Soft green/rose for ±%. |
| Meteors | On flake respawn, 1/500 → **comet**: 600–800 px/s (× `--snow-speed`) with sideways drift ±70–220 px/s and a 16-point glowing trail. Hits the pile → `pile_blast` crater (46–76px, force 55–90) that dumps half the snow on the rim + **30 debris particles under gravity** (orange sparks short, snow chunks longer, alpha fades with life). Lands on bare ground (<3px) → obsidian. **Ctrl+M** / `--no-meteors`. |
| Obsidian | Dark purple core + random shell ring; sinks into pile; never merges. |

Removed on purpose (do not re-add without asking): water particles, snow floating, lava melting.

Heightmap helpers: `pile_remove`, `pile_push` (unused, `PILE_HOOK`); `pile_blast` is used by meteor impacts.

## UI

Centered dark rounded panels for password `*` and error (no bottom hint, no center `mule` title).

## Layout

- `memelock.c` — single translation unit
- `Makefile` — build
- `AGENTS.md` — session notes / docket

Git is local only (no remote). Home dotfiles repo ignores this directory.
