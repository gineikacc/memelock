# AGENTS.md — memelock / mule

## Build / verify

```sh
make
```

Must stay `-Wall -Wextra` clean. No test suite. Binary name stays `memelock`.

## Conventions

- Main code lives in `memelock.c` (plus generated `dvd_logo.c` / `dvd_logo.h` for the embedded PD DVD mark). Prefer editing `memelock.c` in place; match existing style (no drive-by refactors). Do not hand-edit `dvd_logo.c`.
- UI string title is **mule** (help/banner only; **no center on-screen `mule` text** — removed). Code, logs, binary, paths still say memelock unless renaming everything on purpose.
- Commits: short imperative subject. Signing key may prompt for passphrase — if commit fails on SSH sign, use `git -c commit.gpgsign=false commit …` and mention it.
- Local git only; do not add a remote unless asked.

## Architecture map (`memelock.c`)

1. **X11 lock** — own `Display`, fullscreen hints, `XGrabKeyboard`/`XGrabPointer` on root, focus steal + retry at startup, re-grab every 0.5s. Also sends an EWMH `_NET_WM_STATE` **ClientMessage** (root, `SubstructureRedirectMask`) adding `SKIP_TASKBAR`+`SKIP_PAGER` so the window never appears in the tag's tasklist (bare `XChangeProperty` on `_NET_WM_STATE` is ignored by awesome — the message is what works).
2. **Password** — `pump_x11_input` / `handle_xkey` / `ctrl_binds`. PAM runs on a **detached auth thread** (`auth_start` / `auth_poll`); main never blocks on `pam_authenticate`. Raylib does not receive keys.
3. **Snow sim** — flakes, heightmap `pile[]`, float tint channels, `pile_relax` avalanche, **meteors**, ambient **wind gusts** (horizontal only, **~500ms ramp** up / **~3s ease-out** via `wind_x`/`wind_target`; **gaps +10s** — next-gust 12.5–16.5s, post-gust calm 15–23s; `--wind=0`). **Meteors** (`meteor[]` / `meteor_spawn` / `meteor_update`, renamed from the lava droplet): 1/500 flake respawns, **600–800 px/s** × `snow_speed_mult`, **vx ±70–220 px/s** sideways, **16-point trail** (`trail_x/y[0]` = newest, drawn head-bright). Pile hit → `meteor_impact`: `pile_blast(46–76px, force 55–90)` crater + rim, then **30 gravity debris** (`part[]`, `PART_GRAVITY 1500`, orange sparks 0.35–0.8s / white snow chunks 0.7–1.4s, alpha = life fraction); pile < 3px → falls to bare ground → `obsidian_spawn`. Spawning gated by `meteors_enabled` (Ctrl+M / `--no-meteors`). DVD logo (`dvd_*`, off by default): embedded official mark from `dvd_logo.c`, 364 px/s × `--dvd-speed` (not `--snow-speed`), bounce scatter ±0–20°, then `dvd_keep_off_axes` pins every heading **≥25° off both axes** (`DVD_MIN_DEG`), corner auto-aim runs **mid-flight, not on the bounce**: if the line the logo is already flying on passes within 96px (`DVD_AIM_TOL`) of a corner it is heading **toward** (ahead in both axes ⇒ a left-wall bounce can never aim top-left/bottom-left — the bounce-time version pointed back into the wall it had just left and rode the edge in, which the user called trash), it rotates onto that exact line so both clamps fire = corner hit. Aim directions must also clear `DVD_MIN_DEG` (a near-axis corner direction is skipped, not ridden). Deliberately rare: ~1 hit per 2 min at 1920×1080 — do not tune it up, **AABB == drawn rect** (`dvd_hw`/`dvd_hh` from texture aspect). Both-wall hit = corner: sets `dvd_corner_hit` (edge flag — **still no consumer**, purely visual) and bounces out — do not re-aim into the corner.
4. **Background** — full-res root shot in `bg_full`; blur 0 = native + darken only; blur > 0 = downscale budget + 3× box + darken/dither. Darken is **absolute 0..255** (0=none, 255=black; `-d` rejects negatives; **default 160**). CPU runs on a **worker thread**; main only `bg_poll_upload`s the finished texture (GL stays main-thread).
5. **Weather** — Open-Meteo via libcurl + json-c, pthread fetch, cache in `~/.cache/memelock/`, compact fixed-cell widget bottom-left (no today line/titles; night hours = label only; day highs only). Hour block index = **wall-clock now in the payload's timezone** (`utc_offset_seconds` + `gmtime_r`, first `h_time` entry `>= now`) — never `atoi(current.time+11)` as an array index (that pinned stale caches to the fetch hour, e.g. 5am all day); payload `current.time` hour is only the fallback. Cache older than `W_REFRESH_SEC` (mtime) ⇒ `last_ok = 0` so the thread refetches immediately at startup instead of waiting 15 min. Temp color = WMO code. Ctrl+R toggles. Optional live layout file via `--layout[=PATH]`.
6. **Clock + quotes** — top-center clock (default on, `--no-clock`); **DriveBird** (`www.drivebird.com/api/quotes/random?count=50`, free/no key, no attribution UI) blockquote under it (left bar, left-justified multi-line; real author names or muted **unknown** — never “mule”/“proverb”; **random pick each start**; `--no-quotes`, Ctrl+Q next). Cache `quotes.json`; offline builtins (real quotes only). Shared `weather_font` (`LoadFontEx` with Latin-1 + punctuation codepoints so `:` `“”` etc. render).
7. **Microwave timer** — bottom-right pixel art, visible idle by default (`--no-microwave` / Ctrl+T hide only). **+30 is keyboard-only**: `Ctrl++` / `Ctrl+KP+` → `mw_add_thirty` (no mouse — user has none). At 0: cozy soft-attack dink (in-memory wave, soft-fail audio) + done glow; **no timer text** at 0/idle/done (only while counting down). Timer text above when running.
8. **Stocks** — opt-in `--stocks` / `--stocks=A,B` / `--stock=SYM` (defaults `^GSPC`, `INTC`, `TSLA`); Yahoo v8 chart, cache `stocks.json` **keyed by symbol**, top-right, Ctrl+O. **First load blocks** in `stocks_start` before the main loop: load cache, then **fetch symbols still missing** (list grew / old index-keyed cache) **and refetch everything when the cache mtime is older than `STOCKS_REFRESH_SEC`** — a fresh cache always loads fully, so the age check is the only thing that un-sticks stale prices; a failed fetch does not rewrite the cache (no fresh-mtime lie). Refresh runs on the worker and is scheduled on the **wall clock** (`time(NULL)`), not `GetTime()`: the lock restarts constantly and suspends while up, so a monotonic since-start timer never reached 900 s and the panel froze for weeks. Soft green/rose for ±%.
9. **Main loop** — swallow `WindowShouldClose`, re-grab, pump X (keys), `auth_start`/`auth_poll`, `snow_update`, `mw_update`, `layout_poll`, password **idle fade** of `*` box only (**fully** invisible when idle — snaps to 0, no residual frame), draw scene + clock/quote + UI boxes + weather + stocks + microwave (no center `mule` title, **no bottom hint**).
10. **Supervisor** — `main` is a monitor, `app_main` is the lock child. Respawn on non-zero exit / signal death (exit 0 = unlocked, monitor exits); 5 abnormal deaths in 60s → give up exit 1. Event log `~/.cache/memelock/supervisor.log` (`--supervisor-log=PATH`); `--no-supervisor` bypass, `-h` never forks; supervisor-only flags stripped before child parse. SIGTERM/SIGINT forward to child, no respawn after.

`curl_global_init` once in `main` (not in `weather_start`). Unload font / `curl_global_cleanup` / audio on exit.

## Product decisions (respect these)

- **No water**, no snow buoyancy/floating, **no lava melting** — removed after trying them; only re-add if explicitly requested.
- Pile can grow to **full screen** height (old 30% cap removed).
- Shift must type into the password; only Ctrl/Alt/Super are blocked for printable input.
- Flake spawn: **start with 1**, interval = avg fall time / limit.
- Tint must not darken over time: keep pile RGB in **float**, round once in `pile_color_at`.
- Meteor spawn rate currently **1/500** (user “for now” test rate; original was 1/5000).
- Weather: **no** today banner, **no** `next`/`week` titles, **no** day lows, **no** night hour temps or night rain%. Prognosis color = weather code on temp digits.
- Layout file is **opt-in** (`--layout`); default off — do not read/stat it otherwise.
- DVD logo is **opt-in** (`--dvd`); default off — do not enable unless asked. Ctrl+V toggles.
- Clock + quotes default **on**; stocks **opt-in** (blocking first load when enabled); microwave **visible idle** (not running until +30).
- Quotes: source is **DriveBird** free API (not ZenQuotes — Zen required on-screen attribution; Quotable had a dead cert). Author line shows real names or muted `unknown` — **never** `mule`, `proverb`, or long “author unknown” phrases (normalize in `quotes_display_auth`). No on-screen attribution line (removed by user request). **Narrow column** (~460px / half screen max) → ~2–3 lines; very short stays 1 line.
- **No mouse** — do not depend on clicks; microwave +30 is keyboard only. No center on-screen `mule` title.
- Password soft UI: rounded panels, off-white/rose (not pure white/red); fade **`*` box only** to fully invisible (no ghost frame).
- Raylib `TraceLog` is **off** by default (`SetTraceLogLevel(LOG_NONE)` before `InitWindow`); `--raylib-log` restores it. App logs use `fprintf(stderr, "[memelock] …")`.

## Docket (from source comment + history)

- Snow plow → `pile_push` + debris particles  
- Mouse dig/push → handle more `MotionNotify` on our X grab for pile digging (microwave **+30 is keyboard-only** now; X `ButtonPress` path is a no-op).
- Pile AO/shading, settling color (wind gusts for snow are done).

`pile_remove` / `pile_push` exist as hooks (`PILE_HOOK`, unused); `pile_blast` is now called by meteor impacts.

## Gotchas

- `Font` clash: `#define Font X11Font` before X11 includes, `#undef Font` after.
- raylib `GetWindowHandle()` on X11 returns `Window*`, not `GLFWwindow*`.
- `SNOW_COUNT` ramp uses `snow_active`; draw/update loops only go to `snow_active`, not `SNOW_COUNT`.
- Meteors crater the pile on impact (`pile_blast` + gravity debris); they only become obsidian when they land on **bare** ground (pile < 3px). Never melts/clears the pile wholesale (no lava melting).
- `french_slang_and_sentences.txt` is unrelated scratch data.

## Quick test ideas

- `./memelock --snow-speed=20` for fast piling / meteor rain (DVD stays at `--dvd-speed`).
- `./memelock --dvd --dvd-speed=0.5` for a slow logo.
- `./memelock --snow-tint=white` vs default `mix`.
- Hold Super/Alt while typing: must not insert; Shift must insert.
- `./memelock --city=Paris,France` for geocoded weather; `--no-weather` to hide widget.
- Ctrl+R toggles widget; Ctrl+W still deletes word.
- Ctrl+S toggles snow spawn (`--no-snow` at start); Ctrl+X clears the pile.
- Ctrl+M toggles meteors (`--no-meteors` at start); needs a pile first — watch the crater + debris burst, then the crater fill-back.
- Ctrl+, / Ctrl+. step blur (`--min-blur` floor, default 5); Ctrl+B blur field; **Ctrl+H raises the min-blur floor only** (no decrease bind — floor tightens while locked, lifts current blur if below; the old Ctrl+H backspace alias is gone, plain Backspace still deletes).
- Ctrl+Shift+, / Ctrl+Shift+. darken ±5; Ctrl+D darken field (0..255, digits only). Fields are top-left modular (Enter commits, Esc cancels — keys do not hit the password while open).
- `./memelock --dvd` then Ctrl+V; wait for a **rare** corner hit — the logo flies into it from mid-screen, and it must never look like it aims *back* into the wall it just hit (that edge-riding snap was called trash and is gone). ~1 hit / 2 min at 1920×1080 is the intended rate; also no bounce may ever run near-parallel to an edge.
- `./memelock --layout` then edit `~/.cache/memelock/layout.txt` — gaps/fonts update live.
- Starts with the `*` box already faded (invisible); idle 5s also fades it; any password key restores.
- `./memelock --stocks` top-right; Ctrl+O hide; `--stocks=AAPL,INTC` or `--stock=AAPL --stock=INTC` custom list; first open may wait on fetch; cache is per-symbol (missing rows fetch alone).
- `touch -d '1 hour ago' ~/.cache/memelock/stocks.json` then relock → next start logs `stocks: fetching (stale cache)` and refetches (the 15-min age check; in-session refresh is wall-clock, so suspend/resume also refetches).
- Ctrl+T hide microwave; Ctrl++ / Ctrl+KP+ microwave +30; wait for cozy dink (no `0:00` text at end).
- Ctrl+Q next quote; Ctrl+O stocks.
- `./memelock --crash-key`, then Ctrl+K → `abort()`; supervisor logs `killed by Aborted` + respawns. Without the flag Ctrl+K is a no-op.
