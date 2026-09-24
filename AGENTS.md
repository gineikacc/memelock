# AGENTS.md — memelock / mule

## Build / verify

```sh
make
```

Must stay `-Wall -Wextra` clean. No test suite. Binary name stays `memelock`.

## Conventions

- One file: `memelock.c`. Prefer editing in place; match existing style (no drive-by refactors).
- UI string title is **mule**; code, logs, binary, paths still say memelock unless renaming everything on purpose.
- Commits: short imperative subject. Signing key may prompt for passphrase — if commit fails on SSH sign, use `git -c commit.gpgsign=false commit …` and mention it.
- Local git only; do not add a remote unless asked.

## Architecture map (`memelock.c`)

1. **X11 lock** — own `Display`, fullscreen hints, `XGrabKeyboard`/`XGrabPointer` on root, focus steal + retry at startup, re-grab every 0.5s.
2. **Password** — `pump_x11_input` / `handle_xkey` / `ctrl_binds` / `authenticate` (PAM). Raylib does not receive keys.
3. **Snow sim** — flakes, heightmap `pile[]`, float tint channels, `pile_relax` avalanche, lava → obsidian.
4. **Background** — root screenshot before `InitWindow`, float Gaussian + dither, upload after GL context.
5. **Weather** — Open-Meteo via libcurl + json-c, pthread fetch, cache in `~/.cache/memelock/`, fixed-cell widget bottom-left. Ctrl+R toggles.
6. **Main loop** — swallow `WindowShouldClose`, re-grab, pump X, auth, `snow_update`, draw scene + UI boxes + weather.

## Product decisions (respect these)

- **No water**, no snow buoyancy/floating, **no lava melting** — removed after trying them; only re-add if explicitly requested.
- Pile can grow to **full screen** height (old 30% cap removed).
- Shift must type into the password; only Ctrl/Alt/Super are blocked for printable input.
- Flake spawn: **start with 1**, interval = avg fall time / limit.
- Tint must not darken over time: keep pile RGB in **float**, round once in `pile_color_at`.
- Lava spawn rate currently **1/500** (user “for now” test rate; original was 1/5000).

## Docket (from source comment + history)

- Snow plow → `pile_push` + debris particles  
- Meteors → `pile_blast` crater + spark/debris  
- Mouse dig/push → handle `ButtonPress`/`MotionNotify` on our X grab (raylib will not see the mouse)  
- Wind, pile AO/shading, settling color  

`pile_remove` / `pile_push` / `pile_blast` exist as hooks (`PILE_HOOK`, unused).

## Gotchas

- `Font` clash: `#define Font X11Font` before X11 includes, `#undef Font` after.
- raylib `GetWindowHandle()` on X11 returns `Window*`, not `GLFWwindow*`.
- `SNOW_COUNT` ramp uses `snow_active`; draw/update loops only go to `snow_active`, not `SNOW_COUNT`.
- Lava does **not** clear pile anymore; it only falls and becomes obsidian at the bottom.
- `french_slang_and_sentences.txt` is unrelated scratch data.

## Quick test ideas

- `./memelock --snow-speed=20` for fast piling / lava.
- `./memelock --snow-tint=white` vs default `mix`.
- Hold Super/Alt while typing: must not insert; Shift must insert.
- `./memelock --city=Paris,France` for geocoded weather; `--no-weather` to hide widget.
- Ctrl+R toggles widget; Ctrl+W still deletes word.
