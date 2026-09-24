#include "raylib.h"
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <math.h>

// raylib defines `Font`; X11 defines `Font` as XID -> rename X11's away
#define Font X11Font
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#undef Font

// --- X11 hardening (i3lock-style) ---
// How i3lock does it (see i3lock/xcb.c: open_fullscreen_window +
// grab_pointer_and_keyboard):
//  * window created with override_redirect=1 BEFORE mapping, so the WM
//    never manages it (nothing for a kill-client keybind to target).
//  * XGrabKeyboard + XGrabPointer on the ROOT window, retried in a loop
//    (WM may hold the grab briefly at startup; context menus can steal it,
//    hence set-input-focus + retry). While the grab is held, the WM's passive
//    key grabs (awesome global hotkeys, incl. kill client) never fire.
// raylib/GLFW maps its window immediately in InitWindow, so we cannot set
// override_redirect pre-map. What we CAN do (and what actually blocks the
// awesome kill keybind) is the active keyboard grab + swallowing graceful
// WM_DELETE_WINDOW closes. XKillClient (xkill -id) cannot be blocked by any
// X11 client; override_redirect only shrinks the attack surface.
//
// NOTE: raylib 6 GetWindowHandle() on X11 returns `Window*` (pointer to the
// XID), NOT a GLFWwindow*. Cast accordingly.

static Display *xdisplay = NULL; // our own connection (like i3lock's)
static Window xwindow = 0;       // GLFW window XID (server-global, usable here)
static Window xroot = 0;

static int x11_error_handler(Display *dpy, XErrorEvent *ev) {
    char msg[256];
    XGetErrorText(dpy, ev->error_code, msg, sizeof(msg));
    fprintf(stderr, "[memelock] X error: %s (req %d/%d)\n",
            msg, (int)ev->request_code, (int)ev->minor_code);
    return 0; // don't abort like the default handler
}

static void lock_setup_x11(void) {
    XSetErrorHandler(x11_error_handler);

    xdisplay = XOpenDisplay(NULL);
    if (!xdisplay) {
        fprintf(stderr, "[memelock] XOpenDisplay failed, no keyboard grab\n");
        return;
    }

    Window *ph = (Window *)GetWindowHandle();
    if (ph) xwindow = *ph;
    if (!xwindow) {
        fprintf(stderr, "[memelock] GetWindowHandle gave no X window, no grab\n");
        return;
    }
    xroot = DefaultRootWindow(xdisplay);

    // Fullscreen / always-on-top / sticky hints. Harmless without remap;
    // the grab below is what blocks WM hotkeys.
    Atom net_wm_state = XInternAtom(xdisplay, "_NET_WM_STATE", False);
    Atom fs     = XInternAtom(xdisplay, "_NET_WM_STATE_FULLSCREEN", False);
    Atom above  = XInternAtom(xdisplay, "_NET_WM_STATE_ABOVE", False);
    Atom sticky = XInternAtom(xdisplay, "_NET_WM_STATE_STICKY", False);
    Atom states[] = { fs, above, sticky };
    XChangeProperty(xdisplay, xwindow, net_wm_state, XA_ATOM, 32,
                    PropModeReplace, (unsigned char *)states, 3);

    XSetInputFocus(xdisplay, xwindow, RevertToParent, CurrentTime);
    XFlush(xdisplay);
    fprintf(stderr, "[memelock] x11 setup: win=0x%lx root=0x%lx\n",
            (unsigned long)xwindow, (unsigned long)xroot);
}

// Single non-blocking attempt, i3lock-style target: root window.
// Keyboard owner_events=False so ALL keystrokes are delivered to OUR
// connection's grab window no matter which window holds input focus.
// Consequence: raylib/GLFW (separate Display connection) receives NOTHING,
// so password entry is done here via pump_x11_input(), slock-style.
// Pointer owner_events=False like i3lock (we don't need the mouse).
static bool lock_grab_once(void) {
    if (!xdisplay || !xroot) return false;
    int kb = XGrabKeyboard(xdisplay, xroot, False,
                           GrabModeAsync, GrabModeAsync, CurrentTime);
    int pt = XGrabPointer(xdisplay, xroot, False,
                          ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
                          GrabModeAsync, GrabModeAsync, xroot, None, CurrentTime);
    (void)pt; // keyboard is the critical one; pointer failure is non-fatal
    XFlush(xdisplay);
    if (kb != GrabSuccess) {
        fprintf(stderr, "[memelock] XGrabKeyboard status=%d\n", kb);
        return false;
    }
    return true;
}

static void lock_focus_self(void) {
    if (!xdisplay || !xwindow) return;
    // i3lock trick: stealing focus closes context menus that block the grab
    XSetInputFocus(xdisplay, xwindow, RevertToParent, CurrentTime);
    XRaiseWindow(xdisplay, xwindow);
    XFlush(xdisplay);
}

// Bounded retry used ONLY at startup (blocks briefly, before first frame).
static void lock_grab_startup(void) {
    if (!xdisplay) return;
    for (int i = 0; i < 100; i++) {
        if (lock_grab_once()) { fprintf(stderr, "[memelock] keyboard grabbed\n"); return; }
        usleep(10000); // 10ms
    }
    // Possibly a context menu holds the grab; steal focus (i3lock) and retry.
    lock_focus_self();
    for (int i = 0; i < 200; i++) {
        if (lock_grab_once()) { fprintf(stderr, "[memelock] keyboard grabbed (after focus steal)\n"); return; }
        usleep(10000);
    }
    fprintf(stderr, "[memelock] WARNING: cannot grab keyboard, WM hotkeys will still work\n");
}

static void lock_ungrab(void) {
    if (!xdisplay) return;
    XUngrabKeyboard(xdisplay, CurrentTime);
    XUngrabPointer(xdisplay, CurrentTime);
    XFlush(xdisplay);
    XCloseDisplay(xdisplay);
    xdisplay = NULL;
}

// --- Password input, read from OUR X connection (slock-style) ---
// Because the keyboard grab uses owner_events=False, keystrokes arrive here,
// not in raylib. This also makes ctrl-keybinds trivial: one table row each.
// To add a bind, write a passwd_* action and append a { XK_X, fn, "…" } row
// (matched with Ctrl held; letter case is normalized for you).

static char xpassword[128] = {0};
static int xpass_len = 0;
static bool xauth_failed = false;
static bool xpass_submit = false;

static void passwd_backspace_one(void) {
    if (xpass_len <= 0) return;
    // Step back over UTF-8 continuation bytes so multibyte chars delete whole.
    do {
        xpass_len--;
    } while (xpass_len > 0 && (xpassword[xpass_len] & 0xC0) == 0x80);
    xpassword[xpass_len] = '\0';
    xauth_failed = false;
}

static void passwd_backspace(void) { passwd_backspace_one(); }

static void passwd_clear_line(void) {
    memset(xpassword, 0, sizeof(xpassword));
    xpass_len = 0;
    xauth_failed = false;
}

static void passwd_kill_word(void) {
    // Shell-style: eat trailing blanks, then the word itself.
    while (xpass_len > 0 && (xpassword[xpass_len - 1] == ' ' || xpassword[xpass_len - 1] == '\t'))
        passwd_backspace_one();
    while (xpass_len > 0 && xpassword[xpass_len - 1] != ' ' && xpassword[xpass_len - 1] != '\t')
        passwd_backspace_one();
    xauth_failed = false;
}

typedef void (*PasswdAction)(void);

static const struct {
    KeySym ks;
    PasswdAction fn;
    const char *desc;
} ctrl_binds[] = {
    { XK_U, passwd_clear_line, "clear line" },
    { XK_W, passwd_kill_word,  "delete word" },
    { XK_H, passwd_backspace,  "backspace" },
};

static void handle_xkey(XKeyEvent *ev) {
    char buf[32];
    KeySym ks = NoSymbol;
    int n = XLookupString(ev, buf, sizeof(buf), &ks, NULL);

    // Ctrl combos first: match bind table, swallow everything else
    // (so e.g. Ctrl+C / Ctrl+Z can never do anything here).
    if (ev->state & ControlMask) {
        KeySym k = ks;
        if (k >= XK_A && k <= XK_Z) k += (XK_a - XK_A); // Ctrl+Shift+X == Ctrl+X
        for (unsigned i = 0; i < sizeof(ctrl_binds) / sizeof(ctrl_binds[0]); i++) {
            if (k == ctrl_binds[i].ks) {
                ctrl_binds[i].fn();
                return;
            }
        }
        return;
    }

    switch (ks) {
        case XK_Return:
        case XK_KP_Enter:
            if (xpass_len > 0) xpass_submit = true;
            return;
        case XK_BackSpace:
            passwd_backspace();
            return;
        case XK_Escape:
            xauth_failed = false;
            return;
        default:
            break;
    }

    // Printable input (XLookupString already applied Shift/layout for Latin).
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c < 32 || c == 127) continue;
        if (xpass_len < (int)sizeof(xpassword) - 1) {
            xpassword[xpass_len++] = (char)c;
            xpassword[xpass_len] = '\0';
            xauth_failed = false;
        }
    }
}

// Drain OUR Display's queue; call once per frame. Non-blocking.
static void pump_x11_input(void) {
    if (!xdisplay) return;
    while (XPending(xdisplay)) {
        XEvent ev;
        XNextEvent(xdisplay, &ev);
        if (ev.type == KeyPress) handle_xkey(&ev.xkey);
        else if (ev.type == MappingNotify) XRefreshKeyboardMapping(&ev.xmapping);
    }
}

static int pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *responses = calloc(num_msg, sizeof(struct pam_response));
    if (!responses) return PAM_BUF_ERR;

    const char *password = (const char *)appdata_ptr;

    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            responses[i].resp = strdup(password ? password : "");
            responses[i].resp_retcode = 0;
        } else {
            responses[i].resp = NULL;
            responses[i].resp_retcode = 0;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

// --- Background snow / lava / water / obsidian ---
// Done: snow pile + tint + speed; lava melt -> water droplets; obsidian sink.
// Future docket (not yet implemented):
//  * snow plow entity  -> pile_push() ahead of it + debris particles
//  * meteors           -> pile_blast() crater + spark/debris burst
//  * mouse dig/push    -> pump ButtonPress/Motion from our X grab, pile_remove/push
//  * wind gusts, pile AO shading, settling color
#define SNOW_COUNT 200
#define PILE_MAX_FRACTION 0.30f // pile never buries the lock UI
#define PILE_MAX_SLOPE 1.2f     // max height diff between adjacent columns (px)
#define PILE_RELAX_ITERS 3

#define LAVA_MAX 8
#define LAVA_RADIUS 10.0f          // ~20px wide
#define LAVA_MELT_COLS 10          // melts +/- this many columns
#define LAVA_SPAWN_DENOM 500       // 1 in 500 flake respawns (was 5000; "meteor" test rate)

#define WATER_MAX 4000
#define WATER_R 2.0f
#define WATER_CELL 16              // spatial hash cell size (px)

#define OBSIDIAN_MAX 32

static float snow_speed_mult = 1.0f; // --snow-speed=N
static int water_max = WATER_MAX;    // --water-max=N
// TEMP (personal testing): keep water awake so flow is always visible.
// Flip to false (or strip) to restore Minecraft-style sleep.
static bool water_disable_sleep = true;

typedef enum { SNOW_TINT_MIX, SNOW_TINT_WHITE, SNOW_TINT_ICE } SnowTintMode;
static SnowTintMode snow_tint_mode = SNOW_TINT_MIX; // --snow-tint=

static struct {
    float x, y;
    float speed;
    float size;
    float drift;
    float phase;
    Color tint;
} snow[SNOW_COUNT];

// Gradual ramp-in: 1 flake at first, then one per interval until SNOW_COUNT.
// Interval = avg fall time / limit (spawns spread over ~one fall duration).
static int snow_active = 0;
static float snow_spawn_timer = 0.0f;
static float snow_spawn_interval = 0.0f;

static Color snow_pick_tint(void); // defined below

static void snow_place_at_top(int i) {
    int sw = GetScreenWidth();
    snow[i].speed = 30.0f + (float)GetRandomValue(0, 90);
    snow[i].size = 1.0f + (float)GetRandomValue(0, 3);
    snow[i].drift = 10.0f + (float)GetRandomValue(0, 30);
    snow[i].phase = (float)GetRandomValue(0, 628) / 100.0f;
    snow[i].tint = snow_pick_tint();
    snow[i].x = (float)GetRandomValue(0, sw);
    snow[i].y = -snow[i].size;
}

// Lava: falls, melts snow under it, becomes obsidian at screen bottom.
static struct {
    bool alive;
    float x, y;
    float speed;
} lava[LAVA_MAX];

// Obsidian: inert, sinks into the pile, unique shell color, never merges.
static struct {
    bool alive;
    float x, y;
    float sink_v;
    Color shell;
} obsidian[OBSIDIAN_MAX];

// Water: individual droplets. active=false -> no physics (Minecraft sleep).
static struct {
    bool used;
    bool active;
    float x, y;
    float vx, vy;
} water[WATER_MAX];

// Spatial hash over active water only: cell -> droplet index chain.
#define WATER_GRID_W 256
#define WATER_GRID_H 128
static int water_cell_head[WATER_GRID_W * WATER_GRID_H];
static int water_cell_next[WATER_MAX];
static int water_active_n = 0;
static int water_active_list[WATER_MAX];

static float pile[1920]; // per-column snow depth (screen width capped)
static int pile_w = 0;

static float pile_max(void) {
    return (float)GetScreenHeight() * PILE_MAX_FRACTION;
}

static float ground_at(float x) {
    int i = (int)x;
    if (i < 0) i = 0;
    if (i >= pile_w) i = pile_w - 1;
    return (float)GetScreenHeight() - pile[i];
}

static Color snow_pick_tint(void) {
    switch (snow_tint_mode) {
        case SNOW_TINT_WHITE: return (Color){ 255, 255, 255, 255 };
        case SNOW_TINT_ICE:   return (Color){ 200, 230, 255, 255 };
        default: // mix
            switch (GetRandomValue(0, 2)) {
                case 0:  return (Color){ 255, 255, 255, 255 };
                case 1:  return (Color){ 205, 230, 255, 255 };
                default: return (Color){ 230, 220, 255, 255 };
            }
    }
}

// Avalanche: snow slides into neighboring valleys when slope exceeds repose.
static void pile_relax(void) {
    float max = pile_max();
    for (int it = 0; it < PILE_RELAX_ITERS; it++) {
        bool moved = false;
        for (int x = 0; x < pile_w - 1; x++) {
            float d = pile[x] - pile[x + 1];
            if (d > PILE_MAX_SLOPE) {
                float t = (d - PILE_MAX_SLOPE) * 0.5f;
                if (pile[x] - t < 0.0f) t = pile[x];
                if (pile[x + 1] + t > max) t = max - pile[x + 1];
                if (t <= 0.0f) continue;
                pile[x] -= t;
                pile[x + 1] += t;
                moved = true;
            } else if (d < -PILE_MAX_SLOPE) {
                float t = (-d - PILE_MAX_SLOPE) * 0.5f;
                if (pile[x + 1] - t < 0.0f) t = pile[x + 1];
                if (pile[x] + t > max) t = max - pile[x];
                if (t <= 0.0f) continue;
                pile[x + 1] -= t;
                pile[x] += t;
                moved = true;
            }
        }
        if (!moved) break;
    }
}

// Heightmap ops — shared by flakes now; plows/meteors/mouse later.
#define PILE_HOOK __attribute__((unused)) // ready for docket features

static void pile_add(int x, float amount) {
    if (x < 0 || x >= pile_w || amount <= 0.0f) return;
    float room = pile_max() - pile[x];
    if (amount > room) amount = room;
    if (amount <= 0.0f) return;
    pile[x] += amount;
    pile_relax();
}

PILE_HOOK static void pile_remove(int x, float amount) {
    if (x < 0 || x >= pile_w || amount <= 0.0f) return;
    pile[x] -= amount;
    if (pile[x] < 0.0f) pile[x] = 0.0f;
    pile_relax();
}

// Displace snow at x by dir (-1 left / +1 right): digs from x, dumps near x+dir*width.
PILE_HOOK static void pile_push(int x, int dir, float amount, int width) {
    if (x < 0 || x >= pile_w || amount <= 0.0f) return;
    if (dir == 0) return;
    if (amount > pile[x]) amount = pile[x];
    if (amount <= 0.0f) return;
    pile[x] -= amount;
    int dest = x + dir * (width > 0 ? width : 1);
    if (dest < 0) dest = 0;
    if (dest >= pile_w) dest = pile_w - 1;
    float room = pile_max() - pile[dest];
    if (amount > room) {
        // Overflow stays at source so mass is conserved.
        pile[x] += amount - room;
        amount = room;
    }
    pile[dest] += amount;
    pile_relax();
}

// Carve a crater: remove from center, throw some material to the rim.
PILE_HOOK static void pile_blast(int cx, int radius, float force) {
    if (radius < 1) radius = 1;
    int lo = cx - radius, hi = cx + radius;
    if (lo < 0) lo = 0;
    if (hi >= pile_w) hi = pile_w - 1;
    if (cx < 0 || cx >= pile_w) return;
    for (int x = lo; x <= hi; x++) {
        float t = 1.0f - (float)abs(x - cx) / (float)radius;
        if (t <= 0.0f) continue;
        float cut = force * t;
        if (cut > pile[x]) cut = pile[x];
        pile[x] -= cut;
        // Rim deposit just outside the crater.
        int rim = (x < cx) ? lo - (cx - x) : hi + (x - cx);
        if (rim >= 0 && rim < pile_w && pile[rim] < pile_max())
            pile[rim] += cut * 0.5f;
    }
    pile_relax();
}

// --- Water droplets (individual, with sleep/activation) ---

static int water_cell_of(float x, float y) {
    int sw = GetScreenWidth(), sh = GetScreenHeight();
    int cx = (int)(x / WATER_CELL);
    int cy = (int)(y / WATER_CELL);
    if (cx < 0) cx = 0;
    if (cy < 0) cy = 0;
    if (cx >= WATER_GRID_W) cx = WATER_GRID_W - 1;
    if (cy >= WATER_GRID_H) cy = WATER_GRID_H - 1;
    (void)sw; (void)sh;
    return cy * WATER_GRID_W + cx;
}

static void water_wake(int i) {
    if (i < 0 || i >= water_max || !water[i].used) return;
    if (water[i].active) return;
    water[i].active = true;
    water_active_list[water_active_n++] = i;
}

static void water_sleep(int i) {
    if (i < 0 || i >= water_max || !water[i].used) return;
    if (!water[i].active) return;
    if (water_disable_sleep) return; // TEMP testing: never settle-sleep
    water[i].active = false;
    // swap-remove from active list
    for (int k = 0; k < water_active_n; k++) {
        if (water_active_list[k] == i) {
            water_active_list[k] = water_active_list[--water_active_n];
            return;
        }
    }
}

// Forced deactivate (retire) — bypasses water_disable_sleep.
static void water_force_sleep(int i) {
    if (i < 0 || i >= water_max || !water[i].used) return;
    if (!water[i].active) return;
    water[i].active = false;
    for (int k = 0; k < water_active_n; k++) {
        if (water_active_list[k] == i) {
            water_active_list[k] = water_active_list[--water_active_n];
            return;
        }
    }
}

static int water_spawn(float x, float y) {
    for (int i = 0; i < water_max; i++) {
        if (water[i].used) continue;
        water[i].used = true;
        water[i].x = x;
        water[i].y = y;
        water[i].vx = 0.0f;
        water[i].vy = 0.0f;
        water[i].active = false;
        water_wake(i);
        return i;
    }
    // Pool full: recycle an inactive droplet (keeps count bounded).
    for (int i = 0; i < water_max; i++) {
        if (water[i].used && !water[i].active) {
            water[i].x = x;
            water[i].y = y;
            water[i].vx = 0.0f;
            water[i].vy = 0.0f;
            water_wake(i);
            return i;
        }
    }
    return -1;
}

static void water_spawn_from_volume(float x, float y, float volume) {
    // ~area of a WATER_R droplet per spawn; scale so melts aren't insane.
    float per = 3.14f * WATER_R * WATER_R * 0.35f;
    int n = (int)(volume / per);
    if (n < 1 && volume > 0.5f) n = 1;
    if (n > 24) n = 24;
    for (int i = 0; i < n; i++) {
        float jx = x + (float)GetRandomValue(-4, 4);
        float jy = y + (float)GetRandomValue(-2, 2);
        water_spawn(jx, jy);
    }
}

static void water_build_grid(void) {
    for (int c = 0; c < WATER_GRID_W * WATER_GRID_H; c++)
        water_cell_head[c] = -1;
    for (int k = 0; k < water_active_n; k++) {
        int i = water_active_list[k];
        int c = water_cell_of(water[i].x, water[i].y);
        water_cell_next[i] = water_cell_head[c];
        water_cell_head[c] = i;
    }
}

// Wake sleepers near (x,y) — call when snow melts or new water arrives.
static void water_wake_near(float x, float y, float radius) {
    // Events are rare (melt/spawn); linear scan over used slots is fine.
    float r2 = radius * radius;
    for (int i = 0; i < water_max; i++) {
        if (!water[i].used || water[i].active) continue;
        float dx = water[i].x - x, dy = water[i].y - y;
        if (dx * dx + dy * dy <= r2)
            water_wake(i);
    }
}

static void water_update(float dt) {
    // Grid built once per frame from ACTIVE droplets only.
    water_build_grid();

    float g = 900.0f * snow_speed_mult;
    int sh = GetScreenHeight();
    int sw = GetScreenWidth();

    // Snapshot active indices: sleep/wake during the pass mutates the live list.
    static int snap[WATER_MAX];
    int n = water_active_n;
    if (n > WATER_MAX) n = WATER_MAX;
    memcpy(snap, water_active_list, (size_t)n * sizeof(int));

    for (int k = 0; k < n; k++) {
        int i = snap[k];
        if (i < 0 || i >= water_max || !water[i].used || !water[i].active) continue;

        water[i].vy += g * dt;
        if (water[i].vy > 600.0f) water[i].vy = 600.0f;
        water[i].x += water[i].vx * dt;
        water[i].y += water[i].vy * dt;
        water[i].vx *= (1.0f - 2.0f * dt); // light drag

        if (water[i].x < 0) { water[i].x = 0; water[i].vx = 0; }
        if (water[i].x > sw - 1) { water[i].x = (float)sw - 1; water[i].vx = 0; }

        // Sink through the pile: floor is the screen bottom, not snow surface.
        float floor_y = (float)sh - WATER_R;
        // Stack on other active water (same cell).
        int cell = water_cell_of(water[i].x, water[i].y + WATER_R * 2);
        for (int j = water_cell_head[cell]; j != -1; j = water_cell_next[j]) {
            if (j == i) continue;
            float dx = water[j].x - water[i].x;
            float dy = water[j].y - water[i].y;
            if (dx * dx + dy * dy < (WATER_R * 2.0f) * (WATER_R * 2.0f)) {
                float top = water[j].y - WATER_R * 2.0f;
                if (top < floor_y) floor_y = top;
            }
        }

        // Push water out of obsidian — never share cartesian space with it.
        for (int o = 0; o < OBSIDIAN_MAX; o++) {
            if (!obsidian[o].alive) continue;
            float dx = water[i].x - obsidian[o].x;
            float dy = water[i].y - obsidian[o].y;
            float min_d = LAVA_RADIUS * 0.85f + WATER_R + 1.0f;
            float d2 = dx * dx + dy * dy;
            if (d2 < min_d * min_d && d2 > 0.0001f) {
                float d = sqrtf(d2);
                float push = (min_d - d) + 20.0f * dt;
                water[i].x += (dx / d) * push;
                water[i].y += (dy / d) * push;
                water[i].vx += (dx / d) * 60.0f;
                water[i].vy += (dy / d) * 60.0f - 30.0f; // slight pop up/out
                if (water[i].x < 0) water[i].x = 0;
                if (water[i].x > sw - 1) water[i].x = (float)sw - 1;
            }
        }

        if (water[i].y > floor_y) {
            water[i].y = floor_y;
            water[i].vy = 0.0f;

            // On screen floor: light lateral spread if neighbors crowd in.
            float here = ground_at(water[i].x); // unused for sink; keep flat floor
            (void)here;
            // Settle-sleep only when allowed (disabled during personal testing).
            water_sleep(i);
        }
        // Off bottom (edge of screen): retire droplet.
        if (water[i].y > (float)sh + 8.0f) {
            water_force_sleep(i);
            water[i].used = false;
        }
    }
}

// --- Lava ---

static void lava_spawn(float x) {
    for (int i = 0; i < LAVA_MAX; i++) {
        if (lava[i].alive) continue;
        lava[i].alive = true;
        lava[i].x = x;
        lava[i].y = -LAVA_RADIUS;
        lava[i].speed = 220.0f + (float)GetRandomValue(0, 80);
        return;
    }
}

static void obsidian_spawn(float x, float y) {
    static const Color shells[] = {
        {180, 80, 255, 255}, {80, 200, 255, 255}, {255, 120, 80, 255},
        {80, 255, 160, 255}, {255, 80, 160, 255}, {255, 220, 80, 255},
    };
    for (int i = 0; i < OBSIDIAN_MAX; i++) {
        if (obsidian[i].alive) continue;
        obsidian[i].alive = true;
        obsidian[i].x = x;
        obsidian[i].y = y;
        obsidian[i].sink_v = 12.0f + (float)GetRandomValue(0, 20);
        obsidian[i].shell = shells[GetRandomValue(0, 5)];
        return;
    }
    // Pool full: steal the shallowest (least sunk) one.
    int best = -1;
    float best_y = 1e9f;
    for (int i = 0; i < OBSIDIAN_MAX; i++) {
        if (obsidian[i].alive && obsidian[i].y < best_y) {
            best_y = obsidian[i].y;
            best = i;
        }
    }
    if (best >= 0) {
        obsidian[best].alive = true;
        obsidian[best].x = x;
        obsidian[best].y = y;
        obsidian[best].sink_v = 12.0f + (float)GetRandomValue(0, 20);
        obsidian[best].shell = shells[GetRandomValue(0, 5)];
    }
}

static void lava_update(float dt) {
    float sh = (float)GetScreenHeight();
    for (int i = 0; i < LAVA_MAX; i++) {
        if (!lava[i].alive) continue;
        lava[i].y += lava[i].speed * snow_speed_mult * dt;

        // Melt snow in a column band under the droplet; runoff becomes water.
        int cx = (int)lava[i].x;
        float melted = 0.0f;
        int lo = cx - LAVA_MELT_COLS, hi = cx + LAVA_MELT_COLS;
        if (lo < 0) lo = 0;
        if (hi >= pile_w) hi = pile_w - 1;
        for (int x = lo; x <= hi; x++) {
            float t = 1.0f - (float)abs(x - cx) / (float)(LAVA_MELT_COLS + 1);
            if (t <= 0.0f) continue;
            // Only melt near the droplet's vertical band (its way down).
            float col_top = ground_at((float)x);
            if (lava[i].y + LAVA_RADIUS < col_top) continue;
            float cut = (40.0f + 80.0f * t) * dt * snow_speed_mult;
            if (cut > pile[x]) cut = pile[x];
            if (cut <= 0.0f) continue;
            pile[x] -= cut;
            melted += cut;
        }
        if (melted > 0.0f) {
            pile_relax();
            water_spawn_from_volume(lava[i].x, lava[i].y + LAVA_RADIUS, melted);
            water_wake_near(lava[i].x, lava[i].y + LAVA_RADIUS, 24.0f);
        }

        // Touch bottom of screen -> obsidian, then sinks into whatever is below.
        if (lava[i].y >= sh - LAVA_RADIUS * 0.5f) {
            obsidian_spawn(lava[i].x, sh - LAVA_RADIUS);
            lava[i].alive = false;
        }
    }
}

// Obsidian sinks below the surface over time (dense rock in soft snow).
static void obsidian_update(float dt) {
    float sh = (float)GetScreenHeight();
    for (int i = 0; i < OBSIDIAN_MAX; i++) {
        if (!obsidian[i].alive) continue;
        // Sink toward ground line + a bit under the pile surface.
        float target = ground_at(obsidian[i].x) + LAVA_RADIUS * 0.65f;
        if (target > sh - 2.0f) target = sh - 2.0f;
        if (obsidian[i].y < target) {
            obsidian[i].y += obsidian[i].sink_v * dt;
            if (obsidian[i].y > target) obsidian[i].y = target;
        }
    }
}

static void snow_init(void) {
    int sw = GetScreenWidth();
    if (sw > 1920) sw = 1920;
    pile_w = sw;
    memset(pile, 0, sizeof(pile));

    // Avg fall: speeds are 30..120 => mid 75 px/s; time = height / speed.
    float avg_speed = 75.0f;
    float avg_fall_time = (float)GetScreenHeight() / avg_speed;
    // Tiny gap between spawns; total ramp ≈ one fall duration.
    snow_spawn_interval = avg_fall_time / (float)SNOW_COUNT;
    snow_spawn_timer = 0.0f;

    // Only the first flake exists on frame 1; rest activate over time.
    snow_active = 1;
    snow_place_at_top(0);
    for (int i = 1; i < SNOW_COUNT; i++) {
        snow[i].x = 0;
        snow[i].y = -100000.0f; // dormant far offscreen
        snow[i].speed = 0;
        snow[i].size = 1;
        snow[i].drift = 0;
        snow[i].phase = 0;
        snow[i].tint = snow_pick_tint();
    }

    for (int i = 0; i < LAVA_MAX; i++) lava[i].alive = false;
    for (int i = 0; i < OBSIDIAN_MAX; i++) obsidian[i].alive = false;
    memset(water, 0, sizeof(water));
    water_active_n = 0;
    for (int c = 0; c < WATER_GRID_W * WATER_GRID_H; c++)
        water_cell_head[c] = -1;
}

static void snow_update(float dt) {
    int sw = GetScreenWidth();
    int sh = GetScreenHeight();

    // Ramp-in: activate one more flake per interval until the limit.
    snow_spawn_timer += dt * snow_speed_mult;
    if (snow_active < SNOW_COUNT && snow_spawn_timer >= snow_spawn_interval) {
        snow_spawn_timer -= snow_spawn_interval;
        if (snow_spawn_timer > snow_spawn_interval) snow_spawn_timer = 0;
        snow_place_at_top(snow_active);
        snow_active++;
    }

    // Rebuild water grid once so snow buoyancy can probe droplets cheaply.
    water_build_grid();

    for (int i = 0; i < snow_active; i++) {
        snow[i].phase += dt * snow_speed_mult;

        // Buoyancy: if this flake is in/near water, float UP through it
        // (and through piled snow above the water) instead of falling.
        bool in_water = false;
        {
            int cell = water_cell_of(snow[i].x, snow[i].y);
            // also probe cell slightly below (flakes move fast)
            int cell2 = water_cell_of(snow[i].x, snow[i].y + WATER_CELL);
            for (int pass = 0; pass < 2; pass++) {
                int c = pass ? cell2 : cell;
                for (int j = water_cell_head[c]; j != -1; j = water_cell_next[j]) {
                    float dx = water[j].x - snow[i].x;
                    float dy = water[j].y - snow[i].y;
                    float rr = WATER_R + snow[i].size + 1.0f;
                    if (dx * dx + dy * dy <= rr * rr) { in_water = true; break; }
                }
                if (in_water) break;
            }
        }

        if (in_water) {
            // Float up hard — pierces pile layers on the way out.
            snow[i].y -= (120.0f + snow[i].speed * 0.5f) * snow_speed_mult * dt;
            snow[i].x += snow[i].drift * 0.3f * sinf(snow[i].phase) * dt;
        } else {
            snow[i].y += snow[i].speed * snow_speed_mult * dt;
            snow[i].x += snow[i].drift * sinf(snow[i].phase) * dt;
        }

        if (snow[i].x < 0) snow[i].x += sw;
        if (snow[i].x > sw) snow[i].x -= sw;

        // Floated clear of screen top: recycle.
        if (snow[i].y < -snow[i].size) {
            snow[i].y = -snow[i].size;
            snow[i].x = (float)GetRandomValue(0, sw);
            snow[i].tint = snow_pick_tint();
            continue;
        }

        // Landed: join the pile (only when NOT floating in water).
        if (!in_water && snow[i].y >= ground_at(snow[i].x)) {
            pile_add((int)snow[i].x, snow[i].size);
            snow[i].y = -(float)GetRandomValue(1, sh);
            snow[i].x = (float)GetRandomValue(0, sw);
            snow[i].tint = snow_pick_tint();
            // Occasional lava "meteor" instead of a plain respawn.
            if (GetRandomValue(1, LAVA_SPAWN_DENOM) == 1)
                lava_spawn(snow[i].x);
        }
    }

    lava_update(dt);
    water_update(dt);
    obsidian_update(dt);
}

static void snow_draw(void) {
    int sh = GetScreenHeight();

    // Pile
    for (int x = 0; x < pile_w; x++) {
        if (pile[x] <= 0.0f) continue;
        int h = (int)pile[x];
        DrawRectangle(x, sh - h, 1, h,
                      (Color){ 240, 245, 255, 230 });
    }

    // Obsidian (embedded / sinking) — under water & falling stuff
    for (int i = 0; i < OBSIDIAN_MAX; i++) {
        if (!obsidian[i].alive) continue;
        DrawCircleV((Vector2){ obsidian[i].x, obsidian[i].y }, LAVA_RADIUS * 0.85f,
                    (Color){ 48, 16, 64, 255 }); // dark purple core
        DrawCircleLines((int)obsidian[i].x, (int)obsidian[i].y,
                        (int)(LAVA_RADIUS * 0.85f), obsidian[i].shell);
        DrawCircleLines((int)obsidian[i].x, (int)obsidian[i].y,
                        (int)(LAVA_RADIUS * 0.85f) - 1, obsidian[i].shell);
    }

    // Water droplets — only draw used ones (active and settled)
    for (int i = 0; i < water_max; i++) {
        if (!water[i].used) continue;
        DrawCircleV((Vector2){ water[i].x, water[i].y }, WATER_R,
                    (Color){ 40, 110, 255, 200 });
    }

    // Falling snow (only ramped-in flakes)
    for (int i = 0; i < snow_active; i++) {
        Color c = snow[i].tint;
        c.a = (unsigned char)(120 + (int)snow[i].size * 30);
        DrawCircleV((Vector2){ snow[i].x, snow[i].y }, snow[i].size, c);
    }

    // Lava on top (hot glow: core + faint halo)
    for (int i = 0; i < LAVA_MAX; i++) {
        if (!lava[i].alive) continue;
        DrawCircleV((Vector2){ lava[i].x, lava[i].y }, LAVA_RADIUS + 3.0f,
                    (Color){ 255, 80, 0, 50 });
        DrawCircleV((Vector2){ lava[i].x, lava[i].y }, LAVA_RADIUS,
                    (Color){ 255, 120, 20, 255 });
        DrawCircleV((Vector2){ lava[i].x, lava[i].y }, LAVA_RADIUS * 0.45f,
                    (Color){ 255, 220, 80, 255 });
    }
}

static bool authenticate(const char *password) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) return false;

    const char *username = pw->pw_name;

    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { pam_conv, (void *)password };
    int ret = pam_start("login", username, &conv, &pamh);
    if (ret != PAM_SUCCESS) return false;

    ret = pam_authenticate(pamh, PAM_SILENT);
    int ret2 = pam_end(pamh, ret);

    return (ret == PAM_SUCCESS) && (ret2 == PAM_SUCCESS);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--snow-speed=", 13) == 0) {
            float v = strtof(argv[i] + 13, NULL);
            if (v > 0.0f) snow_speed_mult = v;
        } else if (strncmp(argv[i], "--snow-tint=", 12) == 0) {
            const char *t = argv[i] + 12;
            if (strcmp(t, "white") == 0) snow_tint_mode = SNOW_TINT_WHITE;
            else if (strcmp(t, "ice") == 0) snow_tint_mode = SNOW_TINT_ICE;
            else snow_tint_mode = SNOW_TINT_MIX;
        } else if (strncmp(argv[i], "--water-max=", 12) == 0) {
            int v = atoi(argv[i] + 12);
            if (v >= 64 && v <= WATER_MAX) water_max = v;
        }
    }

    const int screen_width = 800;
    const int screen_height = 600;

    SetConfigFlags(FLAG_FULLSCREEN_MODE | FLAG_WINDOW_UNDECORATED | FLAG_WINDOW_TOPMOST);
    InitWindow(screen_width, screen_height, "memelock");

    int monitor = GetCurrentMonitor();
    SetWindowSize(GetMonitorWidth(monitor), GetMonitorHeight(monitor));

    // Must run after InitWindow (need the X window to exist).
    // Grabs all keyboard input so awesomewm global keybinds
    // (incl. kill client) never fire.
    lock_setup_x11();
    lock_grab_startup(); // bounded (~3s max), before first frame only

    SetTargetFPS(60);
    SetExitKey(KEY_NULL);
    SetWindowState(FLAG_WINDOW_ALWAYS_RUN);

    HideCursor();
    snow_init();

    double fail_time = 0.0;
    bool unlocked = false;
    double last_reassert = 0.0;

    while (!unlocked) {
        // Swallow graceful-close requests (WM_DELETE_WINDOW, i.e. awesome's
        // `c:kill()` graceful path). Only a correct password sets unlocked.
        // NOTE: deliberately NOT cleared/exited on; the flag staying set is
        // harmless, the window lives until CloseWindow().
        if (WindowShouldClose()) {
            // keep locking; do NOT break/exit
        }

        // Re-assert the grab periodically WITHOUT blocking: a single attempt.
        // (The old code ran the whole sleep-retry loop here, freezing the
        // frame for up to a second every 0.5s whenever the grab failed.)
        // Focus steal is only needed to close menus that block the grab;
        // input itself is focus-independent (owner_events=False).
        double now = GetTime();
        if (now - last_reassert > 0.5) {
            last_reassert = now;
            if (!lock_grab_once()) lock_focus_self();
        }

        // Password input comes from OUR X connection (see pump_x11_input),
        // not raylib: with owner_events=False raylib receives no keys.
        pump_x11_input();

        if (xpass_submit) {
            xpass_submit = false;
            if (authenticate(xpassword)) {
                memset(xpassword, 0, sizeof(xpassword));
                xpass_len = 0;
                unlocked = true;
                break;
            } else {
                xauth_failed = true;
                fail_time = GetTime();
                memset(xpassword, 0, sizeof(xpassword));
                xpass_len = 0;
            }
        }

        if (xauth_failed && (GetTime() - fail_time > 1.5)) {
            xauth_failed = false;
        }

        snow_update(GetFrameTime());

        BeginDrawing();
        ClearBackground(BLACK);
        snow_draw();

        int sw = GetScreenWidth();
        int sh = GetScreenHeight();

        const char *prompt = "memelock";
        int prompt_size = 80;
        int prompt_width = MeasureText(prompt, prompt_size);
        DrawText(prompt, (sw - prompt_width) / 2, sh / 2 - 140, prompt_size, RAYWHITE);

        char display[128];
        for (int i = 0; i < xpass_len; i++) {
            display[i] = '*';
        }
        display[xpass_len] = '\0';

        int text_size = 64;
        int text_width = MeasureText(display, text_size);
        DrawText(display, (sw - text_width) / 2, sh / 2, text_size, WHITE);

        if (xauth_failed) {
            const char *err = "wrong password";
            int err_size = 40;
            int err_width = MeasureText(err, err_size);
            DrawText(err, (sw - err_width) / 2, sh / 2 + 110, err_size, RED);
        }

        const char *hint = "type password + enter";
        int hint_size = 16;
        int hint_width = MeasureText(hint, hint_size);
        DrawText(hint, (sw - hint_width) / 2, sh - 60, hint_size, GRAY);

        EndDrawing();
    }

    lock_ungrab();
    CloseWindow();
    return 0;
}
