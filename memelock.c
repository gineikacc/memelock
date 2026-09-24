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

    // No password chars while Ctrl/Alt/Super are held (Shift is fine — needed
    // for uppercase/symbols). Ctrl already returned above.
    if (ev->state & (ControlMask | Mod1Mask | Mod4Mask | Mod5Mask))
        return;

    // Printable input (XLookupString already applied layout for Latin).
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

// --- Background snow / lava / obsidian ---
// Done: snow pile + per-flake tint + speed; lava -> obsidian sink.
// Removed: water particles, snow floating, lava melting (per user).
// Future docket (not yet implemented):
//  * snow plow entity  -> pile_push() ahead of it + debris particles
//  * meteors           -> pile_blast() crater + spark/debris burst
//  * mouse dig/push    -> pump ButtonPress/Motion from our X grab, pile_remove/push
//  * wind gusts, pile AO shading, settling color
#define SNOW_COUNT 200
#define PILE_MAX_SLOPE 1.2f     // max height diff between adjacent columns (px)
#define PILE_RELAX_ITERS 3

#define LAVA_MAX 8
#define LAVA_RADIUS 10.0f          // ~20px wide
#define LAVA_SPAWN_DENOM 500       // 1 in 500 flake respawns

#define OBSIDIAN_MAX 32

static float snow_speed_mult = 1.0f; // --snow-speed=N

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

// Lava: falls to screen bottom, becomes obsidian (no melting).
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

static float pile[1920];       // per-column snow depth
// Float RGB avoids integer-truncation darkening over repeated blends.
static float pile_tint_r[1920];
static float pile_tint_g[1920];
static float pile_tint_b[1920];
static int pile_w = 0;

static float pile_max(void) {
    return (float)GetScreenHeight(); // full screen height
}

static float ground_at(float x) {
    int i = (int)x;
    if (i < 0) i = 0;
    if (i >= pile_w) i = pile_w - 1;
    return (float)GetScreenHeight() - pile[i];
}

// White-dominated per-flake tint: pure white with a small random cast.
static Color snow_pick_tint(void) {
    int j = 25;
    switch (snow_tint_mode) {
        case SNOW_TINT_WHITE:
            j = 0;
            break;
        case SNOW_TINT_ICE:
            // Cool bias, still mostly white.
            return (Color){
                (unsigned char)(255 - GetRandomValue(0, 10)),
                (unsigned char)(255 - GetRandomValue(0, 5)),
                255,
                255
            };
        default:
            break;
    }
    int r = 255 - GetRandomValue(0, j);
    int g = 255 - GetRandomValue(0, j);
    int b = 255 - GetRandomValue(0, j);
    // Occasional soft blue/lavender cast, still near white.
    if (snow_tint_mode == SNOW_TINT_MIX && GetRandomValue(0, 7) == 0) {
        b = 255;
        r = 255 - GetRandomValue(10, 35);
        g = 255 - GetRandomValue(5, 25);
    }
    return (Color){ (unsigned char)r, (unsigned char)g, (unsigned char)b, 255 };
}

// Avalanche: snow slides into neighboring valleys when slope exceeds repose.
// Material that moves also mixes tint so heights don't band as stripes.
static void pile_mix_tint(int from, int to, float amount) {
    if (from < 0 || from >= pile_w || to < 0 || to >= pile_w) return;
    if (amount <= 0.0f) return;
    float dest_old = pile[to];
    float total = dest_old + amount;
    if (total <= 0.0f) return;
    float w_old = dest_old / total;
    float w_new = amount / total;
    if (dest_old <= 0.0f) {
        pile_tint_r[to] = pile_tint_r[from];
        pile_tint_g[to] = pile_tint_g[from];
        pile_tint_b[to] = pile_tint_b[from];
        return;
    }
    pile_tint_r[to] = pile_tint_r[to] * w_old + pile_tint_r[from] * w_new;
    pile_tint_g[to] = pile_tint_g[to] * w_old + pile_tint_g[from] * w_new;
    pile_tint_b[to] = pile_tint_b[to] * w_old + pile_tint_b[from] * w_new;
}

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
                pile_mix_tint(x, x + 1, t);
                pile[x] -= t;
                pile[x + 1] += t;
                moved = true;
            } else if (d < -PILE_MAX_SLOPE) {
                float t = (-d - PILE_MAX_SLOPE) * 0.5f;
                if (pile[x + 1] - t < 0.0f) t = pile[x + 1];
                if (pile[x] + t > max) t = max - pile[x];
                if (t <= 0.0f) continue;
                pile_mix_tint(x + 1, x, t);
                pile[x + 1] -= t;
                pile[x] += t;
                moved = true;
            }
        }
        if (!moved) break;
    }
}

// Light horizontal blur so single-column tint hits don't read as vertical lines.
// All math in float; only rounded once at draw time.
static void pile_smooth_tint(void) {
    static float tr[1920], tg[1920], tb[1920];
    if (pile_w < 3) return;
    for (int x = 0; x < pile_w; x++) {
        int l = x > 0 ? x - 1 : x;
        int r = x < pile_w - 1 ? x + 1 : x;
        if (pile[l] <= 0.0f || pile[x] <= 0.0f || pile[r] <= 0.0f) {
            tr[x] = pile_tint_r[x];
            tg[x] = pile_tint_g[x];
            tb[x] = pile_tint_b[x];
            continue;
        }
        tr[x] = (pile_tint_r[l] + pile_tint_r[x] * 2.0f + pile_tint_r[r]) * 0.25f;
        tg[x] = (pile_tint_g[l] + pile_tint_g[x] * 2.0f + pile_tint_g[r]) * 0.25f;
        tb[x] = (pile_tint_b[l] + pile_tint_b[x] * 2.0f + pile_tint_b[r]) * 0.25f;
    }
    memcpy(pile_tint_r, tr, (size_t)pile_w * sizeof(float));
    memcpy(pile_tint_g, tg, (size_t)pile_w * sizeof(float));
    memcpy(pile_tint_b, tb, (size_t)pile_w * sizeof(float));
}

static unsigned char pile_chan_u8(float v) {
    if (v < 0.0f) v = 0.0f;
    if (v > 255.0f) v = 255.0f;
    return (unsigned char)(v + 0.5f); // round, never truncate toward black
}

static Color pile_color_at(int x) {
    return (Color){
        pile_chan_u8(pile_tint_r[x]),
        pile_chan_u8(pile_tint_g[x]),
        pile_chan_u8(pile_tint_b[x]),
        230
    };
}

// Heightmap ops — shared by flakes now; plows/meteors/mouse later.
#define PILE_HOOK __attribute__((unused)) // ready for docket features

static void pile_add(int x, float amount, Color tint) {
    if (x < 0 || x >= pile_w || amount <= 0.0f) return;
    float room = pile_max() - pile[x];
    if (amount > room) amount = room;
    if (amount <= 0.0f) return;

    // Blend flake tint into the landing column…
    float old = pile[x];
    float total = old + amount;
    float tr = tint.r, tg = tint.g, tb = tint.b;
    if (old <= 0.0f) {
        pile_tint_r[x] = tr;
        pile_tint_g[x] = tg;
        pile_tint_b[x] = tb;
    } else {
        float w_old = old / total;
        float w_new = amount / total;
        pile_tint_r[x] = pile_tint_r[x] * w_old + tr * w_new;
        pile_tint_g[x] = pile_tint_g[x] * w_old + tg * w_new;
        pile_tint_b[x] = pile_tint_b[x] * w_old + tb * w_new;
    }

    // …and lightly into nearby columns so one hit isn't a 1px stripe.
    for (int d = 1; d <= 3; d++) {
        float w = 0.35f / (float)d;
        float inv = 1.0f - w;
        for (int s = -1; s <= 1; s += 2) {
            int n = x + s * d;
            if (n < 0 || n >= pile_w || pile[n] <= 0.0f) continue;
            pile_tint_r[n] = pile_tint_r[n] * inv + tr * w;
            pile_tint_g[n] = pile_tint_g[n] * inv + tg * w;
            pile_tint_b[n] = pile_tint_b[n] * inv + tb * w;
        }
    }

    pile[x] += amount;
    pile_relax();
    pile_smooth_tint();
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
    for (int i = 0; i < pile_w; i++) {
        pile_tint_r[i] = 240.0f;
        pile_tint_g[i] = 245.0f;
        pile_tint_b[i] = 255.0f;
    }

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

    for (int i = 0; i < snow_active; i++) {
        snow[i].phase += dt * snow_speed_mult;
        snow[i].y += snow[i].speed * snow_speed_mult * dt;
        snow[i].x += snow[i].drift * sinf(snow[i].phase) * dt;
        if (snow[i].x < 0) snow[i].x += sw;
        if (snow[i].x > sw) snow[i].x -= sw;

        // Landed: deposit a visible amount of tinted snow, then respawn.
        if (snow[i].y >= ground_at(snow[i].x)) {
            // size 1..4 -> 3..48 height units so big flakes build the pile.
            float deposit = snow[i].size * snow[i].size * 3.0f;
            pile_add((int)snow[i].x, deposit, snow[i].tint);
            snow[i].y = -(float)GetRandomValue(1, sh);
            snow[i].x = (float)GetRandomValue(0, sw);
            snow[i].tint = snow_pick_tint();
            // Occasional lava "meteor" instead of a plain respawn.
            if (GetRandomValue(1, LAVA_SPAWN_DENOM) == 1)
                lava_spawn(snow[i].x);
        }
    }

    lava_update(dt);
    obsidian_update(dt);
}

static void snow_draw(void) {
    int sh = GetScreenHeight();

    // Pile (per-column blended flake tint)
    for (int x = 0; x < pile_w; x++) {
        if (pile[x] <= 0.0f) continue;
        int h = (int)pile[x];
        DrawRectangle(x, sh - h, 1, h, pile_color_at(x));
    }

    // Obsidian (embedded / sinking)
    for (int i = 0; i < OBSIDIAN_MAX; i++) {
        if (!obsidian[i].alive) continue;
        DrawCircleV((Vector2){ obsidian[i].x, obsidian[i].y }, LAVA_RADIUS * 0.85f,
                    (Color){ 48, 16, 64, 255 }); // dark purple core
        DrawCircleLines((int)obsidian[i].x, (int)obsidian[i].y,
                        (int)(LAVA_RADIUS * 0.85f), obsidian[i].shell);
        DrawCircleLines((int)obsidian[i].x, (int)obsidian[i].y,
                        (int)(LAVA_RADIUS * 0.85f) - 1, obsidian[i].shell);
    }

    // Falling snow (only ramped-in flakes)
    for (int i = 0; i < snow_active; i++) {
        Color c = snow[i].tint;
        int a = 200 + (int)snow[i].size * 13;
        if (a > 255) a = 255;
        c.a = (unsigned char)a;
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

// --- Desktop snapshot background ---
// Capture + blur on CPU BEFORE InitWindow (fullscreen would hide the desktop).
// Upload to a GL texture only AFTER InitWindow (needs a context).
static Texture2D bg_tex = {0};
static Image bg_img = {0};
static bool bg_ready = false;
static int bg_blur = 5;     // -b / -b=N
static int bg_darken = -25; // -d / -d=N (fraction of 255)

// Separable Gaussian in float, then darken + blue-noise-ish dither when
// quantizing back to 8-bit. raylib's ImageBlurGaussian is a box-blur
// approximation and ImageColorBrightness truncates — both band gradients.
static void bg_gaussian_blur(Image *img, int radius, float darken) {
    if (!img || !img->data) return;
    int w = img->width, h = img->height;
    if (w < 1 || h < 1) return;
    if (radius < 1) radius = 1;
    if (radius > 64) radius = 64;

    // 1D Gaussian kernel, sigma ≈ radius/2 (keeps a soft but visible blur)
    int diam = radius * 2 + 1;
    float *kern = (float *)malloc((size_t)diam * sizeof(float));
    float *tmp = (float *)malloc((size_t)w * (size_t)h * 4 * sizeof(float));
    float *src = (float *)malloc((size_t)w * (size_t)h * 4 * sizeof(float));
    if (!kern || !tmp || !src) {
        free(kern);
        free(tmp);
        free(src);
        return;
    }

    float sigma = (float)radius * 0.5f;
    float sum = 0.0f;
    float s2 = 2.0f * sigma * sigma;
    for (int i = -radius; i <= radius; i++) {
        float v = expf(-(float)(i * i) / s2);
        kern[i + radius] = v;
        sum += v;
    }
    for (int i = 0; i < diam; i++) kern[i] /= sum;

    unsigned char *px = (unsigned char *)img->data;
    size_t n = (size_t)w * (size_t)h;
    for (size_t i = 0; i < n; i++) {
        src[i * 4 + 0] = (float)px[i * 4 + 0];
        src[i * 4 + 1] = (float)px[i * 4 + 1];
        src[i * 4 + 2] = (float)px[i * 4 + 2];
        src[i * 4 + 3] = 255.0f; // force opaque
    }

    // Horizontal
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            float r = 0, g = 0, b = 0;
            for (int t = -radius; t <= radius; t++) {
                int xx = x + t;
                if (xx < 0) xx = 0;
                if (xx >= w) xx = w - 1;
                float kv = kern[t + radius];
                size_t o = ((size_t)y * (size_t)w + (size_t)xx) * 4;
                r += src[o + 0] * kv;
                g += src[o + 1] * kv;
                b += src[o + 2] * kv;
            }
            size_t o = ((size_t)y * (size_t)w + (size_t)x) * 4;
            tmp[o + 0] = r;
            tmp[o + 1] = g;
            tmp[o + 2] = b;
            tmp[o + 3] = 255.0f;
        }
    }

    // Vertical + darken + dithered quantize
    // hash-based ±0.5 LSB dither breaks up 8-bit banding on smooth gradients
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            float r = 0, g = 0, b = 0;
            for (int t = -radius; t <= radius; t++) {
                int yy = y + t;
                if (yy < 0) yy = 0;
                if (yy >= h) yy = h - 1;
                float kv = kern[t + radius];
                size_t o = ((size_t)yy * (size_t)w + (size_t)x) * 4;
                r += tmp[o + 0] * kv;
                g += tmp[o + 1] * kv;
                b += tmp[o + 2] * kv;
            }
            r *= darken;
            g *= darken;
            b *= darken;

            unsigned hx = (unsigned)(x * 73856093u) ^ (unsigned)(y * 19349663u);
            float dith = ((float)(hx & 1023u) / 1023.0f) - 0.5f;

            r += dith;
            g += dith;
            b += dith;

            if (r < 0) r = 0;
            if (r > 255) r = 255;
            if (g < 0) g = 0;
            if (g > 255) g = 255;
            if (b < 0) b = 0;
            if (b > 255) b = 255;

            size_t o = ((size_t)y * (size_t)w + (size_t)x) * 4;
            px[o + 0] = (unsigned char)(r + 0.5f);
            px[o + 1] = (unsigned char)(g + 0.5f);
            px[o + 2] = (unsigned char)(b + 0.5f);
            px[o + 3] = 255;
        }
    }

    free(kern);
    free(tmp);
    free(src);
}

static unsigned char xmask_to_u8(unsigned long pixel, unsigned long mask) {
    if (mask == 0) return 0;
    int shift = 0;
    while (((mask >> shift) & 1UL) == 0UL) shift++;
    unsigned long v = (pixel & mask) >> shift;
    unsigned long max = mask >> shift;
    if (max == 0) return 0;
    return (unsigned char)((v * 255UL) / max);
}

static Image capture_root_image(void) {
    Image img = {0};
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "[memelock] bg: XOpenDisplay failed\n");
        return img;
    }
    int scr = DefaultScreen(dpy);
    int w = DisplayWidth(dpy, scr);
    int h = DisplayHeight(dpy, scr);
    Window root = RootWindow(dpy, scr);
    XImage *xi = XGetImage(dpy, root, 0, 0, (unsigned)w, (unsigned)h,
                           AllPlanes, ZPixmap);
    if (!xi) {
        fprintf(stderr, "[memelock] bg: XGetImage failed\n");
        XCloseDisplay(dpy);
        return img;
    }

    img.width = w;
    img.height = h;
    img.mipmaps = 1;
    img.format = PIXELFORMAT_UNCOMPRESSED_R8G8B8A8;
    img.data = malloc((size_t)w * (size_t)h * 4);
    if (!img.data) {
        XDestroyImage(xi);
        XCloseDisplay(dpy);
        img.data = NULL;
        img.width = img.height = 0;
        return img;
    }

    unsigned long rm = xi->red_mask;
    unsigned long gm = xi->green_mask;
    unsigned long bm = xi->blue_mask;
    int bpp = xi->bits_per_pixel;
    unsigned char *dst = (unsigned char *)img.data;

    for (int y = 0; y < h; y++) {
        const unsigned char *line =
            (const unsigned char *)xi->data + (long)y * xi->bytes_per_line;
        for (int x = 0; x < w; x++) {
            unsigned long pixel = 0;
            if (bpp == 32) {
                memcpy(&pixel, line + (size_t)x * 4, 4);
            } else if (bpp == 24) {
                const unsigned char *p = line + (size_t)x * 3;
                pixel = (unsigned long)p[0] | ((unsigned long)p[1] << 8) |
                        ((unsigned long)p[2] << 16);
            } else {
                pixel = XGetPixel(xi, x, y);
            }
            size_t o = ((size_t)y * (size_t)w + (size_t)x) * 4;
            dst[o + 0] = xmask_to_u8(pixel, rm);
            dst[o + 1] = xmask_to_u8(pixel, gm);
            dst[o + 2] = xmask_to_u8(pixel, bm);
            dst[o + 3] = 255;
        }
    }

    XDestroyImage(xi);
    XCloseDisplay(dpy);
    return img;
}

// Call BEFORE InitWindow so the lock window is not in the shot.
// Leaves CPU image in bg_img; upload happens later in bg_upload().
static void bg_capture_and_process(void) {
    Image img = capture_root_image();
    if (!img.data) return;

    // Downscale large desktops so blur is cheap, then stretch at draw time.
    if (img.width > 960) {
        int nh = (int)((float)img.height * (960.0f / (float)img.width));
        if (nh < 1) nh = 1;
        ImageResize(&img, 960, nh);
    }

    if (bg_blur < 0) bg_blur = 0;
    if (bg_blur > 64) bg_blur = 64;
    if (bg_darken < -255) bg_darken = -255;
    if (bg_darken > 255) bg_darken = 255;

    // darken: -25 means multiply by (1 - 25/255) ≈ 0.90, matching prior feel
    float darken = 1.0f + ((float)bg_darken / 255.0f);
    if (darken < 0.0f) darken = 0.0f;
    bg_gaussian_blur(&img, bg_blur, darken);
    bg_img = img;

    // Debug: sample a few pixels so we can see if capture came out black.
    unsigned char *px = (unsigned char *)bg_img.data;
    if (px && bg_img.width > 0 && bg_img.height > 0) {
        size_t mid = ((size_t)bg_img.height / 2 * bg_img.width +
                      (size_t)bg_img.width / 2) * 4;
        fprintf(stderr,
                "[memelock] bg: %dx%d mid RGB=(%u,%u,%u)\n",
                bg_img.width, bg_img.height, px[mid], px[mid + 1], px[mid + 2]);
    }
}

// Call AFTER InitWindow — needs the OpenGL context.
static void bg_upload(void) {
    if (!bg_img.data) return;
    bg_tex = LoadTextureFromImage(bg_img);
    UnloadImage(bg_img);
    bg_img = (Image){0};
    if (bg_tex.id > 0) {
        bg_ready = true;
        SetTextureFilter(bg_tex, TEXTURE_FILTER_BILINEAR);
        fprintf(stderr, "[memelock] bg: texture id=%u %dx%d\n",
                bg_tex.id, bg_tex.width, bg_tex.height);
    } else {
        fprintf(stderr, "[memelock] bg: texture upload failed\n");
    }
}

static void bg_draw(int sw, int sh) {
    if (!bg_ready) return;
    DrawTexturePro(bg_tex,
                   (Rectangle){ 0, 0, (float)bg_tex.width, (float)bg_tex.height },
                   (Rectangle){ 0, 0, (float)sw, (float)sh },
                   (Vector2){ 0, 0 }, 0.0f, WHITE);
}

static void bg_unload(void) {
    if (bg_ready) {
        UnloadTexture(bg_tex);
        bg_ready = false;
    }
}

#define MEMELOCK_VERSION "1.0.0"

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n"
           "\n"
           "Options:\n"
           "  -h, --help              show this help and exit\n"
           "  -b, -b=N                background blur radius (default 5)\n"
           "  -d, -d=N                background darken, -255..255 (default -25)\n"
           "  --snow-speed=N          snowfall speed multiplier (default 1.0)\n"
           "  --snow-tint=MODE        flake color: white | ice | mix (default mix)\n",
           prog);
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bg_blur = atoi(argv[++i]);
        } else if (strncmp(argv[i], "-b=", 3) == 0) {
            bg_blur = atoi(argv[i] + 3);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            bg_darken = atoi(argv[++i]);
        } else if (strncmp(argv[i], "-d=", 3) == 0) {
            bg_darken = atoi(argv[i] + 3);
        } else if (strncmp(argv[i], "--snow-speed=", 13) == 0) {
            float v = strtof(argv[i] + 13, NULL);
            if (v > 0.0f) snow_speed_mult = v;
        } else if (strncmp(argv[i], "--snow-tint=", 12) == 0) {
            const char *t = argv[i] + 12;
            if (strcmp(t, "white") == 0) snow_tint_mode = SNOW_TINT_WHITE;
            else if (strcmp(t, "ice") == 0) snow_tint_mode = SNOW_TINT_ICE;
            else snow_tint_mode = SNOW_TINT_MIX;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    const int screen_width = 800;
    const int screen_height = 600;

    // Snapshot desktop before the lock window covers it (CPU only).
    bg_capture_and_process();

    SetConfigFlags(FLAG_FULLSCREEN_MODE | FLAG_WINDOW_UNDECORATED | FLAG_WINDOW_TOPMOST);
    InitWindow(screen_width, screen_height, "mule");

    // GL context exists — upload the pre-captured image as a texture.
    bg_upload();

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
        {
            int sw0 = GetScreenWidth();
            int sh0 = GetScreenHeight();
            bg_draw(sw0, sh0);
        }
        snow_draw();

        int sw = GetScreenWidth();
        int sh = GetScreenHeight();

        const int ui_pad = 18;
        const Color ui_bg = { 10, 12, 18, 190 };

        const char *prompt = "mule";
        int prompt_size = 80;
        int prompt_width = MeasureText(prompt, prompt_size);
        int prompt_x = (sw - prompt_width) / 2;
        int prompt_y = sh / 2 - 140;
        DrawRectangle(prompt_x - ui_pad, prompt_y - ui_pad,
                      prompt_width + ui_pad * 2, prompt_size + ui_pad * 2, ui_bg);
        DrawText(prompt, prompt_x, prompt_y, prompt_size, RAYWHITE);

        char display[128];
        for (int i = 0; i < xpass_len; i++) {
            display[i] = '*';
        }
        display[xpass_len] = '\0';

        int text_size = 64;
        int text_width = MeasureText(display, text_size);
        // Always reserve room for at least one caret-wide box so it doesn't jump.
        int box_text_w = text_width > 0 ? text_width : MeasureText("*", text_size);
        int text_x = (sw - box_text_w) / 2;
        int text_y = sh / 2;
        DrawRectangle(text_x - ui_pad, text_y - ui_pad,
                      box_text_w + ui_pad * 2, text_size + ui_pad * 2, ui_bg);
        DrawText(display, (sw - text_width) / 2, text_y, text_size, WHITE);

        if (xauth_failed) {
            const char *err = "wrong password";
            int err_size = 40;
            int err_width = MeasureText(err, err_size);
            int err_x = (sw - err_width) / 2;
            int err_y = sh / 2 + 110;
            DrawRectangle(err_x - ui_pad, err_y - ui_pad,
                          err_width + ui_pad * 2, err_size + ui_pad * 2, ui_bg);
            DrawText(err, err_x, err_y, err_size, RED);
        }

        const char *hint = "type password + enter";
        int hint_size = 16;
        int hint_width = MeasureText(hint, hint_size);
        int hint_x = (sw - hint_width) / 2;
        int hint_y = sh - 60;
        DrawRectangle(hint_x - 10, hint_y - 8,
                      hint_width + 20, hint_size + 16, ui_bg);
        DrawText(hint, hint_x, hint_y, hint_size, GRAY);

        // Tiny, dull version tag — bottom-right, easy to miss on purpose.
        {
            const char *ver = MEMELOCK_VERSION;
            int ver_size = 10;
            int ver_w = MeasureText(ver, ver_size);
            DrawText(ver, sw - ver_w - 10, sh - 18, ver_size,
                     (Color){ 70, 74, 82, 160 });
        }

        EndDrawing();
    }

    lock_ungrab();
    bg_unload();
    CloseWindow();
    return 0;
}
