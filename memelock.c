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
#include <curl/curl.h>
#include <json-c/json.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#define MEMELOCK_VERSION "1.2.0"

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

// Weather widget visibility (Ctrl+R). Full state lives with the weather section.
static bool weather_enabled = true;
static bool weather_visible = true;

static void weather_toggle(void) {
    if (weather_enabled) weather_visible = !weather_visible;
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
    { XK_R, weather_toggle,    "toggle weather" },
};

static void handle_xkey(XKeyEvent *ev) {
    char buf[32];
    KeySym ks = NoSymbol;
    int n = XLookupString(ev, buf, sizeof(buf), &ks, NULL);

    // Ctrl combos first: match bind table, swallow everything else
    // (so e.g. Ctrl+C / Ctrl+Z can never do anything here).
    // Normalize keysym to lowercase so XK_R / XK_r both match XK_R binds.
    if (ev->state & ControlMask) {
        KeySym k = ks;
        if (k >= XK_A && k <= XK_Z) k += (XK_a - XK_A);
        for (unsigned i = 0; i < sizeof(ctrl_binds) / sizeof(ctrl_binds[0]); i++) {
            KeySym bk = ctrl_binds[i].ks;
            if (bk >= XK_A && bk <= XK_Z) bk += (XK_a - XK_A);
            if (k == bk) {
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

// --- Weather widget (Open-Meteo, no API key) ---
// Compact fixed-cell layout, bottom-left. Ctrl+R toggles visibility.
// Optional live layout file: --layout[=PATH] (off by default).

#define W_HOURS 7  // matches W_DAYS so hour/day columns line up
#define W_DAYS 7
#define W_REFRESH_SEC 900

typedef struct {
    float lat, lon;
    char place[64];

    float cur_temp;
    int cur_code;
    int cur_pop;

    float hour_temp[W_HOURS];
    int hour_code[W_HOURS];
    int hour_pop[W_HOURS];
    int hour_is_day[W_HOURS]; // 1 day, 0 night; default 1 if missing
    char hour_label[W_HOURS][8];

    float day_min[W_DAYS];
    float day_max[W_DAYS];
    int day_code[W_DAYS];
    int day_pop[W_DAYS];
    char day_label[W_DAYS][4];

    bool ready;
    bool fetching;
    double last_ok;
} WeatherState;

// Tunable layout — defaults are compact; live-reloaded from file if enabled.
typedef struct {
    int margin;
    int pad;
    int col_gap;
    int row_gap;
    int block_gap;
    int font_label;
    int font_temp;
    int font_pop;
    int row_h;
    int day_row_h;
    int min_col_w;
    int bg_alpha;
} LayoutCfg;

static LayoutCfg layout = {
    .margin = 16,
    .pad = 6,
    .col_gap = 2,
    .row_gap = 0,      // between label/temp/pop rows (~0)
    .block_gap = 8,    // only between hours block and days block
    .font_label = 24,
    .font_temp = 36,
    .font_pop = 18,
    .row_h = 0,        // legacy: extra px after each hour row (0 = tight)
    .day_row_h = 0,    // legacy: extra px after each day row
    .min_col_w = 40,
    .bg_alpha = 190,
};

static bool layout_enabled = false;
static char layout_path[512] = {0};
static time_t layout_mtime = 0;
static bool layout_seen = false;

static WeatherState weather;
static pthread_mutex_t weather_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t weather_thr;
static bool weather_thr_started = false;
static bool weather_shutdown = false;
static Font weather_font = {0};
static bool weather_font_owned = false;
static void weather_load_font(void);

static float cli_lat = 0, cli_lon = 0;
static bool cli_have_latlon = false;
static char cli_city[128] = {0};

static void layout_apply_kv(const char *key, const char *val) {
    int v = atoi(val);
    if (strcmp(key, "margin") == 0) layout.margin = v;
    else if (strcmp(key, "pad") == 0) layout.pad = v;
    else if (strcmp(key, "col_gap") == 0) layout.col_gap = v;
    else if (strcmp(key, "row_gap") == 0) layout.row_gap = v;
    else if (strcmp(key, "block_gap") == 0) layout.block_gap = v;
    else if (strcmp(key, "font_label") == 0) layout.font_label = v;
    else if (strcmp(key, "font_temp") == 0) layout.font_temp = v;
    else if (strcmp(key, "font_pop") == 0) layout.font_pop = v;
    else if (strcmp(key, "row_h") == 0) layout.row_h = v;
    else if (strcmp(key, "day_row_h") == 0) layout.day_row_h = v;
    else if (strcmp(key, "min_col_w") == 0) layout.min_col_w = v;
    else if (strcmp(key, "bg_alpha") == 0) layout.bg_alpha = v;
    // unknown keys ignored
}

static void layout_defaults(void) {
    layout.margin = 16;
    layout.pad = 6;
    layout.col_gap = 2;
    layout.row_gap = 0;
    layout.block_gap = 8;
    layout.font_label = 24;
    layout.font_temp = 36;
    layout.font_pop = 18;
    layout.row_h = 0;
    layout.day_row_h = 0;
    layout.min_col_w = 40;
    layout.bg_alpha = 190;
}

static void layout_clamp(void) {
    if (layout.margin < 0) layout.margin = 0;
    if (layout.pad < 0) layout.pad = 0;
    if (layout.col_gap < 0) layout.col_gap = 0;
    if (layout.row_gap < 0) layout.row_gap = 0;
    if (layout.block_gap < 0) layout.block_gap = 0;
    if (layout.font_label < 8) layout.font_label = 8;
    if (layout.font_temp < 8) layout.font_temp = 8;
    if (layout.font_pop < 8) layout.font_pop = 8;
    if (layout.row_h < 0) layout.row_h = 0;
    if (layout.day_row_h < 0) layout.day_row_h = 0;
    if (layout.min_col_w < 16) layout.min_col_w = 16;
    if (layout.bg_alpha < 0) layout.bg_alpha = 0;
    if (layout.bg_alpha > 255) layout.bg_alpha = 255;
}

static bool layout_load(void) {
    if (!layout_enabled || !layout_path[0]) return false;
    FILE *f = fopen(layout_path, "r");
    if (!f) return false;

    LayoutCfg prev = layout;
    layout_defaults(); // removed keys fall back to defaults
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = s;
        char *val = eq + 1;
        // trim key
        char *ke = key + strlen(key);
        while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = '\0';
        // trim value
        while (*val == ' ' || *val == '\t') val++;
        char *ve = val + strlen(val);
        while (ve > val && (ve[-1] == '\n' || ve[-1] == '\r' ||
                            ve[-1] == ' ' || ve[-1] == '\t'))
            *--ve = '\0';
        if (!key[0] || !val[0]) continue;
        layout_apply_kv(key, val);
    }
    fclose(f);
    layout_clamp();

    struct stat st;
    if (stat(layout_path, &st) == 0) {
        if (layout_seen && st.st_mtime != layout_mtime)
            fprintf(stderr, "[memelock] layout: reloaded %s\n", layout_path);
        layout_mtime = st.st_mtime;
        layout_seen = true;
    }

    if (memcmp(&prev, &layout, sizeof(prev)) != 0)
        return true;
    return false;
}

// Poll mtime at most a few times/sec; no-op when layout mode is off.
static void layout_poll(void) {
    if (!layout_enabled || !layout_path[0]) return;
    static double last = 0;
    double now = GetTime();
    if (now - last < 0.15) return;
    last = now;
    layout_load();
}

static void weather_cache_path(char *out, size_t n, const char *file) {
    const char *home = getenv("HOME");
    if (!home || !home[0]) home = "/tmp";
    snprintf(out, n, "%s/.cache/memelock", home);
    mkdir(out, 0755);
    snprintf(out, n, "%s/.cache/memelock/%s", home, file);
}

static size_t http_write_cb(char *p, size_t s, size_t n, void *u) {
    size_t m = s * n;
    char **b = (char **)u;
    size_t old = *b ? strlen(*b) : 0;
    char *nb = (char *)realloc(*b, old + m + 1);
    if (!nb) return 0;
    memcpy(nb + old, p, m);
    nb[old + m] = '\0';
    *b = nb;
    return m;
}

static char *http_get(const char *url, int timeout_s) {
    char *body = NULL;
    CURL *c = curl_easy_init();
    if (!c) return NULL;
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, http_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, (long)timeout_s);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, (long)(timeout_s > 3 ? 3 : timeout_s));
    curl_easy_setopt(c, CURLOPT_USERAGENT, "memelock/" MEMELOCK_VERSION);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode r = curl_easy_perform(c);
    curl_easy_cleanup(c);
    if (r != CURLE_OK) {
        free(body);
        return NULL;
    }
    return body;
}

// Temp digit color by WMO code — prognosis is encoded in the number color.
static Color wmo_temp_color(int code) {
    if (code == 0) return (Color){ 245, 215, 110, 255 }; // clear — yellow
    if (code == 1) return (Color){ 240, 220, 140, 255 }; // mainly clear
    if (code == 2) return (Color){ 232, 217, 160, 255 }; // partly cloudy
    if (code == 3) return (Color){ 154, 160, 168, 255 }; // overcast — gray
    if (code == 45 || code == 48) return (Color){ 176, 180, 186, 255 }; // fog
    if (code >= 51 && code <= 57) return (Color){ 111, 168, 220, 255 }; // drizzle
    if (code >= 61 && code <= 67) return (Color){ 111, 168, 220, 255 }; // rain
    if (code >= 71 && code <= 77) return (Color){ 168, 208, 230, 255 }; // snow
    if (code >= 80 && code <= 82) return (Color){ 111, 168, 220, 255 }; // showers
    if (code == 85 || code == 86) return (Color){ 168, 208, 230, 255 }; // snow showers
    if (code >= 95) return (Color){ 180, 142, 173, 255 }; // storm — violet
    return (Color){ 154, 160, 168, 255 }; // cloudy
}

static const char *day_name(const char *iso) {
    int y = 0, m = 0, d = 0;
    if (!iso || sscanf(iso, "%d-%d-%d", &y, &m, &d) != 3) return "???";
    static const char *names[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const int t[] = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    if (m < 3) y -= 1;
    int w = (y + y / 4 - y / 100 + y / 400 + t[m - 1] + d) % 7;
    return names[w];
}

static bool weather_parse_forecast(const char *json_text) {
    if (!json_text || !json_text[0]) return false;
    json_object *root = json_tokener_parse(json_text);
    if (!root) return false;

    json_object *cur = NULL, *hourly = NULL, *daily = NULL;
    if (!json_object_object_get_ex(root, "current", &cur) ||
        !json_object_object_get_ex(root, "hourly", &hourly) ||
        !json_object_object_get_ex(root, "daily", &daily)) {
        json_object_put(root);
        return false;
    }

    WeatherState w;
    memset(&w, 0, sizeof(w));
    pthread_mutex_lock(&weather_mu);
    w.lat = weather.lat;
    w.lon = weather.lon;
    memcpy(w.place, weather.place, sizeof(w.place));
    pthread_mutex_unlock(&weather_mu);

    json_object *o = NULL;
    if (json_object_object_get_ex(cur, "temperature_2m", &o))
        w.cur_temp = (float)json_object_get_double(o);
    if (json_object_object_get_ex(cur, "weather_code", &o))
        w.cur_code = json_object_get_int(o);
    if (json_object_object_get_ex(cur, "precipitation_probability", &o) &&
        json_object_get_type(o) == json_type_int)
        w.cur_pop = json_object_get_int(o);

    json_object *h_t = NULL, *h_c = NULL, *h_p = NULL, *h_time = NULL, *h_day = NULL;
    json_object_object_get_ex(hourly, "temperature_2m", &h_t);
    json_object_object_get_ex(hourly, "weather_code", &h_c);
    json_object_object_get_ex(hourly, "precipitation_probability", &h_p);
    json_object_object_get_ex(hourly, "time", &h_time);
    json_object_object_get_ex(hourly, "is_day", &h_day);
    if (!h_t || !h_time) {
        json_object_put(root);
        return false;
    }

    int n = json_object_array_length(h_t);
    int idx = 0;
    const char *ct = NULL;
    if (json_object_object_get_ex(cur, "time", &o)) ct = json_object_get_string(o);
    if (ct && strlen(ct) >= 13) idx = atoi(ct + 11);
    if (idx < 0) idx = 0;
    if (idx + W_HOURS > n) idx = (n > W_HOURS) ? (n - W_HOURS) : 0;

    for (int i = 0; i < W_HOURS; i++) {
        int j = idx + i;
        if (j >= n) break;
        json_object *tj = json_object_array_get_idx(h_t, j);
        w.hour_temp[i] = tj ? (float)json_object_get_double(tj) : 0;
        w.hour_is_day[i] = 1;
        if (h_day) {
            json_object *dj = json_object_array_get_idx(h_day, j);
            if (dj) w.hour_is_day[i] = json_object_get_int(dj) ? 1 : 0;
        }
        if (h_c) {
            json_object *cj = json_object_array_get_idx(h_c, j);
            w.hour_code[i] = cj ? json_object_get_int(cj) : 0;
        }
        if (h_p) {
            json_object *pj = json_object_array_get_idx(h_p, j);
            if (pj && json_object_get_type(pj) == json_type_int)
                w.hour_pop[i] = json_object_get_int(pj);
        }
        if (i == 0) {
            snprintf(w.hour_label[i], sizeof(w.hour_label[i]), "now");
        } else {
            json_object *timej = json_object_array_get_idx(h_time, j);
            const char *ts = timej ? json_object_get_string(timej) : NULL;
            // "2026-09-24T11:00" -> "11" (no ":00")
            if (ts && strlen(ts) >= 13)
                snprintf(w.hour_label[i], sizeof(w.hour_label[i]), "%d", atoi(ts + 11));
            else
                snprintf(w.hour_label[i], sizeof(w.hour_label[i]), "+%d", i);
        }
    }

    json_object *d_min = NULL, *d_max = NULL, *d_c = NULL, *d_p = NULL, *d_time = NULL;
    json_object_object_get_ex(daily, "temperature_2m_min", &d_min);
    json_object_object_get_ex(daily, "temperature_2m_max", &d_max);
    json_object_object_get_ex(daily, "weather_code", &d_c);
    json_object_object_get_ex(daily, "precipitation_probability_max", &d_p);
    json_object_object_get_ex(daily, "time", &d_time);
    int dn = d_min ? json_object_array_length(d_min) : 0;
    if (dn > W_DAYS) dn = W_DAYS;
    for (int i = 0; i < dn; i++) {
        json_object *e = json_object_array_get_idx(d_min, i);
        w.day_min[i] = e ? (float)json_object_get_double(e) : 0;
        if (d_max) {
            e = json_object_array_get_idx(d_max, i);
            w.day_max[i] = e ? (float)json_object_get_double(e) : 0;
        }
        if (d_c) {
            e = json_object_array_get_idx(d_c, i);
            w.day_code[i] = e ? json_object_get_int(e) : 0;
        }
        if (d_p) {
            e = json_object_array_get_idx(d_p, i);
            if (e && json_object_get_type(e) == json_type_int)
                w.day_pop[i] = json_object_get_int(e);
        }
        if (d_time) {
            e = json_object_array_get_idx(d_time, i);
            const char *iso = e ? json_object_get_string(e) : NULL;
            snprintf(w.day_label[i], sizeof(w.day_label[i]), "%s", day_name(iso));
        }
    }

    if (dn <= 0) {
        json_object_put(root);
        return false;
    }

    if (w.cur_pop <= 0 && h_p &&
        idx < (int)json_object_array_length(h_p)) {
        json_object *pj = json_object_array_get_idx(h_p, idx);
        if (pj && json_object_get_type(pj) == json_type_int)
            w.cur_pop = json_object_get_int(pj);
    }

    w.ready = true;
    w.fetching = false;
    w.last_ok = GetTime();

    pthread_mutex_lock(&weather_mu);
    weather = w;
    pthread_mutex_unlock(&weather_mu);
    json_object_put(root);
    return true;
}

static void weather_save_cache(const char *json_text) {
    char path[512];
    weather_cache_path(path, sizeof(path), "weather.json");
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs(json_text, f);
    fclose(f);
}

static bool weather_load_cache(void) {
    char path[512];
    weather_cache_path(path, sizeof(path), "weather.json");
    FILE *f = fopen(path, "r");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 2 * 1024 * 1024) {
        fclose(f);
        return false;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return false;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    bool ok = weather_parse_forecast(buf);
    free(buf);
    return ok;
}

static void weather_save_loc(void) {
    char path[512];
    weather_cache_path(path, sizeof(path), "loc.txt");
    FILE *f = fopen(path, "w");
    if (!f) return;
    pthread_mutex_lock(&weather_mu);
    fprintf(f, "%.5f\n%.5f\n%s\n", weather.lat, weather.lon, weather.place);
    pthread_mutex_unlock(&weather_mu);
    fclose(f);
}

static bool weather_load_loc(void) {
    char path[512];
    weather_cache_path(path, sizeof(path), "loc.txt");
    FILE *f = fopen(path, "r");
    if (!f) return false;
    float lat = 0, lon = 0;
    char place[64] = {0};
    if (fscanf(f, "%f\n%f\n", &lat, &lon) != 2) {
        fclose(f);
        return false;
    }
    if (!fgets(place, sizeof(place), f)) place[0] = '\0';
    fclose(f);
    size_t L = strlen(place);
    while (L > 0 && (place[L - 1] == '\n' || place[L - 1] == '\r')) place[--L] = '\0';
    pthread_mutex_lock(&weather_mu);
    weather.lat = lat;
    weather.lon = lon;
    snprintf(weather.place, sizeof(weather.place), "%s", place[0] ? place : "local");
    pthread_mutex_unlock(&weather_mu);
    return true;
}

static bool weather_set_place(float lat, float lon, const char *place) {
    pthread_mutex_lock(&weather_mu);
    weather.lat = lat;
    weather.lon = lon;
    snprintf(weather.place, sizeof(weather.place), "%.63s",
             place && place[0] ? place : "local");
    pthread_mutex_unlock(&weather_mu);
    weather_save_loc();
    return true;
}

static bool weather_geocode_city(const char *city) {
    char *e = curl_easy_escape(NULL, city, 0);
    if (!e) return false;
    char url[512];
    snprintf(url, sizeof(url),
             "https://geocoding-api.open-meteo.com/v1/search?name=%s"
             "&count=1&language=en&format=json",
             e);
    curl_free(e);

    char *body = http_get(url, 6);
    if (!body) return false;

    json_object *root = json_tokener_parse(body);
    free(body);
    if (!root) return false;

    json_object *results = NULL;
    bool ok = false;
    if (json_object_object_get_ex(root, "results", &results) &&
        json_object_array_length(results) > 0) {
        json_object *r0 = json_object_array_get_idx(results, 0);
        json_object *la = NULL, *lo = NULL, *nm = NULL, *cc = NULL;
        json_object_object_get_ex(r0, "latitude", &la);
        json_object_object_get_ex(r0, "longitude", &lo);
        json_object_object_get_ex(r0, "name", &nm);
        json_object_object_get_ex(r0, "country_code", &cc);
        if (la && lo) {
            char label[96];
            const char *n = nm ? json_object_get_string(nm) : city;
            const char *c = cc ? json_object_get_string(cc) : "";
            snprintf(label, sizeof(label), "%.40s, %.16s", n, c);
            ok = weather_set_place((float)json_object_get_double(la),
                                   (float)json_object_get_double(lo), label);
        }
    }
    json_object_put(root);
    return ok;
}

static bool weather_ip_locate(void) {
    char *body = http_get("https://ipapi.co/json/", 6);
    if (!body) body = http_get("https://ipwho.is/", 6);
    if (!body) return false;

    json_object *root = json_tokener_parse(body);
    free(body);
    if (!root) return false;

    json_object *la = NULL, *lo = NULL, *city = NULL, *cc = NULL;
    json_object_object_get_ex(root, "latitude", &la);
    json_object_object_get_ex(root, "longitude", &lo);
    json_object_object_get_ex(root, "city", &city);
    if (!json_object_object_get_ex(root, "country_code", &cc))
        json_object_object_get_ex(root, "country", &cc);

    bool ok = false;
    if (la && lo) {
        char label[64];
        const char *c = city ? json_object_get_string(city) : "";
        const char *k = cc ? json_object_get_string(cc) : "";
        if (c[0])
            snprintf(label, sizeof(label), "%s, %s", c, k);
        else
            snprintf(label, sizeof(label), "ip");
        ok = weather_set_place((float)json_object_get_double(la),
                               (float)json_object_get_double(lo), label);
    }
    json_object_put(root);
    return ok;
}

static bool weather_resolve_location(void) {
    if (cli_have_latlon) {
        char label[64];
        snprintf(label, sizeof(label), "%.2f, %.2f", cli_lat, cli_lon);
        return weather_set_place(cli_lat, cli_lon, label);
    }
    if (cli_city[0]) {
        if (weather_geocode_city(cli_city)) return true;
    }
    if (weather_load_loc()) return true;
    return weather_ip_locate();
}

static bool weather_fetch(void) {
    float lat, lon;
    pthread_mutex_lock(&weather_mu);
    lat = weather.lat;
    lon = weather.lon;
    weather.fetching = true;
    pthread_mutex_unlock(&weather_mu);

    if (lat == 0.0f && lon == 0.0f) {
        if (!weather_resolve_location()) {
            pthread_mutex_lock(&weather_mu);
            weather.fetching = false;
            pthread_mutex_unlock(&weather_mu);
            return false;
        }
        pthread_mutex_lock(&weather_mu);
        lat = weather.lat;
        lon = weather.lon;
        pthread_mutex_unlock(&weather_mu);
    }

    char url[768];
    snprintf(url, sizeof(url),
             "https://api.open-meteo.com/v1/forecast"
             "?latitude=%.4f&longitude=%.4f"
             "&current=temperature_2m,weather_code,apparent_temperature,"
             "precipitation_probability"
             "&hourly=temperature_2m,weather_code,precipitation_probability,is_day"
             "&daily=weather_code,temperature_2m_max,temperature_2m_min,"
             "precipitation_probability_max"
             "&forecast_days=7&timezone=auto",
             lat, lon);

    char *body = http_get(url, 8);
    if (!body) {
        pthread_mutex_lock(&weather_mu);
        weather.fetching = false;
        pthread_mutex_unlock(&weather_mu);
        fprintf(stderr, "[memelock] weather: fetch failed\n");
        return false;
    }

    bool ok = weather_parse_forecast(body);
    if (ok) weather_save_cache(body);
    free(body);

    pthread_mutex_lock(&weather_mu);
    weather.fetching = false;
    pthread_mutex_unlock(&weather_mu);
    return ok;
}

static void *weather_thread(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&weather_mu);
        bool down = weather_shutdown;
        double last = weather.last_ok;
        bool ready = weather.ready;
        bool fetching = weather.fetching;
        pthread_mutex_unlock(&weather_mu);
        if (down) break;

        bool due = !ready || (!fetching && (last <= 0.0 || (GetTime() - last) >= W_REFRESH_SEC));
        if (due) weather_fetch();

        for (int i = 0; i < 50 && !weather_shutdown; i++)
            usleep(20 * 1000);
    }
    return NULL;
}

static void weather_start(void) {
    if (!weather_enabled) return;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    weather_load_font();

    if (cli_have_latlon || cli_city[0])
        weather_resolve_location();
    else
        weather_load_loc();
    weather_load_cache();

    weather_thr_started =
        (pthread_create(&weather_thr, NULL, weather_thread, NULL) == 0);
    if (!weather_thr_started)
        fprintf(stderr, "[memelock] weather: thread create failed\n");
}

static void weather_stop(void) {
    if (!weather_enabled) return;
    pthread_mutex_lock(&weather_mu);
    weather_shutdown = true;
    pthread_mutex_unlock(&weather_mu);
    if (weather_thr_started) {
        pthread_join(weather_thr, NULL);
        weather_thr_started = false;
    }
    if (weather_font_owned && weather_font.texture.id > 0) {
        UnloadFont(weather_font);
        weather_font = (Font){0};
        weather_font_owned = false;
    }
    curl_global_cleanup();
}

// Widget font: sleek humanist sans, not raylib's boxy default.
static void weather_load_font(void) {
    const char *cands[] = {
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/Ubuntu-R.ttf",
        NULL,
    };
    for (int i = 0; cands[i]; i++) {
        if (!FileExists(cands[i])) continue;
        Font f = LoadFontEx(cands[i], 64, NULL, 0);
        if (f.texture.id > 0) {
            weather_font = f;
            weather_font_owned = true;
            SetTextureFilter(weather_font.texture, TEXTURE_FILTER_BILINEAR);
            return;
        }
    }
    weather_font = GetFontDefault();
    weather_font_owned = false;
}

static Font *w_font_ptr(void) {
    if (weather_font.texture.id > 0) return &weather_font;
    return NULL;
}

static int w_measure(const char *s, int size) {
    Font *f = w_font_ptr();
    if (f) return (int)MeasureTextEx(*f, s, (float)size, 0.0f).x;
    return MeasureText(s, size);
}

static void w_draw(const char *s, int x, int y, int size, Color c) {
    Font *f = w_font_ptr();
    if (f) DrawTextEx(*f, s, (Vector2){ (float)x, (float)y }, (float)size, 0.0f, c);
    else DrawText(s, x, y, size, c);
}

static void w_cell(const char *s, int x, int y, int w, int h, int font, Color c) {
    int tw = w_measure(s, font);
    int tx = x + (w - tw) / 2;
    int ty = y + (h - font) / 2;
    if (tx < x) tx = x;
    if (ty < y) ty = y;
    w_draw(s, tx, ty, font, c);
}

static void weather_draw(int sw, int sh) {
    if (!weather_enabled || !weather_visible) return;

    WeatherState snap;
    pthread_mutex_lock(&weather_mu);
    snap = weather;
    pthread_mutex_unlock(&weather_mu);

    const int F_LABEL = layout.font_label;
    const int F_TEMP = layout.font_temp;
    const int F_POP = layout.font_pop;
    const int F_DIM = F_LABEL;
    const int pad = layout.pad;
    const int margin = layout.margin;
    const int col_gap = layout.col_gap;
    const int row_gap = layout.row_gap;
    const int block_gap = layout.block_gap;
    // Tight vertical: row pitch = font size + row_gap (+ legacy extra).
    const int rh_lab = F_LABEL + row_gap + layout.row_h;
    const int rh_tmp = F_TEMP + row_gap + layout.row_h;
    const int rh_pop = F_POP + layout.row_h; // no gap after last row
    const int dh_lab = F_LABEL + row_gap + layout.day_row_h;
    const int dh_tmp = F_TEMP + row_gap + layout.day_row_h;
    const int dh_pop = F_POP + layout.day_row_h;

    const Color c_label = { 170, 175, 185, 230 };
    const Color c_pop = { 100, 140, 200, 220 };
    const Color c_dim = { 90, 95, 105, 200 };
    Color ui_bg = { 10, 12, 18, (unsigned char)layout.bg_alpha };

    // Hours: label | temp (day) | pop (day)  — night: label only
    // Days:  label | high | pop              — no lows
    int hours_h = rh_lab + rh_tmp + rh_pop;
    int days_h = dh_lab + dh_tmp + dh_pop;
    int panel_content_h = hours_h + block_gap + days_h;

    if (!snap.ready) {
        int panel_w = w_measure("weather...", F_DIM) + pad * 2;
        int panel_h = F_DIM + pad * 2;
        int px = margin;
        int py = sh - margin - panel_h;
        if (py < 0) py = 0;
        DrawRectangle(px, py, panel_w, panel_h, ui_bg);
        int tx = px + pad;
        int tw = w_measure("weather...", F_DIM);
        w_draw("weather...", px + (panel_w - tw) / 2, py + pad, F_DIM, c_dim);
        if (snap.fetching)
            w_draw("...", tx + tw + 4, py + pad, F_DIM, c_dim);
        (void)sw;
        return;
    }

    // Column width: max of label / temp / pop at each font (day cells only matter for temp).
    int col_w = layout.min_col_w;
    for (int i = 0; i < W_HOURS; i++) {
        int m = w_measure(snap.hour_label[i], F_LABEL);
        if (snap.hour_is_day[i]) {
            char tbuf[16];
            int wt;
            snprintf(tbuf, sizeof(tbuf), "%.0f", snap.hour_temp[i]);
            wt = w_measure(tbuf, F_TEMP);
            if (wt > m) m = wt;
            snprintf(tbuf, sizeof(tbuf), "%d%%", snap.hour_pop[i]);
            wt = w_measure(tbuf, F_POP);
            if (wt > m) m = wt;
        }
        if (m + 6 > col_w) col_w = m + 6;
    }
    for (int i = 0; i < W_DAYS; i++) {
        int m = w_measure(snap.day_label[i], F_LABEL);
        char tbuf[16];
        int wt;
        snprintf(tbuf, sizeof(tbuf), "%.0f", snap.day_max[i]);
        wt = w_measure(tbuf, F_TEMP);
        if (wt > m) m = wt;
        snprintf(tbuf, sizeof(tbuf), "%d%%", snap.day_pop[i]);
        wt = w_measure(tbuf, F_POP);
        if (wt > m) m = wt;
        if (m + 6 > col_w) col_w = m + 6;
    }

    int hours_w = W_HOURS * col_w + (W_HOURS - 1) * col_gap;
    int days_w = W_DAYS * col_w + (W_DAYS - 1) * col_gap;
    int content_w = hours_w > days_w ? hours_w : days_w;
    int panel_w = content_w + pad * 2;
    int panel_h = panel_content_h + pad * 2;
    int px = margin;
    int py = sh - margin - panel_h;
    if (py < 0) py = 0;

    DrawRectangle(px, py, panel_w, panel_h, ui_bg);
    int cx = px + pad;
    int cy = py + pad;

    // --- Hours ---
    int hy = cy;
    int y_lab = hy;
    int y_tmp = y_lab + rh_lab;
    int y_pop = y_tmp + rh_tmp;
    for (int i = 0; i < W_HOURS; i++) {
        int x = cx + i * (col_w + col_gap);
        w_cell(snap.hour_label[i], x, y_lab, col_w, rh_lab, F_LABEL, c_label);
        if (!snap.hour_is_day[i]) continue;
        char tbuf[16];
        snprintf(tbuf, sizeof(tbuf), "%.0f", snap.hour_temp[i]);
        w_cell(tbuf, x, y_tmp, col_w, rh_tmp, F_TEMP,
               wmo_temp_color(snap.hour_code[i]));
        snprintf(tbuf, sizeof(tbuf), "%d%%", snap.hour_pop[i]);
        w_cell(tbuf, x, y_pop, col_w, rh_pop, F_POP, c_pop);
    }

    // --- Days (highs only) ---
    int dy = cy + hours_h + block_gap;
    int d_lab = dy;
    int d_tmp = d_lab + dh_lab;
    int d_pop = d_tmp + dh_tmp;
    for (int i = 0; i < W_DAYS; i++) {
        int x = cx + i * (col_w + col_gap);
        w_cell(snap.day_label[i], x, d_lab, col_w, dh_lab, F_LABEL, c_label);
        char tbuf[16];
        snprintf(tbuf, sizeof(tbuf), "%.0f", snap.day_max[i]);
        w_cell(tbuf, x, d_tmp, col_w, dh_tmp, F_TEMP,
               wmo_temp_color(snap.day_code[i]));
        snprintf(tbuf, sizeof(tbuf), "%d%%", snap.day_pop[i]);
        w_cell(tbuf, x, d_pop, col_w, dh_pop, F_POP, c_pop);
    }

    (void)sw;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n"
           "\n"
           "Options:\n"
           "  -h, --help              show this help and exit\n"
           "  -b, -b=N                background blur radius (default 5)\n"
           "  -d, -d=N                background darken, -255..255 (default -25)\n"
           "  --weather               weather widget visible at start (default)\n"
           "  --no-weather            disable weather widget\n"
           "  --city=NAME[,CC]        city for weather (e.g. Vilnius or Paris,FR)\n"
           "  --lat=LAT --lon=LON     exact coordinates for weather\n"
           "  --layout[=PATH]         live-reload weather layout file\n"
           "                          (default ~/.cache/memelock/layout.txt)\n"
           "  --snow-speed=N          snowfall speed multiplier (default 1.0)\n"
           "  --snow-tint=MODE        flake color: white | ice | mix (default mix)\n"
           "\n"
           "While locked: Ctrl+R toggles the weather widget.\n",
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
        } else if (strcmp(argv[i], "--weather") == 0) {
            weather_enabled = true;
            weather_visible = true;
        } else if (strcmp(argv[i], "--no-weather") == 0) {
            weather_enabled = false;
            weather_visible = false;
        } else if (strncmp(argv[i], "--city=", 7) == 0) {
            snprintf(cli_city, sizeof(cli_city), "%s", argv[i] + 7);
        } else if (strncmp(argv[i], "--lat=", 6) == 0) {
            cli_lat = (float)strtod(argv[i] + 6, NULL);
            if (cli_have_latlon || cli_lon != 0.0f) cli_have_latlon = true;
        } else if (strncmp(argv[i], "--lon=", 6) == 0) {
            cli_lon = (float)strtod(argv[i] + 6, NULL);
            cli_have_latlon = true;
        } else if (strcmp(argv[i], "--layout") == 0) {
            layout_enabled = true;
            weather_cache_path(layout_path, sizeof(layout_path), "layout.txt");
        } else if (strncmp(argv[i], "--layout=", 9) == 0) {
            layout_enabled = true;
            snprintf(layout_path, sizeof(layout_path), "%s", argv[i] + 9);
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

    weather_start();
    if (layout_enabled) {
        layout_clamp();
        layout_load(); // initial load if file exists
        fprintf(stderr, "[memelock] layout: live reload on %s\n", layout_path);
    }

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

        // Default-font '*' ink (raylib sprite): rows 2..6 of 10 → center row 4.
        // DrawText places the full 10px cell at y (offsetY=0), so the star sits
        // high in the line box; shift down so the ink centers in the panel.
        const int text_size = 64;
        int text_width = MeasureText(display, text_size);
        int star_w = MeasureText("*", text_size);
        int content_w = text_width > 0 ? text_width : star_w;
        int content_x = (sw - content_w) / 2;
        int box_h = text_size + ui_pad * 2;
        int box_y = sh / 2 - ui_pad;
        int ink_cy = text_size * 4 / 10; // center of * from DrawText y
        int text_y = box_y + box_h / 2 - ink_cy;

        DrawRectangle(content_x - ui_pad, box_y,
                      content_w + ui_pad * 2, box_h, ui_bg);
        if (text_width > 0)
            DrawText(display, content_x, text_y, text_size, WHITE);

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

        // Weather widget — compact layout, bottom-left (Ctrl+R toggles).
        layout_poll();
        weather_draw(sw, sh);

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
    weather_stop();
    bg_unload();
    CloseWindow();
    return 0;
}
