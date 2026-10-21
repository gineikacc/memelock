#include "raylib.h"
#include "dvd_logo.h"
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
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>
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

    // Fullscreen / always-on-top / sticky / skip-taskbar hints. Harmless
    // without remap; the grab below is what blocks WM hotkeys.
    Atom net_wm_state = XInternAtom(xdisplay, "_NET_WM_STATE", False);
    Atom fs     = XInternAtom(xdisplay, "_NET_WM_STATE_FULLSCREEN", False);
    Atom above  = XInternAtom(xdisplay, "_NET_WM_STATE_ABOVE", False);
    Atom sticky = XInternAtom(xdisplay, "_NET_WM_STATE_STICKY", False);
    Atom skip_tb = XInternAtom(xdisplay, "_NET_WM_STATE_SKIP_TASKBAR", False);
    Atom skip_pg = XInternAtom(xdisplay, "_NET_WM_STATE_SKIP_PAGER", False);
    Atom states[] = { fs, above, sticky, skip_tb, skip_pg };
    XChangeProperty(xdisplay, xwindow, net_wm_state, XA_ATOM, 32,
                    PropModeReplace, (unsigned char *)states, 5);

    // EWMH: WMs only apply _NET_WM_STATE changes delivered as a ClientMessage
    // on the root — property writes alone are ignored. Ask to be skipped in
    // taskbars/pagers so we never show up in the tag's client list.
    {
        XEvent ev = {0};
        ev.xclient.type = ClientMessage;
        ev.xclient.window = xwindow;
        ev.xclient.message_type = net_wm_state;
        ev.xclient.format = 32;
        ev.xclient.data.l[0] = 1; // _NET_WM_STATE_ADD
        ev.xclient.data.l[1] = (long)skip_tb;
        ev.xclient.data.l[2] = (long)skip_pg;
        ev.xclient.data.l[3] = 1; // source: normal application
        XSendEvent(xdisplay, xroot, False,
                   SubstructureRedirectMask | SubstructureNotifyMask, &ev);
    }

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

// --- Modular prompt field (top-left corner) ---
// Small text/number entry opened by a Ctrl bind while locked. While open,
// keystrokes go here (not the password). Enter commits, Esc cancels.
// Consumers: blur (Ctrl+B), darken (Ctrl+D). Add more via prompt_open_with.

typedef void (*PromptCommitFn)(const char *text);

static bool prompt_open = false;
static char prompt_label[32] = {0};
static char prompt_buf[64] = {0};
static int prompt_len = 0;
static bool prompt_numeric = false;
static bool prompt_signed = false; // allow a single leading '-'
static PromptCommitFn prompt_commit = NULL;

static void prompt_close(void) {
    prompt_open = false;
    prompt_len = 0;
    prompt_buf[0] = '\0';
    prompt_label[0] = '\0';
    prompt_numeric = false;
    prompt_signed = false;
    prompt_commit = NULL;
}

static void prompt_open_with(const char *label, const char *initial,
                             bool numeric, bool signed_val,
                             PromptCommitFn on_commit) {
    snprintf(prompt_label, sizeof(prompt_label), "%s", label);
    snprintf(prompt_buf, sizeof(prompt_buf), "%s", initial ? initial : "");
    prompt_len = (int)strlen(prompt_buf);
    prompt_numeric = numeric;
    prompt_signed = signed_val;
    prompt_commit = on_commit;
    prompt_open = true;
}

// Copy buffer first: commit callback may call prompt_close().
static void prompt_submit(void) {
    if (!prompt_open || prompt_len <= 0 || !prompt_commit) return;
    char tmp[sizeof(prompt_buf)];
    PromptCommitFn fn = prompt_commit;
    memcpy(tmp, prompt_buf, sizeof(tmp));
    prompt_close();
    fn(tmp);
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
// Idle fade for the * box only. Reset on any password key.
// Starts faded out (last_key far in the past → already "idle" at launch).
static double passwd_last_key = -1e9;
static float passwd_fade = 0.0f; // 1 = fully visible, 0 = hidden

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

// Snow spawn on/off (Ctrl+S / --no-snow). Clear pile (Ctrl+X) after pile[].
static bool snow_spawning = true;
static void snow_spawn_toggle(void) { snow_spawning = !snow_spawning; }
static void snow_clear(void);

// Meteors on/off (Ctrl+M / --no-meteors). Stops new spawns only — anything
// already in flight still lands. Body with the snow sim section below.
static bool meteors_enabled = true;
static void meteors_toggle(void) { meteors_enabled = !meteors_enabled; }

// Deliberate crash for supervisor testing (Ctrl+K). Double-gated: the
// bind below is inert unless --crash-key enabled this run.
static bool crash_key_enabled = false;
static void crash_now(void) {
    if (!crash_key_enabled) return;
    fprintf(stderr, "[memelock] deliberate crash via test key\n");
    fflush(stderr);
    abort();
}

// DVD logo toggle (Ctrl+V / --dvd); body with the snow sim section.
static void dvd_toggle(void);

// Microwave timer (Ctrl+T), quotes (Ctrl+Q), stocks (Ctrl+O) — see sections.
static void mw_toggle(void);
static void mw_add_thirty(void);
static void quotes_next(void);
static void stocks_toggle(void);

// Blur / darken controls (defined with background section below).
static void bg_set_blur(int v);
static void bg_set_darken(int v);
static void blur_step(int delta);
static void blur_dec(void) { blur_step(-1); }
static void blur_inc(void) { blur_step(+1); }
static void blur_field_open(void);
static void min_blur_inc(void);
static void darken_step(int delta);
static void darken_dec(void) { darken_step(-5); }
static void darken_inc(void) { darken_step(+5); }
static void darken_field_open(void);

typedef void (*PasswdAction)(void);

// shift: require ShiftMask held (Ctrl always held when matched).
// Punctuation keysyms alias so Ctrl+Shift+, works as XK_comma or XK_less.
static const struct {
    KeySym ks;
    bool shift;
    PasswdAction fn;
    const char *desc;
} ctrl_binds[] = {
    { XK_U,      false, passwd_clear_line, "clear line" },
    { XK_W,      false, passwd_kill_word,  "delete word" },
    { XK_R,      false, weather_toggle,    "toggle weather" },
    { XK_S,      false, snow_spawn_toggle, "toggle snow spawn" },
    { XK_X,      false, snow_clear,        "clear snow" },
    { XK_M,      false, meteors_toggle,    "toggle meteors" },
    { XK_comma,  false, blur_dec,          "blur -" },
    { XK_period, false, blur_inc,          "blur +" },
    { XK_comma,  true,  darken_dec,        "darken -" },
    { XK_period, true,  darken_inc,        "darken +" },
    { XK_B,      false, blur_field_open,   "blur field" },
    { XK_H,      false, min_blur_inc,      "min blur +" },
    { XK_D,      false, darken_field_open, "darken field" },
    { XK_V,      false, dvd_toggle,        "toggle dvd logo" },
    { XK_T,      false, mw_toggle,         "toggle microwave" },
    { XK_Q,      false, quotes_next,       "next quote" },
    { XK_O,      false, stocks_toggle,     "toggle stocks" },
    { XK_K,      false, crash_now,         "deliberate crash (needs --crash-key)" },
    // +30 on the microwave — keyboard only (no mouse on this lock).
    { XK_plus,     false, mw_add_thirty,   "microwave +30" },
    { XK_KP_Add,   false, mw_add_thirty,   "microwave +30" },
    { XK_plus,     true,  mw_add_thirty,   "microwave +30" },
};

static bool keysym_matches(KeySym k, KeySym bk) {
    if (k >= XK_A && k <= XK_Z) k += (XK_a - XK_A);
    if (bk >= XK_A && bk <= XK_Z) bk += (XK_a - XK_A);
    if (k == bk) return true;
    // Shifted US punctuation often arrives as the shifted character.
    if (bk == XK_comma && k == XK_less) return true;
    if (bk == XK_period && k == XK_greater) return true;
    if (bk == XK_plus && (k == XK_plus || k == XK_KP_Add ||
                          k == XK_equal || k == XK_KP_Equal))
        return true;
    return false;
}

static void handle_xkey(XKeyEvent *ev) {
    char buf[32];
    KeySym ks = NoSymbol;
    int n = XLookupString(ev, buf, sizeof(buf), &ks, NULL);

    // Ctrl combos first: match bind table, swallow everything else
    // (so e.g. Ctrl+C / Ctrl+Z can never do anything here).
    // Normalize keysym to lowercase so XK_R / XK_r both match XK_R binds.
    if (ev->state & ControlMask) {
        bool shift = (ev->state & ShiftMask) != 0;
        for (unsigned i = 0; i < sizeof(ctrl_binds) / sizeof(ctrl_binds[0]); i++) {
            if (ctrl_binds[i].shift != shift) continue;
            if (keysym_matches(ks, ctrl_binds[i].ks)) {
                ctrl_binds[i].fn();
                return;
            }
        }
        return;
    }

    // Modular corner field takes keys while open (not the password).
    if (prompt_open) {
        switch (ks) {
            case XK_Return:
            case XK_KP_Enter:
                prompt_submit();
                return;
            case XK_BackSpace:
                if (prompt_len > 0) {
                    prompt_len--;
                    prompt_buf[prompt_len] = '\0';
                }
                return;
            case XK_Escape:
                prompt_close();
                return;
            default:
                break;
        }
        if (ev->state & (ControlMask | Mod1Mask | Mod4Mask | Mod5Mask))
            return;
        for (int i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];
            if (c < 32 || c == 127) continue;
            if (prompt_numeric) {
                if (c == '-') {
                    if (!prompt_signed || prompt_len != 0) continue;
                } else if (c < '0' || c > '9') {
                    continue;
                }
            }
            if (prompt_len < (int)sizeof(prompt_buf) - 1) {
                prompt_buf[prompt_len++] = (char)c;
                prompt_buf[prompt_len] = '\0';
            }
        }
        return;
    }

    switch (ks) {
        case XK_Return:
        case XK_KP_Enter:
            passwd_last_key = GetTime();
            if (xpass_len > 0) xpass_submit = true;
            return;
        case XK_BackSpace:
            passwd_last_key = GetTime();
            passwd_backspace();
            return;
        case XK_Escape:
            passwd_last_key = GetTime();
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
            passwd_last_key = GetTime();
            xpassword[xpass_len++] = (char)c;
            xpassword[xpass_len] = '\0';
            xauth_failed = false;
        }
    }
}

// Microwave +30 is keyboard-only (Ctrl++ / KP+); ButtonPress is a no-op.
static void mw_handle_click(int rx, int ry);

// Drain OUR Display's queue; call once per frame. Non-blocking.
static void pump_x11_input(void) {
    if (!xdisplay) return;
    while (XPending(xdisplay)) {
        XEvent ev;
        XNextEvent(xdisplay, &ev);
        if (ev.type == KeyPress) handle_xkey(&ev.xkey);
        else if (ev.type == ButtonPress)
            mw_handle_click(ev.xbutton.x_root, ev.xbutton.y_root);
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

// --- Background snow / meteors / obsidian ---
// Done: snow pile + per-flake tint + speed; meteors (fast fireballs with a
// comet-style trail + sideways drift) crater the pile and throw debris;
// bare ground -> obsidian sink.
// Removed: water particles, snow floating, lava melting (per user).
// Future docket (not yet implemented):
//  * snow plow entity  -> pile_push() ahead of it + debris particles
//  * mouse dig/push    -> pump ButtonPress/Motion from our X grab, pile_remove/push
// Done: wind gusts (horizontal only on flakes); meteor impact debris.
#define SNOW_COUNT 200
#define PILE_MAX_SLOPE 1.2f     // max height diff between adjacent columns (px)
#define PILE_RELAX_ITERS 3

#define METEOR_MAX 8
#define METEOR_RADIUS 10.0f          // ~20px wide
#define METEOR_SPAWN_DENOM 500       // 1 in 500 flake respawns
#define METEOR_TRAIL 16              // trail samples behind the head

#define OBSIDIAN_MAX 32

static float snow_speed_mult = 1.0f; // --snow-speed=N
// Ambient wind gusts: push flakes sideways only (not pile/meteor/DVD).
static float wind_x = 0.0f;          // current px/s
static float wind_target = 0.0f;     // ramp goal (eased over ~0.5s)
static float wind_phase = 0.0f;
static float wind_gap = 0.0f;        // seconds until next gust attempt
static float wind_allow = 1.0f;      // --wind=0 disables

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

// Meteor: fast fireball with a short trail and a little sideways drift.
// Hits the snow pile -> crater + debris burst; bare ground -> obsidian.
static struct {
    bool alive;
    float x, y;
    float speed;                    // vertical px/s
    float vx;                       // horizontal px/s
    float trail_x[METEOR_TRAIL];    // [0] = newest
    float trail_y[METEOR_TRAIL];
} meteor[METEOR_MAX];

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

// Ctrl+X: wipe accumulated pile (falling flakes keep going until Ctrl+S).
static void snow_clear(void) {
    memset(pile, 0, sizeof(pile));
    for (int i = 0; i < pile_w; i++) {
        pile_tint_r[i] = 240.0f;
        pile_tint_g[i] = 245.0f;
        pile_tint_b[i] = 255.0f;
    }
}

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
// Used by meteor impacts (pile_remove / pile_push still docket-only).
static void pile_blast(int cx, int radius, float force) {
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

// --- Meteors ---

static void meteor_spawn(float x) {
    for (int i = 0; i < METEOR_MAX; i++) {
        if (meteor[i].alive) continue;
        meteor[i].alive = true;
        meteor[i].x = x;
        meteor[i].y = -METEOR_RADIUS;
        // 600..800 px/s — ~2.5x the old lava droplet (220..300).
        meteor[i].speed = 600.0f + (float)GetRandomValue(0, 200);
        // A bit of horizontal momentum, either direction.
        meteor[i].vx = (GetRandomValue(0, 1) ? 1.0f : -1.0f) *
                       (70.0f + (float)GetRandomValue(0, 150));
        for (int k = 0; k < METEOR_TRAIL; k++) {
            meteor[i].trail_x[k] = meteor[i].x;
            meteor[i].trail_y[k] = meteor[i].y;
        }
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

// --- Impact debris: sparks + snow chunks, both under gravity ---
#define PART_MAX 192
#define PART_GRAVITY 1500.0f // px/s^2

static struct {
    bool alive;
    float x, y, vx, vy;
    float life, max_life;
    float size;
    Color col;
} part[PART_MAX];

static void part_emit(float x, float y, float vx, float vy,
                      float life, float size, Color col) {
    int slot = -1;
    float worst = 1e9f;
    for (int i = 0; i < PART_MAX; i++) {
        if (!part[i].alive) { slot = i; break; }
        if (part[i].life < worst) { worst = part[i].life; slot = i; }
    }
    if (slot < 0) return;
    part[slot].alive = true;
    part[slot].x = x;
    part[slot].y = y;
    part[slot].vx = vx;
    part[slot].vy = vy;
    part[slot].life = life;
    part[slot].max_life = life;
    part[slot].size = size;
    part[slot].col = col;
}

// Meteor meets snow: carve a crater (pile_blast takes the center out and
// dumps half of it on the rim) and blow sparks + snow chunks out of it.
static void meteor_impact(float x, float y) {
    int cx = (int)x;
    if (cx < 0) cx = 0;
    if (cx >= pile_w) cx = pile_w - 1;
    pile_blast(cx, 46 + GetRandomValue(0, 30),
               55.0f + (float)GetRandomValue(0, 35));

    for (int i = 0; i < 16; i++) { // hot sparks
        float ang = (float)GetRandomValue(0, 359) * DEG2RAD;
        float sp = 180.0f + (float)GetRandomValue(0, 340);
        Color c = GetRandomValue(0, 1) ? (Color){255, 190, 90, 255}
                                       : (Color){255, 110, 40, 255};
        part_emit(x, y, cosf(ang) * sp, sinf(ang) * sp - 150.0f,
                  0.35f + (float)GetRandomValue(0, 45) / 100.0f,
                  1.5f + (float)GetRandomValue(0, 3), c);
    }
    for (int i = 0; i < 14; i++) { // snow chunks
        float ang = (float)GetRandomValue(0, 359) * DEG2RAD;
        float sp = 120.0f + (float)GetRandomValue(0, 260);
        Color c = { 238, 243, 255, 255 };
        part_emit(x, y, cosf(ang) * sp, sinf(ang) * sp - 180.0f,
                  0.7f + (float)GetRandomValue(0, 70) / 100.0f,
                  1.5f + (float)GetRandomValue(0, 3), c);
    }
}

static void meteor_update(float dt) {
    float sh = (float)GetScreenHeight();
    float sw = (float)GetScreenWidth();
    for (int i = 0; i < METEOR_MAX; i++) {
        if (!meteor[i].alive) continue;
        meteor[i].y += meteor[i].speed * snow_speed_mult * dt;
        meteor[i].x += meteor[i].vx * snow_speed_mult * dt;
        if (meteor[i].x < -METEOR_RADIUS || meteor[i].x > sw + METEOR_RADIUS) {
            meteor[i].alive = false; // drifted off the side
            continue;
        }
        // Trail history: newest at [0], oldest at [METEOR_TRAIL-1].
        for (int k = METEOR_TRAIL - 1; k > 0; k--) {
            meteor[i].trail_x[k] = meteor[i].trail_x[k - 1];
            meteor[i].trail_y[k] = meteor[i].trail_y[k - 1];
        }
        meteor[i].trail_x[0] = meteor[i].x;
        meteor[i].trail_y[0] = meteor[i].y;

        float gy = ground_at(meteor[i].x);
        if (meteor[i].y < gy) continue;
        int col = (int)meteor[i].x;
        if (col < 0) col = 0;
        if (col >= pile_w) col = pile_w - 1;
        if (pile[col] > 3.0f) {
            meteor_impact(meteor[i].x, gy); // crater + debris
            meteor[i].alive = false;
        } else if (meteor[i].y >= sh - METEOR_RADIUS * 0.5f) {
            // Bare ground: cools into a rock that sinks into the snow.
            obsidian_spawn(meteor[i].x, sh - METEOR_RADIUS);
            meteor[i].alive = false;
        }
    }
}

static void parts_update(float dt) {
    float m = snow_speed_mult;
    for (int i = 0; i < PART_MAX; i++) {
        if (!part[i].alive) continue;
        part[i].life -= dt * m;
        if (part[i].life <= 0.0f) {
            part[i].alive = false;
            continue;
        }
        part[i].vy += PART_GRAVITY * m * dt;
        part[i].x += part[i].vx * m * dt;
        part[i].y += part[i].vy * m * dt;
        if (part[i].x < -8.0f || part[i].x > (float)GetScreenWidth() + 8.0f) {
            part[i].alive = false;
            continue;
        }
        if (part[i].y >= ground_at(part[i].x)) part[i].alive = false; // landed
    }
}

// Obsidian sinks below the surface over time (dense rock in soft snow).
static void obsidian_update(float dt) {
    float sh = (float)GetScreenHeight();
    for (int i = 0; i < OBSIDIAN_MAX; i++) {
        if (!obsidian[i].alive) continue;
        // Sink toward ground line + a bit under the pile surface.
        float target = ground_at(obsidian[i].x) + METEOR_RADIUS * 0.65f;
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
    // --no-snow: start with zero flakes (spawn still ramps in when toggled on).
    snow_active = snow_spawning ? 1 : 0;
    if (snow_spawning) snow_place_at_top(0);
    for (int i = snow_active; i < SNOW_COUNT; i++) {
        snow[i].x = 0;
        snow[i].y = -100000.0f; // dormant far offscreen
        snow[i].speed = 0;
        snow[i].size = 1;
        snow[i].drift = 0;
        snow[i].phase = 0;
        snow[i].tint = snow_pick_tint();
    }

    for (int i = 0; i < METEOR_MAX; i++) meteor[i].alive = false;
    for (int i = 0; i < OBSIDIAN_MAX; i++) obsidian[i].alive = false;
    for (int i = 0; i < PART_MAX; i++) part[i].alive = false;
}

static void snow_update(float dt) {
    int sw = GetScreenWidth();
    int sh = GetScreenHeight();

    // Wind gusts: rare ramps of horizontal force; ~500ms in, ~3s ease-out.
    if (wind_allow > 0.0f) {
        wind_gap -= dt;
        if (wind_gap <= 0.0f) {
            if (wind_target == 0.0f) {
                float mag = 30.0f + (float)GetRandomValue(0, 50);
                wind_target = (GetRandomValue(0, 1) ? mag : -mag) * wind_allow;
                wind_gap = 12.5f + (float)GetRandomValue(0, 40) / 10.0f;
                wind_phase = 0.0f;
            } else {
                wind_gap = 14.0f + (float)GetRandomValue(0, 50) / 10.0f;
            }
        }
        if (wind_target != 0.0f) {
            wind_phase += dt;
            // Envelope after ramp: hold, then fall (~3.5s total life).
            if (wind_phase > 3.5f) {
                wind_target = 0.0f;
            }
        }
        // Ease wind_x → wind_target: ~500ms ramp up, ~3s ease-out to calm.
        if (wind_x != wind_target) {
            float tau = (wind_target == 0.0f) ? 0.9f : 0.18f;
            float k = 1.0f - expf(-dt / tau);
            wind_x += (wind_target - wind_x) * k;
            if (fabsf(wind_x - wind_target) < 1.0f) wind_x = wind_target;
            if (wind_target == 0.0f && fabsf(wind_x) < 2.0f) {
                wind_x = 0.0f;
                wind_phase = 0.0f;
                wind_gap = 15.0f + (float)GetRandomValue(0, 80) / 10.0f;
            }
        }
    } else {
        wind_x = 0.0f;
        wind_target = 0.0f;
    }

    // Ramp-in: activate one more flake per interval until the limit.
    if (snow_spawning) {
        snow_spawn_timer += dt * snow_speed_mult;
        if (snow_active < SNOW_COUNT && snow_spawn_timer >= snow_spawn_interval) {
            snow_spawn_timer -= snow_spawn_interval;
            if (snow_spawn_timer > snow_spawn_interval) snow_spawn_timer = 0;
            snow_place_at_top(snow_active);
            snow_active++;
        }
    }

    for (int i = 0; i < snow_active; i++) {
        snow[i].phase += dt * snow_speed_mult;
        snow[i].y += snow[i].speed * snow_speed_mult * dt;
        snow[i].x += (snow[i].drift * sinf(snow[i].phase) + wind_x * snow[i].size) * dt;
        if (snow[i].x < 0) snow[i].x += sw;
        if (snow[i].x > sw) snow[i].x -= sw;

        // Landed: deposit a visible amount of tinted snow, then respawn
        // (or park dormant if spawn is off — Ctrl+S / --no-snow).
        if (snow[i].y >= ground_at(snow[i].x)) {
            // size 1..4 -> 3..48 height units so big flakes build the pile.
            float deposit = snow[i].size * snow[i].size * 3.0f;
            pile_add((int)snow[i].x, deposit, snow[i].tint);
            if (snow_spawning) {
                snow[i].y = -(float)GetRandomValue(1, sh);
                snow[i].x = (float)GetRandomValue(0, sw);
                snow[i].tint = snow_pick_tint();
                // Occasional meteor instead of a plain respawn.
                if (meteors_enabled && GetRandomValue(1, METEOR_SPAWN_DENOM) == 1)
                    meteor_spawn(snow[i].x);
            } else {
                snow_active--;
                if (i != snow_active) snow[i] = snow[snow_active];
                snow[snow_active].y = -100000.0f;
                snow[snow_active].speed = 0;
            }
        }
    }

    meteor_update(dt);
    parts_update(dt);
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
        DrawCircleV((Vector2){ obsidian[i].x, obsidian[i].y }, METEOR_RADIUS * 0.85f,
                    (Color){ 48, 16, 64, 255 }); // dark purple core
        DrawCircleLines((int)obsidian[i].x, (int)obsidian[i].y,
                        (int)(METEOR_RADIUS * 0.85f), obsidian[i].shell);
        DrawCircleLines((int)obsidian[i].x, (int)obsidian[i].y,
                        (int)(METEOR_RADIUS * 0.85f) - 1, obsidian[i].shell);
    }

    // Falling snow (only ramped-in flakes)
    for (int i = 0; i < snow_active; i++) {
        Color c = snow[i].tint;
        int a = 200 + (int)snow[i].size * 13;
        if (a > 255) a = 255;
        c.a = (unsigned char)a;
        DrawCircleV((Vector2){ snow[i].x, snow[i].y }, snow[i].size, c);
    }

    // Meteors: comet-style trail, then the hot glow body
    for (int i = 0; i < METEOR_MAX; i++) {
        if (!meteor[i].alive) continue;
        for (int k = METEOR_TRAIL - 1; k >= 0; k--) {
            float t = 1.0f - (float)k / (float)METEOR_TRAIL; // 1 at the head
            Color c = { 255, 150, 60, (unsigned char)(30.0f + 90.0f * t) };
            float r = METEOR_RADIUS * (0.30f + 0.70f * t);
            DrawCircleV((Vector2){ meteor[i].trail_x[k], meteor[i].trail_y[k] }, r, c);
        }
        DrawCircleV((Vector2){ meteor[i].x, meteor[i].y }, METEOR_RADIUS + 3.0f,
                    (Color){ 255, 80, 0, 50 });
        DrawCircleV((Vector2){ meteor[i].x, meteor[i].y }, METEOR_RADIUS,
                    (Color){ 255, 120, 20, 255 });
        DrawCircleV((Vector2){ meteor[i].x, meteor[i].y }, METEOR_RADIUS * 0.45f,
                    (Color){ 255, 220, 80, 255 });
    }

    // Impact debris on top: sparks + snow chunks (gravity in parts_update)
    for (int i = 0; i < PART_MAX; i++) {
        if (!part[i].alive) continue;
        float t = part[i].life / part[i].max_life;
        if (t < 0.0f) t = 0.0f;
        if (t > 1.0f) t = 1.0f;
        Color c = part[i].col;
        c.a = (unsigned char)(255.0f * t);
        DrawCircleV((Vector2){ part[i].x, part[i].y }, part[i].size, c);
    }
}

// --- DVD logo bounce (Ctrl+V / --dvd) ---
// Off by default. Corner aim (mid-flight, not on bounce): if the line the
// logo is already flying on passes within DVD_AIM_TOL of a corner it is
// heading *toward*, rotate onto it so the arrival is exact — both clamps fire
// in one frame = corner hit. Only corners ahead in both axes count, so a
// bounce off the left wall can never aim at top-left/bottom-left: that snap
// pointed back into the wall just left and rode the edge into the corner
// (looks wrong). The correction is made at the start of a flight segment,
// where it is at most atan(TOL / distance) — a couple of degrees, invisible.
// Every heading, seed/bounce/jitter/aim alike, stays >= DVD_MIN_DEG off both
// axes (an aim that would skim a wall is skipped instead). Collision box ==
// drawn rect.
#define DVD_AIM_TOL 96.0f
#define DVD_SPEED   364.0f  // 280 * 1.3
#define DVD_HALF_W  87.0f   // target visual half-width (px)
#define DVD_MIN_DEG 25.0f   // min degrees off the horizontal AND vertical axis

static float dvd_speed_mult = 1.0f; // --dvd-speed=N (independent of snow)
static bool dvd_enabled = false;
static bool dvd_inited = false;
static Vector2 dvd_pos = {0};
static Vector2 dvd_vel = {0};
static float dvd_hw = DVD_HALF_W; // half-width  (collision == draw)
static float dvd_hh = 38.0f;      // half-height (from texture aspect)
static Color dvd_color = {255, 40, 40, 255};
// Edge trigger: true after the logo hits a corner. Clear after you consume it.
static bool dvd_corner_hit = false;
static Texture2D dvd_tex = {0};
static bool dvd_tex_ready = false;

// Sync collision half-extents to the drawn texture rect.
static void dvd_sync_size(void) {
    dvd_hw = DVD_HALF_W;
    if (dvd_tex_ready && dvd_tex.width > 0 && dvd_tex.height > 0)
        dvd_hh = dvd_hw * (float)dvd_tex.height / (float)dvd_tex.width;
    else
        dvd_hh = dvd_hw * 226.0f / 512.0f;
    if (dvd_hh < 1.0f) dvd_hh = 1.0f;
}

// Load once after InitWindow (GL on main). White PNG × dvd_color = tinted mark.
static void dvd_tex_load(void) {
    if (dvd_tex_ready) return;
    Image img = LoadImageFromMemory(".png", dvd_logo_png, (int)dvd_logo_png_len);
    if (img.data) {
        dvd_tex = LoadTextureFromImage(img);
        UnloadImage(img);
        SetTextureFilter(dvd_tex, TEXTURE_FILTER_BILINEAR);
        dvd_tex_ready = (dvd_tex.id > 0);
    }
    dvd_sync_size();
}

static void dvd_tex_unload(void) {
    if (dvd_tex_ready) {
        UnloadTexture(dvd_tex);
        dvd_tex = (Texture2D){0};
        dvd_tex_ready = false;
    }
    dvd_sync_size();
}

static void dvd_toggle(void) {
    dvd_enabled = !dvd_enabled;
    dvd_inited = false; // re-seed on next update
}

// Position of a heading inside the 90° cycle of the axes: 0 = exactly on an
// axis (horizontal/vertical), 0..90 otherwise. Shared by the two rules below.
static float dvd_axis_phase(float ang) {
    float d = fmodf(ang * RAD2DEG, 90.0f);
    if (d < 0.0f) d += 90.0f;
    return d;
}

// True when a heading keeps at least DVD_MIN_DEG away from BOTH axes.
static bool dvd_clear_of_axes(float ang) {
    float d = dvd_axis_phase(ang);
    return d >= DVD_MIN_DEG && d <= 90.0f - DVD_MIN_DEG;
}

// Rotate a heading out of the narrow band around both axes: the result is
// always >= DVD_MIN_DEG from horizontal AND vertical, so the logo can never
// travel nearly parallel to an edge. Speed and quadrant are preserved.
static float dvd_keep_off_axes(float ang) {
    float d = dvd_axis_phase(ang);
    float fix = 0.0f;
    if (d < DVD_MIN_DEG)
        fix = DVD_MIN_DEG - d;
    else if (d > 90.0f - DVD_MIN_DEG)
        fix = (90.0f - DVD_MIN_DEG) - d;
    return ang + fix * DEG2RAD;
}

static void dvd_seed(int sw, int sh) {
    dvd_sync_size();
    int mx = (int)dvd_hw + 8;
    int my = (int)dvd_hh + 8;
    dvd_pos.x = (float)GetRandomValue(mx, sw > mx + 64 ? sw - mx - 8 : mx + 16);
    dvd_pos.y = (float)GetRandomValue(my, sh > my + 64 ? sh - my - 8 : my + 16);
    // Both components nonzero so we always bounce.
    float ang = ((float)GetRandomValue(20, 70)) * (DEG2RAD);
    int quad = GetRandomValue(0, 3);
    float sx = (quad == 0 || quad == 3) ? 1.0f : -1.0f;
    float sy = (quad < 2) ? 1.0f : -1.0f;
    ang = dvd_keep_off_axes(atan2f(sinf(ang) * sy, cosf(ang) * sx));
    dvd_vel.x = cosf(ang) * DVD_SPEED;
    dvd_vel.y = sinf(ang) * DVD_SPEED;
    static const Color palette[] = {
        { 230, 40, 40, 255 },
        { 40, 200, 70, 255 },
        { 50, 120, 255, 255 },
        { 250, 200, 40, 255 },
        { 220, 60, 200, 255 },
    };
    dvd_color = palette[GetRandomValue(0, 4)];
    dvd_inited = true;
}

// Mid-flight corner approach: the current flight line already passes close to
// a corner the logo is flying toward — rotate onto that exact line so it
// arrives in the corner (both clamps in one frame = the corner hit).
// Candidates must be ahead in BOTH axes (dx*vx and dy*vy positive): after a
// left-wall bounce vx points right, so top-left/bottom-left are behind us and
// can never be chosen — no aiming back into the wall just left, no riding the
// edge. The perpendicular miss decides how far off the line we are, so the
// snap happens as early in the segment as possible and costs only a few
// degrees. A corner whose exact direction would skim an edge is skipped: we
// would rather miss it than travel nearly parallel to a wall for half a
// screen.
static bool dvd_aim_corner_path(int sw, int sh) {
    float speed = sqrtf(dvd_vel.x * dvd_vel.x + dvd_vel.y * dvd_vel.y);
    if (speed < 1.0f) return false;
    // Inner corners: where the AABB center rests (half-extent inset).
    Vector2 corners[4] = {
        { dvd_hw, dvd_hh },
        { (float)sw - dvd_hw, dvd_hh },
        { dvd_hw, (float)sh - dvd_hh },
        { (float)sw - dvd_hw, (float)sh - dvd_hh },
    };
    float best_miss = 0.0f;
    int best_i = -1;
    for (int i = 0; i < 4; i++) {
        float dx = corners[i].x - dvd_pos.x;
        float dy = corners[i].y - dvd_pos.y;
        if (dx * dvd_vel.x <= 0.0f || dy * dvd_vel.y <= 0.0f) continue; // behind us
        float miss = fabsf(dx * dvd_vel.y - dy * dvd_vel.x) / speed; // dist(corner, line)
        if (miss > DVD_AIM_TOL) continue;
        if (best_i >= 0 && miss >= best_miss) continue; // keep the closest line
        if (!dvd_clear_of_axes(atan2f(dy, dx))) continue;
        best_miss = miss;
        best_i = i;
    }
    if (best_i < 0) return false;
    Vector2 c = corners[best_i];
    float dx = c.x - dvd_pos.x;
    float dy = c.y - dvd_pos.y;
    float len = sqrtf(dx * dx + dy * dy);
    if (len < 1e-3f) return false; // already on it — clamps take over
    float ang = atan2f(dy, dx);
    dvd_vel.x = cosf(ang) * speed;
    dvd_vel.y = sinf(ang) * speed;
    return true;
}

// Wall bounce: reflect, then scatter the heading so paths don’t repeat.
// Keeps speed; random rotate 0..20°, then push back inside the safe band so
// the result can never run nearly parallel to an edge.
static void dvd_bounce_jitter(void) {
    float speed = sqrtf(dvd_vel.x * dvd_vel.x + dvd_vel.y * dvd_vel.y);
    if (speed < 1.0f) speed = DVD_SPEED;
    float ang = atan2f(dvd_vel.y, dvd_vel.x);
    float jitter_deg = (float)GetRandomValue(0, 20);
    if (GetRandomValue(0, 1)) jitter_deg = -jitter_deg;
    ang = dvd_keep_off_axes(ang + jitter_deg * DEG2RAD);
    dvd_vel.x = cosf(ang) * speed;
    dvd_vel.y = sinf(ang) * speed;
}

static void dvd_update(float dt) {
    if (!dvd_enabled) return;
    int sw = GetScreenWidth();
    int sh = GetScreenHeight();
    if (sw < 32 || sh < 32) return;
    if (!dvd_inited) dvd_seed(sw, sh);
    dvd_sync_size(); // texture may load later

    float step = dt * dvd_speed_mult;
    dvd_pos.x += dvd_vel.x * step;
    dvd_pos.y += dvd_vel.y * step;

    bool hit_x = false, hit_y = false;
    if (dvd_pos.x - dvd_hw < 0.0f) {
        dvd_pos.x = dvd_hw;
        dvd_vel.x = fabsf(dvd_vel.x);
        hit_x = true;
    } else if (dvd_pos.x + dvd_hw > (float)sw) {
        dvd_pos.x = (float)sw - dvd_hw;
        dvd_vel.x = -fabsf(dvd_vel.x);
        hit_x = true;
    }
    if (dvd_pos.y - dvd_hh < 0.0f) {
        dvd_pos.y = dvd_hh;
        dvd_vel.y = fabsf(dvd_vel.y);
        hit_y = true;
    } else if (dvd_pos.y + dvd_hh > (float)sh) {
        dvd_pos.y = (float)sh - dvd_hh;
        dvd_vel.y = -fabsf(dvd_vel.y);
        hit_y = true;
    }
    // Nothing hit: fly. This is also where the corner aim runs — it must be
    // mid-flight, not on the bounce, so it can only ever pick a corner the
    // logo is heading toward (a bounce-time aim always sat on a wall and
    // pointed back into it).
    if (!hit_x && !hit_y) {
        dvd_aim_corner_path(sw, sh);
        return;
    }

    // Both walls in one frame = corner hit. Bounce out (vels already flipped
    // away from the walls), raise the edge trigger, don't re-aim into it.
    if (hit_x && hit_y) {
        dvd_corner_hit = true;
        dvd_bounce_jitter();
        return;
    }
    dvd_bounce_jitter();
}

static void dvd_draw(void) {
    if (!dvd_enabled || !dvd_inited) return;
    // Same rect as collision AABB (dvd_sync_size keeps them in lockstep).
    if (!dvd_tex_ready) dvd_tex_load();
    if (!dvd_tex_ready) return;

    Rectangle src = { 0, 0, (float)dvd_tex.width, (float)dvd_tex.height };
    Rectangle dst = {
        dvd_pos.x - dvd_hw, dvd_pos.y - dvd_hh,
        dvd_hw * 2.0f, dvd_hh * 2.0f,
    };
    DrawTexturePro(dvd_tex, src, dst, (Vector2){ 0, 0 }, 0.0f, dvd_color);
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

// PAM on a worker thread — a bad password must not freeze snow/DVD/weather.
// Main only posts the password and polls; GL stays on main.
#define AUTH_PASS_MAX 256
static pthread_mutex_t auth_mu = PTHREAD_MUTEX_INITIALIZER;
static char auth_pass[AUTH_PASS_MAX];
static bool auth_busy = false;
static bool auth_done = false;
static bool auth_ok = false;

static void *auth_thread(void *arg) {
    (void)arg;
    bool ok = authenticate(auth_pass);
    pthread_mutex_lock(&auth_mu);
    auth_ok = ok;
    auth_done = true;
    auth_busy = false;
    memset(auth_pass, 0, sizeof(auth_pass));
    pthread_mutex_unlock(&auth_mu);
    return NULL;
}

// Returns false if an attempt is already in flight.
static bool auth_start(const char *password) {
    pthread_mutex_lock(&auth_mu);
    if (auth_busy) {
        pthread_mutex_unlock(&auth_mu);
        return false;
    }
    auth_busy = true;
    auth_done = false;
    auth_ok = false;
    snprintf(auth_pass, sizeof(auth_pass), "%s", password);
    pthread_mutex_unlock(&auth_mu);

    pthread_t thr;
    if (pthread_create(&thr, NULL, auth_thread, NULL) != 0) {
        pthread_mutex_lock(&auth_mu);
        auth_busy = false;
        memset(auth_pass, 0, sizeof(auth_pass));
        pthread_mutex_unlock(&auth_mu);
        return false;
    }
    pthread_detach(thr);
    return true;
}

// Non-blocking: true once an attempt finishes; *ok is the PAM result.
static bool auth_poll(bool *ok) {
    pthread_mutex_lock(&auth_mu);
    if (!auth_done) {
        pthread_mutex_unlock(&auth_mu);
        return false;
    }
    auth_done = false;
    if (ok) *ok = auth_ok;
    pthread_mutex_unlock(&auth_mu);
    return true;
}

// --- Desktop snapshot background ---
// Capture full-res on CPU BEFORE InitWindow (fullscreen would hide it).
// CPU blur/darken runs on a worker thread so snow keeps animating; the main
// thread only swaps in the finished texture (GL must stay on main).
//
// blur==0: full-res original (darken still applied).
// blur>0:  downscale budget → 3× box → darken. darken is absolute 0..255
//          (0 = none, 255 = pitch black).
static Texture2D bg_tex = {0};
static Image bg_full = {0};   // native-res capture, never mutated after init
static Image bg_mid = {0};    // ≤960-wide cache for blur>0 (built before worker)
static bool bg_ready = false;
static int bg_blur = 5;     // -b / -b=N; clamped to [bg_blur_min, 64]
static int bg_blur_min = 5; // --min-blur=N (floor for -b and live keys)
static int bg_darken = 160; // -d / -d=N absolute 0..255 (0=none, 255=black)

static pthread_mutex_t bg_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t bg_cv = PTHREAD_COND_INITIALIZER;
static int bg_req_blur = 5;
static int bg_req_darken = 160;
static bool bg_dirty = false;
static Image bg_done = {0};
static bool bg_done_ready = false;
static pthread_t bg_thr;
static bool bg_thr_started = false;
static bool bg_shutdown = false;

static int clamp_darken(int v) {
    if (v < 0) v = 0;
    if (v > 255) v = 255;
    return v;
}

// Absolute darken: 0 = no change, 255 = pitch black.
// Hash dither breaks up 8-bit banding on smooth mid-tones.
static void bg_darken_dither(Image *img, int darken_val) {
    if (!img || !img->data) return;
    int w = img->width, h = img->height;
    if (w < 1 || h < 1) return;
    if (darken_val <= 0) return;

    unsigned char *px = (unsigned char *)img->data;
    if (darken_val >= 255) {
        for (size_t i = 0; i < (size_t)w * (size_t)h; i++) {
            px[i * 4 + 0] = 0;
            px[i * 4 + 1] = 0;
            px[i * 4 + 2] = 0;
            px[i * 4 + 3] = 255;
        }
        return;
    }

    float factor = 1.0f - ((float)darken_val / 255.0f);
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            size_t o = ((size_t)y * (size_t)w + (size_t)x) * 4;
            float r = (float)px[o + 0] * factor;
            float g = (float)px[o + 1] * factor;
            float b = (float)px[o + 2] * factor;
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
            px[o + 0] = (unsigned char)(r + 0.5f);
            px[o + 1] = (unsigned char)(g + 0.5f);
            px[o + 2] = (unsigned char)(b + 0.5f);
            px[o + 3] = 255;
        }
    }
}

// One separable box pass with edge-clamped window. half ≤16 after the
// rebuild downscale budget, so the O(half) inner loop stays cheap.
static void box_pass(unsigned char *dst, const unsigned char *src,
                     int w, int h, int half, bool horizontal) {
    if (half <= 0) return;
    int line = horizontal ? w : h;
    int lines = horizontal ? h : w;
    int span = half * 2 + 1;

    for (int li = 0; li < lines; li++) {
        for (int i = 0; i < line; i++) {
            float sr = 0, sg = 0, sb = 0;
            for (int t = -half; t <= half; t++) {
                int p = i + t;
                if (p < 0) p = 0;
                if (p >= line) p = line - 1;
                int x, y;
                if (horizontal) { x = p; y = li; }
                else            { x = li; y = p; }
                size_t o = ((size_t)y * (size_t)w + (size_t)x) * 4;
                sr += (float)src[o + 0];
                sg += (float)src[o + 1];
                sb += (float)src[o + 2];
            }
            sr /= (float)span;
            sg /= (float)span;
            sb /= (float)span;
            if (sr < 0) sr = 0;
            if (sr > 255) sr = 255;
            if (sg < 0) sg = 0;
            if (sg > 255) sg = 255;
            if (sb < 0) sb = 0;
            if (sb > 255) sb = 255;
            int x, y;
            if (horizontal) { x = i; y = li; }
            else            { x = li; y = i; }
            size_t o = ((size_t)y * (size_t)w + (size_t)x) * 4;
            dst[o + 0] = (unsigned char)(sr + 0.5f);
            dst[o + 1] = (unsigned char)(sg + 0.5f);
            dst[o + 2] = (unsigned char)(sb + 0.5f);
            dst[o + 3] = 255;
        }
    }
}

// 3× separable box ≈ Gaussian (CLT). half is box half-width in work pixels.
static void bg_box_blur(Image *img, int half) {
    if (!img || !img->data || half <= 0) return;
    int w = img->width, h = img->height;
    if (w < 1 || h < 1) return;
    if (half > 64) half = 64;

    size_t nbytes = (size_t)w * (size_t)h * 4;
    unsigned char *a = (unsigned char *)img->data;
    unsigned char *b = (unsigned char *)malloc(nbytes);
    unsigned char *c = (unsigned char *)malloc(nbytes);
    if (!b || !c) {
        free(b);
        free(c);
        return;
    }

    const int passes = 3;
    for (int p = 0; p < passes; p++) {
        box_pass(b, a, w, h, half, true);
        box_pass(c, b, w, h, half, false);
        memcpy(a, c, nbytes);
    }
    free(b);
    free(c);
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
// Full-res source of truth; blur path downscales a copy in the worker.
static void bg_capture(void) {
    Image img = capture_root_image();
    if (!img.data) return;
    if (bg_full.data) UnloadImage(bg_full);
    bg_full = img;
    if (bg_mid.data) {
        UnloadImage(bg_mid);
        bg_mid = (Image){0};
    }
}

// ≤960-wide cache for blur>0. Call only before the worker starts (or under bg_mu).
static void bg_ensure_mid(void) {
    if (!bg_full.data || bg_mid.data) return;
    if (bg_full.width <= 960) return;
    int nh = (int)((float)bg_full.height * (960.0f / (float)bg_full.width));
    if (nh < 1) nh = 1;
    Image mid = ImageCopy(bg_full);
    ImageResize(&mid, 960, nh);
    bg_mid = mid;
}

static Image bg_blur_source(void) {
    if (!bg_full.data) return (Image){0};
    if (bg_full.width <= 960) return ImageCopy(bg_full);
    if (bg_mid.data) return ImageCopy(bg_mid);
    // Fallback (should not hit after bg_ensure_mid): build mid on the fly.
    bg_ensure_mid();
    if (bg_mid.data) return ImageCopy(bg_mid);
    return ImageCopy(bg_full);
}

static int clamp_blur(int v) {
    if (v < bg_blur_min) v = bg_blur_min;
    if (v > 64) v = 64;
    return v;
}

// CPU-only: source → optional box blur → darken. Produces a finished image.
// Safe on the worker thread (no GL). Caller owns the returned Image.
static Image bg_process(int blur, int darken) {
    Image img;
    if (blur <= 0) {
        if (!bg_full.data) return (Image){0};
        img = ImageCopy(bg_full);
    } else {
        img = bg_blur_source();
        if (!img.data) return (Image){0};
        int r = blur;
        int div = 1;
        if (r > 32) div = 4;
        else if (r > 16) div = 2;
        if (div > 1 && img.width >= div * 2) {
            int nw = img.width / div;
            int nh = img.height / div;
            if (nw < 1) nw = 1;
            if (nh < 1) nh = 1;
            ImageResize(&img, nw, nh);
        }
        int half = r / div;
        if (half < 1) half = 1;
        bg_box_blur(&img, half);
    }
    bg_darken_dither(&img, darken);
    return img;
}

// Synchronous rebuild — used once after InitWindow for the first frame.
static bool bg_rebuild_sync(void) {
    bg_blur = clamp_blur(bg_blur);
    bg_darken = clamp_darken(bg_darken);
    bg_ensure_mid();

    Image img = bg_process(bg_blur, bg_darken);
    if (!img.data) return false;

    if (bg_ready) {
        UnloadTexture(bg_tex);
        bg_ready = false;
    }
    bg_tex = LoadTextureFromImage(img);
    UnloadImage(img);
    if (bg_tex.id <= 0) {
        fprintf(stderr, "[memelock] bg: texture upload failed\n");
        return false;
    }
    bg_ready = true;
    SetTextureFilter(bg_tex, TEXTURE_FILTER_BILINEAR);
    fprintf(stderr, "[memelock] bg: texture id=%u %dx%d blur=%d darken=%d\n",
            bg_tex.id, bg_tex.width, bg_tex.height, bg_blur, bg_darken);
    return true;
}

static void *bg_thread(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&bg_mu);
        while (!bg_dirty && !bg_shutdown)
            pthread_cond_wait(&bg_cv, &bg_mu);
        if (bg_shutdown) {
            pthread_mutex_unlock(&bg_mu);
            break;
        }
        int blur = bg_req_blur;
        int darken = bg_req_darken;
        bg_dirty = false;
        pthread_mutex_unlock(&bg_mu);

        Image img = bg_process(blur, darken);

        pthread_mutex_lock(&bg_mu);
        if (bg_shutdown) {
            pthread_mutex_unlock(&bg_mu);
            if (img.data) UnloadImage(img);
            break;
        }
        // Coalesce: if a newer request arrived while we worked, drop this
        // result and loop — main still shows the previous texture.
        if (bg_dirty) {
            pthread_mutex_unlock(&bg_mu);
            if (img.data) UnloadImage(img);
            continue;
        }
        if (bg_done.data) UnloadImage(bg_done);
        bg_done = img;
        bg_done_ready = img.data != NULL;
        pthread_mutex_unlock(&bg_mu);
    }
    return NULL;
}

static void bg_worker_start(void) {
    if (bg_thr_started) return;
    pthread_mutex_lock(&bg_mu);
    bg_shutdown = false;
    bg_req_blur = clamp_blur(bg_blur);
    bg_req_darken = clamp_darken(bg_darken);
    bg_dirty = false;
    pthread_mutex_unlock(&bg_mu);
    bg_thr_started = (pthread_create(&bg_thr, NULL, bg_thread, NULL) == 0);
    if (!bg_thr_started)
        fprintf(stderr, "[memelock] bg: thread create failed\n");
}

static void bg_worker_stop(void) {
    if (!bg_thr_started) return;
    pthread_mutex_lock(&bg_mu);
    bg_shutdown = true;
    pthread_cond_signal(&bg_cv);
    pthread_mutex_unlock(&bg_mu);
    pthread_join(bg_thr, NULL);
    bg_thr_started = false;
    pthread_mutex_lock(&bg_mu);
    if (bg_done.data) {
        UnloadImage(bg_done);
        bg_done = (Image){0};
    }
    bg_done_ready = false;
    pthread_mutex_unlock(&bg_mu);
}

// Main thread only: swap in a finished worker image if one is ready.
static void bg_poll_upload(void) {
    Image img = {0};
    pthread_mutex_lock(&bg_mu);
    if (bg_done_ready && bg_done.data) {
        img = bg_done;
        bg_done = (Image){0};
        bg_done_ready = false;
    }
    pthread_mutex_unlock(&bg_mu);
    if (!img.data) return;

    Texture2D old = bg_tex;
    bool had_old = bg_ready;
    bg_tex = LoadTextureFromImage(img);
    UnloadImage(img);
    if (bg_tex.id <= 0) {
        fprintf(stderr, "[memelock] bg: texture upload failed\n");
        if (had_old) bg_tex = old; // keep drawing previous
        return;
    }
    bg_ready = true;
    SetTextureFilter(bg_tex, TEXTURE_FILTER_BILINEAR);
    if (had_old && old.id > 0) UnloadTexture(old);
    fprintf(stderr, "[memelock] bg: texture id=%u %dx%d blur=%d darken=%d\n",
            bg_tex.id, bg_tex.width, bg_tex.height, bg_blur, bg_darken);
}

// Live setters: update desired params and wake the worker (non-blocking).
static void bg_set_blur(int v) {
    v = clamp_blur(v);
    bg_blur = v;
    if (!bg_thr_started) {
        bg_rebuild_sync();
        return;
    }
    pthread_mutex_lock(&bg_mu);
    bg_req_blur = v;
    bg_dirty = true;
    pthread_cond_signal(&bg_cv);
    pthread_mutex_unlock(&bg_mu);
}

static void bg_set_darken(int v) {
    v = clamp_darken(v);
    bg_darken = v;
    if (!bg_thr_started) {
        bg_rebuild_sync();
        return;
    }
    pthread_mutex_lock(&bg_mu);
    bg_req_darken = v;
    bg_dirty = true;
    pthread_cond_signal(&bg_cv);
    pthread_mutex_unlock(&bg_mu);
}

static void blur_step(int delta) { bg_set_blur(bg_blur + delta); }
static void darken_step(int delta) { bg_set_darken(bg_darken + delta); }

static void blur_field_commit(const char *text) {
    if (text && text[0]) bg_set_blur(atoi(text));
}

static void blur_field_open(void) {
    char init[16];
    snprintf(init, sizeof(init), "%d", bg_blur);
    prompt_open_with("blur", init, true, false, blur_field_commit);
}

// Ctrl+H: raise the --min-blur floor (one step). No decrease bind on purpose —
// while locked the floor only tightens; lift current blur with it if below.
static void min_blur_inc(void) {
    if (bg_blur_min >= 64) return;
    bg_blur_min++;
    if (bg_blur < bg_blur_min) bg_set_blur(bg_blur_min);
}

static void darken_field_commit(const char *text) {
    if (text && text[0]) bg_set_darken(atoi(text));
}

static void darken_field_open(void) {
    char init[16];
    snprintf(init, sizeof(init), "%d", bg_darken);
    // Absolute 0..255 — digits only, no sign.
    prompt_open_with("darken", init, true, false, darken_field_commit);
}

static void bg_draw(int sw, int sh) {
    if (!bg_ready) return;
    DrawTexturePro(bg_tex,
                   (Rectangle){ 0, 0, (float)bg_tex.width, (float)bg_tex.height },
                   (Rectangle){ 0, 0, (float)sw, (float)sh },
                   (Vector2){ 0, 0 }, 0.0f, WHITE);
}

static void bg_unload(void) {
    bg_worker_stop();
    if (bg_ready) {
        UnloadTexture(bg_tex);
        bg_ready = false;
    }
    if (bg_full.data) {
        UnloadImage(bg_full);
        bg_full = (Image){0};
    }
    if (bg_mid.data) {
        UnloadImage(bg_mid);
        bg_mid = (Image){0};
    }
}

// Top-left modular field (weather is bottom-left). Same box style as password.
static void prompt_draw(void) {
    if (!prompt_open) return;
    const int ui_pad = 14;
    const int text_size = 36;
    const int margin = 16;
    const Color ui_bg = { 10, 12, 18, 190 };
    char line[160];
    snprintf(line, sizeof(line), "%s: %s", prompt_label, prompt_buf);
    int tw = MeasureText(line, text_size);
    DrawRectangle(margin, margin, tw + ui_pad * 2, text_size + ui_pad * 2, ui_bg);
    DrawText(line, margin + ui_pad, margin + ui_pad, text_size, WHITE);
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
    // First slot = the CURRENT hour, from the wall clock in the payload's own
    // timezone (utc_offset_seconds). The old rule — hour-of-day taken from the
    // payload's current.time used directly as an array index — pinned the block
    // to the hour a stale cache was fetched (5am rows all day).
    int utc_off = 0;
    if (json_object_object_get_ex(root, "utc_offset_seconds", &o))
        utc_off = json_object_get_int(o);
    time_t now = time(NULL) + utc_off;
    struct tm tmv;
    gmtime_r(&now, &tmv);
    char want[64];
    snprintf(want, sizeof(want), "%04d-%02d-%02dT%02d:00",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour);

    int idx = -1;
    if (h_time) {
        for (int j = 0; j < n; j++) {
            json_object *tj = json_object_array_get_idx(h_time, j);
            const char *ts = tj ? json_object_get_string(tj) : NULL;
            if (ts && strncmp(ts, want, 13) >= 0) { idx = j; break; }
        }
    }
    if (idx < 0) {
        // No entry at/after now (ancient cache): fall back to the payload's
        // own current hour, then clamp to the tail of the array.
        const char *ct = NULL;
        if (json_object_object_get_ex(cur, "time", &o)) ct = json_object_get_string(o);
        if (ct && strlen(ct) >= 13) idx = atoi(ct + 11);
    }
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
    if (ok) {
        // Age the payload by its file mtime. parse_forecast stamps last_ok
        // with "now", which would otherwise keep a stale cache on screen for
        // a full W_REFRESH_SEC after startup — force an immediate fetch.
        struct stat st;
        if (stat(path, &st) == 0 && difftime(time(NULL), st.st_mtime) >= W_REFRESH_SEC) {
            pthread_mutex_lock(&weather_mu);
            weather.last_ok = 0.0; // thread treats 0 as "due now"
            pthread_mutex_unlock(&weather_mu);
        }
    }
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
    // curl_global_init is done once in main; font is loaded in main too.
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
    if (weather_enabled) {
        pthread_mutex_lock(&weather_mu);
        weather_shutdown = true;
        pthread_mutex_unlock(&weather_mu);
        if (weather_thr_started) {
            pthread_join(weather_thr, NULL);
            weather_thr_started = false;
        }
    }
    if (weather_font_owned && weather_font.texture.id > 0) {
        UnloadFont(weather_font);
        weather_font = (Font){0};
        weather_font_owned = false;
    }
}

// Widget font: humanist sans with Latin-1 + punctuation (clock “:”, quotes).
static void weather_load_font(void) {
    // Glyphs beyond ASCII: middle-dot, curly quotes, dashes, ellipsis, etc.
    static int codepoints[512];
    static int n_cp = 0;
    if (n_cp == 0) {
        int n = 0;
        for (int cp = 0x20; cp <= 0x7E && n < 512; cp++) codepoints[n++] = cp;
        for (int cp = 0xA0; cp <= 0xFF && n < 512; cp++) codepoints[n++] = cp;
        static const int extra[] = {
            0x2013, 0x2014, 0x2018, 0x2019, 0x201C, 0x201D,
            0x2026, 0x2022, 0x2192, 0x00B7, 0x2212, 0
        };
        for (int i = 0; extra[i] && n < 512; i++) codepoints[n++] = extra[i];
        n_cp = n;
    }

    const char *cands[] = {
        "/usr/share/fonts/Adwaita/AdwaitaSans-Regular.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/Ubuntu-R.ttf",
        "/usr/share/fonts/gnu-free/FreeSans.otf",
        NULL,
    };
    for (int i = 0; cands[i]; i++) {
        if (!FileExists(cands[i])) continue;
        Font f = LoadFontEx(cands[i], 96, codepoints, n_cp);
        if (f.texture.id > 0) {
            weather_font = f;
            weather_font_owned = true;
            SetTextureFilter(weather_font.texture, TEXTURE_FILTER_BILINEAR);
            fprintf(stderr, "[memelock] ui font: %s\n", cands[i]);
            return;
        }
    }
    fprintf(stderr, "[memelock] ui font: fallback default (limited glyphs)\n");
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

// --- Clock (top-center, no panel) ---
static bool clock_enabled = true; // --no-clock
static void quotes_draw(int sw, int y, int font); // defined below

static void clock_draw(int sw, int sh) {
    (void)sh;
    if (!clock_enabled) return;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);

    char hhmm[16];
    strftime(hhmm, sizeof(hhmm), "%H:%M", &tmv);

    const int F_TIME = 110;
    const int F_DATE = 28;
    const int F_QUOTE = 33; // ~+50% of previous 22

    int tw = w_measure(hhmm, F_TIME);
    int tx = (sw - tw) / 2;
    int ty = 36;
    Color c_time = { 235, 232, 240, 245 };
    w_draw(hhmm, tx, ty, F_TIME, c_time);

    static const char *mons[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    char iso[16];
    strftime(iso, sizeof(iso), "%Y-%m-%d", &tmv);
    char date[64];
    snprintf(date, sizeof(date), "%s · %s %d",
             day_name(iso), mons[tmv.tm_mon], tmv.tm_mday);
    int dw = w_measure(date, F_DATE);
    Color c_date = { 170, 175, 185, 220 };
    w_draw(date, (sw - dw) / 2, ty + F_TIME + 8, F_DATE, c_date);

    quotes_draw(sw, ty + F_TIME + 8 + F_DATE + 14, F_QUOTE);
}

// --- Quotes / sayings (DriveBird free API + local cache) ---
#define QUOTES_MAX 64
#define QUOTES_REFRESH_SEC 3600

static bool quotes_enabled = true; // --no-quotes
static bool quotes_visible = true;
static int quotes_idx = 0;
static int quotes_count = 0;
static char quotes_text[QUOTES_MAX][240];
static char quotes_auth[QUOTES_MAX][64];
static pthread_mutex_t quotes_mu = PTHREAD_MUTEX_INITIALIZER;
static bool quotes_shutdown = false;
static pthread_t quotes_thr;
static bool quotes_thr_started = false;
static double quotes_last_ok = 0;

// Offline only: real quotes + named authors (no "mule" / "proverb").
static const char *const quotes_builtin[][2] = {
    { "Nature does not hurry, yet everything is accomplished.", "Lao Tzu" },
    { "The quieter you become, the more you can hear.", "Rumi" },
    { "Almost everything will work again if you unplug it for a few minutes.", "Anne Lamott" },
    { "We cannot become what we want to be by remaining what we are.", "Max De Pree" },
    { "You miss 100% of the shots you don't take.", "Wayne Gretzky" },
    { "Do what you can, where you are, with what you have.", "Theodore Roosevelt" },
    { "Life is what happens to you while you're busy making other plans.", "John Lennon" },
    { "The only way to do great work is to love what you do.", "Steve Jobs" },
    { "Fall seven times, stand up eight.", "unknown" },
    { "It is not a lack of love, but a lack of friendship that makes unhappy marriages.", "Friedrich Nietzsche" },
    { "If you tell the truth, you don't have to remember anything.", "Mark Twain" },
    { "In the middle of difficulty lies opportunity.", "Albert Einstein" },
};

// Meta / placeholder authors → short muted label.
static void quotes_display_auth(const char *raw, char *out, size_t outn) {
    if (!raw || !raw[0]) {
        snprintf(out, outn, "unknown");
        return;
    }
    // lowercase copy for matching
    char lower[80];
    size_t j = 0;
    for (size_t i = 0; raw[i] && j + 1 < sizeof(lower); i++) {
        unsigned char c = (unsigned char)raw[i];
        lower[j++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
    lower[j] = '\0';

    static const char *const weak[] = {
        "mule", "memelock", "proverb", "proverbs", "saying", "sayings",
        "author unknown", "unknown", "anonymous", "anon", "various",
        "traditional", "unknown author", NULL
    };
    for (int i = 0; weak[i]; i++) {
        if (strcmp(lower, weak[i]) == 0) {
            snprintf(out, outn, "unknown");
            return;
        }
    }
    snprintf(out, outn, "%s", raw);
}

static void quotes_load_builtin(void) {
    pthread_mutex_lock(&quotes_mu);
    quotes_count = 0;
    for (size_t i = 0; i < sizeof(quotes_builtin) / sizeof(quotes_builtin[0]); i++) {
        snprintf(quotes_text[quotes_count], sizeof(quotes_text[0]), "%s",
                 quotes_builtin[i][0]);
        snprintf(quotes_auth[quotes_count], sizeof(quotes_auth[0]), "%s",
                 quotes_builtin[i][1]);
        quotes_count++;
    }
    if (quotes_count > 0) quotes_idx = GetRandomValue(0, quotes_count - 1);
    pthread_mutex_unlock(&quotes_mu);
}

static void quotes_cache_path(char *out, size_t n) {
    weather_cache_path(out, n, "quotes.json");
}

static void quotes_save_cache(const char *json_text) {
    char path[512];
    quotes_cache_path(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs(json_text, f);
    fclose(f);
}

// Parse shapes:
//   DriveBird:              [{id,quote,author}, …] (also {data:[…]})
//   ZenQuotes legacy cache: [{q,a}, …]
//   Quotable-style:         [{content,author}, …]
static bool quotes_parse(const char *json_text) {
    if (!json_text || !json_text[0]) return false;
    json_object *root = json_tokener_parse(json_text);
    if (!root) return false;

    // Unwrap common envelopes: {quotes:[…]} / {results:[…]} / {data:[…]}
    if (json_object_get_type(root) == json_type_object) {
        json_object *arr = NULL;
        static const char *keys[] = { "quotes", "results", "data", "items", NULL };
        for (int i = 0; keys[i]; i++) {
            if (json_object_object_get_ex(root, keys[i], &arr) &&
                json_object_get_type(arr) == json_type_array) {
                json_object_put(root);
                root = arr;
                json_object_get(root);
                break;
            }
        }
    }

    if (json_object_get_type(root) != json_type_array) {
        json_object_put(root);
        return false;
    }
    int n = (int)json_object_array_length(root);
    char tmp_text[QUOTES_MAX][240];
    char tmp_auth[QUOTES_MAX][64];
    int c = 0;
    for (int i = 0; i < n && c < QUOTES_MAX; i++) {
        json_object *item = json_object_array_get_idx(root, i);
        json_object *jq = NULL, *ja = NULL;
        const char *q = NULL, *a = NULL;
        if (json_object_object_get_ex(item, "q", &jq))
            q = json_object_get_string(jq);
        else if (json_object_object_get_ex(item, "content", &jq))
            q = json_object_get_string(jq);
        else if (json_object_object_get_ex(item, "quote", &jq))
            q = json_object_get_string(jq);
        else if (json_object_object_get_ex(item, "text", &jq))
            q = json_object_get_string(jq);
        else if (json_object_object_get_ex(item, "quoteText", &jq))
            q = json_object_get_string(jq);
        if (!q || !q[0]) continue;

        if (json_object_object_get_ex(item, "a", &ja))
            a = json_object_get_string(ja);
        else if (json_object_object_get_ex(item, "author", &ja))
            a = json_object_get_string(ja);
        else if (json_object_object_get_ex(item, "quoteAuthor", &ja))
            a = json_object_get_string(ja);
        else if (json_object_object_get_ex(item, "authorName", &ja))
            a = json_object_get_string(ja);

        char disp[64];
        quotes_display_auth(a, disp, sizeof(disp));
        snprintf(tmp_text[c], sizeof(tmp_text[0]), "%s", q);
        snprintf(tmp_auth[c], sizeof(tmp_auth[0]), "%s", disp);
        c++;
    }
    json_object_put(root);
    if (c <= 0) return false;

    pthread_mutex_lock(&quotes_mu);
    quotes_count = c;
    for (int i = 0; i < c; i++) {
        memcpy(quotes_text[i], tmp_text[i], sizeof(quotes_text[0]));
        memcpy(quotes_auth[i], tmp_auth[i], sizeof(quotes_auth[0]));
    }
    if (quotes_count > 0) quotes_idx = GetRandomValue(0, quotes_count - 1);
    pthread_mutex_unlock(&quotes_mu);
    return true;
}

static bool quotes_load_cache(void) {
    char path[512];
    quotes_cache_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 2 * 1024 * 1024) {
        fclose(f);
        return false;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return false;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    bool ok = quotes_parse(buf);
    free(buf);
    return ok;
}

static bool quotes_fetch(void) {
    // DriveBird free quotes API — no key, real named authors, batch up to 50.
    char *body = http_get("https://www.drivebird.com/api/quotes/random?count=50", 8);
    if (!body) return false;
    bool ok = quotes_parse(body);
    if (ok) {
        quotes_save_cache(body);
        quotes_last_ok = GetTime();
    }
    free(body);
    return ok;
}

static void *quotes_thread(void *arg) {
    (void)arg;
    bool boot = true;
    for (;;) {
        pthread_mutex_lock(&quotes_mu);
        bool down = quotes_shutdown;
        double last = quotes_last_ok;
        int cnt = quotes_count;
        pthread_mutex_unlock(&quotes_mu);
        if (down) break;

        bool due = cnt <= 0 || last <= 0.0 || (GetTime() - last) >= QUOTES_REFRESH_SEC;
        if (boot) {
            boot = false;
            if (cnt <= 0 && !quotes_load_cache()) {
                if (!quotes_fetch()) quotes_load_builtin();
            } else {
                quotes_last_ok = GetTime();
            }
        } else if (due) {
            if (!quotes_fetch() && cnt <= 0) quotes_load_builtin();
        }

        for (int i = 0; i < 50 && !quotes_shutdown; i++)
            usleep(20 * 1000);
    }
    return NULL;
}

static void quotes_next(void) {
    if (!quotes_enabled || !quotes_visible) return;
    pthread_mutex_lock(&quotes_mu);
    if (quotes_count > 0) {
        quotes_idx = (quotes_idx + 1) % quotes_count;
    }
    pthread_mutex_unlock(&quotes_mu);
}

// Word-wrap left-justified blockquote with a left bar (markdown style).
static void quotes_draw(int sw, int y, int font) {
    if (!quotes_enabled || !quotes_visible) return;

    char body[400];
    char raw_auth[80];
    char auth[80];
    pthread_mutex_lock(&quotes_mu);
    if (quotes_count <= 0) {
        pthread_mutex_unlock(&quotes_mu);
        return;
    }
    if (quotes_idx < 0 || quotes_idx >= quotes_count) quotes_idx = 0;
    snprintf(body, sizeof(body), "%.320s", quotes_text[quotes_idx]);
    snprintf(raw_auth, sizeof(raw_auth), "%.70s", quotes_auth[quotes_idx]);
    pthread_mutex_unlock(&quotes_mu);
    quotes_display_auth(raw_auth, auth, sizeof(auth));

    int max_w = 460; // cozy column → 2–3 lines (very short stays 1)
    if (max_w > sw / 2) max_w = sw / 2;
    if (max_w < 300) max_w = 300;
    const int line_h = font + 6;
    const int bar_w = 4;
    const int pad_l = 16;
    const int pad = 12;

    // Wrap body into up to 6 lines at spaces (narrow width).
    char lines[6][400];
    int nlines = 0;
    {
        const char *p = body;
        while (*p && nlines < 6) {
            // Skip leading spaces
            while (*p == ' ') p++;
            if (!*p) break;
            if (w_measure(p, font) <= max_w - pad_l - bar_w - 8) {
                snprintf(lines[nlines], sizeof(lines[0]), "%s", p);
                nlines++;
                break;
            }
            // Find last space that fits
            int take = 0;
            int last_sp = -1;
            while (p[take]) {
                int upto = take + 1;
                char tmp[400];
                if (upto >= (int)sizeof(tmp)) break;
                memcpy(tmp, p, (size_t)upto);
                tmp[upto] = '\0';
                if (w_measure(tmp, font) > max_w - pad_l - bar_w - 8) break;
                if (p[take] == ' ') last_sp = take;
                take++;
            }
            if (take <= 0) take = 1;
            int cut = (last_sp > 0) ? last_sp : take;
            snprintf(lines[nlines], sizeof(lines[0]), "%.*s", cut, p);
            nlines++;
            p += cut;
            while (*p == ' ') p++;
        }
    }

    int text_w = 0;
    for (int i = 0; i < nlines; i++) {
        int w = w_measure(lines[i], font);
        if (w > text_w) text_w = w;
    }
    int auth_size = font - 6;
    if (auth_size < 16) auth_size = 16;
    int aw = w_measure(auth, auth_size);
    if (aw > text_w) text_w = aw;

    int bw = pad_l + bar_w + 8 + text_w + pad;
    int bh = pad + nlines * line_h + 4 + auth_size + pad;
    int bx = (sw - bw) / 2;
    int by = y;

    const Color panel = { 10, 12, 18, 130 };
    const Color bar_c = { 140, 150, 175, 220 };
    Color c_q = { 200, 204, 214, 245 };
    Color c_a = { 150, 155, 168, 230 };

    DrawRectangle(bx, by, bw, bh, panel);
    DrawRectangle(bx + 8, by + pad, bar_w, bh - pad * 2, bar_c);

    int tx = bx + 8 + bar_w + 8;
    int ly = by + pad;
    for (int i = 0; i < nlines; i++) {
        w_draw(lines[i], tx, ly, font, c_q);
        ly += line_h;
    }
    ly += 2;
    w_draw(auth, tx, ly, auth_size, c_a);
}

static void quotes_start(void) {
    if (!quotes_enabled) return;
    if (quotes_count <= 0 && !quotes_load_cache()) quotes_load_builtin();
    // Random pick every startup (even if cache already had a list).
    pthread_mutex_lock(&quotes_mu);
    if (quotes_count > 0) quotes_idx = GetRandomValue(0, quotes_count - 1);
    pthread_mutex_unlock(&quotes_mu);
    quotes_thr_started = (pthread_create(&quotes_thr, NULL, quotes_thread, NULL) == 0);
}

static void quotes_stop(void) {
    if (!quotes_enabled) return;
    pthread_mutex_lock(&quotes_mu);
    quotes_shutdown = true;
    pthread_mutex_unlock(&quotes_mu);
    if (quotes_thr_started) {
        pthread_join(quotes_thr, NULL);
        quotes_thr_started = false;
    }
}

// --- Microwave timer (pixel art, bottom-right, idle by default) ---
// Keyboard only: Ctrl+T hides, Ctrl++ / KP+ adds +30 (no mouse needed).
// Done → one dink.

static bool mw_enabled = true;  // --no-microwave
static bool mw_visible = true;  // Ctrl+T
static bool mw_running = false;
static bool mw_done = false;
static float mw_remaining = 0.0f; // seconds
static bool mw_audio_ok = false;
static Sound mw_dink;

static void mw_toggle(void) {
    if (mw_enabled) mw_visible = !mw_visible;
}

static void mw_add_thirty(void) {
    if (!mw_enabled || !mw_visible) return;
    mw_remaining += 30.0f;
    if (mw_remaining > 600.0f) mw_remaining = 600.0f;
    mw_done = false;
    mw_running = true;
}

static void mw_handle_click(int rx, int ry) {
    (void)rx;
    (void)ry;
    // Mouse unused on purpose — keyboard only (Ctrl++ / KP+).
}

static void mw_update(float dt) {
    if (!mw_enabled) return;
    if (!mw_running || mw_done) return;
    mw_remaining -= dt;
    if (mw_remaining <= 0.0f) {
        mw_remaining = 0.0f;
        mw_running = false;
        mw_done = true;
        if (mw_audio_ok) PlaySound(mw_dink);
    }
}

// Procedural pixel microwave. sx = pixel scale. Returns +30 button rect in
// absolute window coords (also stored for hit-test).
static void mw_draw(int sw, int sh) {
    if (!mw_enabled || !mw_visible) return;

    const int px = 3; // pixel scale
    // Sprite grid ~22 wide × 16 tall body + keypad column
    const int gw = 24, gh = 16;
    int mw_w = gw * px;
    int mw_h = gh * px;
    int margin = 20;
    int base_x = sw - margin - mw_w;
    int base_y = sh - margin - 50 - mw_h; // leave room for version line

    // Timer text above — only while running with time left (none at 0/idle/done).
    if (mw_running && mw_remaining > 0.0f) {
        int mm = (int)(mw_remaining / 60.0f);
        int ss = (int)(mw_remaining - mm * 60.0f);
        char tbuf[16];
        snprintf(tbuf, sizeof(tbuf), "%d:%02d", mm, ss);
        const int F_T = 28;
        int tw = w_measure(tbuf, F_T);
        w_draw(tbuf, base_x + (mw_w - tw) / 2, base_y - F_T - 8, F_T,
               (Color){ 200, 205, 215, 240 });
    }

    // Colors — soft cozy palette
    Color body    = { 52, 56, 66, 255 };
    Color body_d  = { 40, 44, 54, 255 };
    Color face    = { 62, 68, 80, 255 };
    Color door    = { 28, 32, 40, 255 };
    Color door_gl = mw_running ? (Color){ 90, 100, 70, 255 }
                 : mw_done    ? (Color){ 100, 88, 50, 255 }
                              : (Color){ 40, 46, 56, 255 };
    Color led     = mw_running ? (Color){ 120, 220, 140, 255 }
                 : mw_done    ? (Color){ 240, 190, 90, 255 }
                              : (Color){ 70, 78, 90, 255 };
    Color btn     = { 78, 84, 96, 255 };
    Color btn_h   = { 110, 120, 140, 255 };
    Color shadow  = { 0, 0, 0, 60 };

    // Drop shadow
    DrawRectangle(base_x + 2, base_y + 3, mw_w, mw_h, shadow);

    // Outer body
    DrawRectangle(base_x, base_y, mw_w, mw_h, body);
    DrawRectangle(base_x, base_y + mw_h - px, mw_w, px, body_d);

    // Door window (left ~14 cells)
    int door_x = base_x + 2 * px;
    int door_y = base_y + 2 * px;
    int door_w = 13 * px;
    int door_h = 10 * px;
    DrawRectangle(door_x, door_y, door_w, door_h, door);
    DrawRectangle(door_x + px, door_y + px, door_w - 2 * px, door_h - 2 * px, door_gl);
    // Mesh lines
    for (int i = 1; i < 5; i++) {
        DrawRectangle(door_x + px, door_y + i * (door_h / 5),
                      door_w - 2 * px, 1, (Color){ 0, 0, 0, 80 });
    }

    // Keypad strip (right side)
    int pad_x = base_x + 16 * px;
    int pad_y = base_y + 2 * px;
    DrawRectangle(pad_x, pad_y, 6 * px, 10 * px, face);

    // LED
    DrawRectangle(pad_x + px, pad_y + px, 4 * px, 2 * px, led);

    // +30 button (2×2 cells with label)
    int bx = pad_x + px;
    int by = pad_y + 4 * px;
    int bw = 4 * px;
    int bh = 3 * px;
    DrawRectangle(bx, by, bw, bh, btn);
    DrawRectangle(bx + 1, by + 1, bw - 2, 1, btn_h);
    // tiny "+30" as three pixel groups — draw text instead for clarity
    {
        const char *lab = "+30";
        int fs = px * 3;
        int lw = w_measure(lab, fs);
        // may overflow tiny button — use raw DrawText default if needed
        if (lw <= bw - 2)
            w_draw(lab, bx + (bw - lw) / 2, by + (bh - fs) / 2, fs,
                   (Color){ 230, 232, 240, 255 });
        else {
            DrawText(lab, bx + 1, by + (bh - 8) / 2, 8,
                     (Color){ 230, 232, 240, 255 });
        }
    }

    // Feet
    DrawRectangle(base_x + px, base_y + mw_h, 3 * px, px, body_d);
    DrawRectangle(base_x + mw_w - 4 * px, base_y + mw_h, 3 * px, px, body_d);
}

// --- Stocks (opt-in, top-right) ---
#define STOCKS_MAX 10

static bool stocks_enabled = false; // --stocks
static bool stocks_visible = true;  // Ctrl+O
static int stocks_n = 0;
static char stocks_sym[STOCKS_MAX][16];
static float stocks_price[STOCKS_MAX];
static float stocks_pct[STOCKS_MAX];
static bool stocks_ok[STOCKS_MAX];
static char stocks_cli[STOCKS_MAX][16];
static int stocks_cli_n = 0;
static pthread_mutex_t stocks_mu = PTHREAD_MUTEX_INITIALIZER;
static bool stocks_shutdown = false;
static pthread_t stocks_thr;
static bool stocks_thr_started = false;
static time_t stocks_last_ok = 0; // wall clock — see stocks_thread
#define STOCKS_REFRESH_SEC 900

static void stocks_toggle(void) {
    if (stocks_enabled) stocks_visible = !stocks_visible;
}

static void stocks_cache_path(char *out, size_t n) {
    weather_cache_path(out, n, "stocks.json");
}

static void stocks_apply_defaults(void) {
    stocks_n = 0;
    if (stocks_cli_n > 0) {
        for (int i = 0; i < stocks_cli_n && stocks_n < STOCKS_MAX; i++) {
            snprintf(stocks_sym[stocks_n], sizeof(stocks_sym[0]), "%.15s",
                     stocks_cli[i]);
            stocks_ok[stocks_n] = false;
            stocks_price[stocks_n] = 0;
            stocks_pct[stocks_n] = 0;
            stocks_n++;
        }
        return;
    }
    const char *def[] = { "^GSPC", "INTC", "TSLA" };
    for (size_t i = 0; i < sizeof(def) / sizeof(def[0]) && stocks_n < STOCKS_MAX; i++) {
        snprintf(stocks_sym[stocks_n], sizeof(stocks_sym[0]), "%.15s", def[i]);
        stocks_ok[stocks_n] = false;
        stocks_price[stocks_n] = 0;
        stocks_pct[stocks_n] = 0;
        stocks_n++;
    }
}

// Parse "AAPL,INTC,^GSPC" (and lone symbols) into stocks_cli.
static void stocks_add_list(const char *list) {
    if (!list || !list[0]) return;
    const char *p = list;
    while (*p && stocks_cli_n < STOCKS_MAX) {
        while (*p == ',' || *p == ' ') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',' && *p != ' ') p++;
        int len = (int)(p - start);
        if (len > 0) {
            if (len > 15) len = 15;
            snprintf(stocks_cli[stocks_cli_n], sizeof(stocks_cli[0]),
                     "%.*s", len, start);
            stocks_cli_n++;
        }
    }
}

static bool stocks_parse_one(const char *sym, const char *json_text) {
    if (!json_text) return false;
    json_object *root = json_tokener_parse(json_text);
    if (!root) return false;
    json_object *chart = NULL;
    if (!json_object_object_get_ex(root, "chart", &chart)) {
        json_object_put(root);
        return false;
    }
    json_object *result = NULL;
    if (!json_object_object_get_ex(chart, "result", &result) ||
        json_object_array_length(result) < 1) {
        json_object_put(root);
        return false;
    }
    json_object *r0 = json_object_array_get_idx(result, 0);
    json_object *meta = NULL;
    if (!json_object_object_get_ex(r0, "meta", &meta)) {
        json_object_put(root);
        return false;
    }
    json_object *jp = NULL, *jc = NULL;
    float price = 0, pct = 0;
    bool has_p = json_object_object_get_ex(meta, "regularMarketPrice", &jp);
    bool has_c = json_object_object_get_ex(meta, "regularMarketChangePercent", &jc);
    if (has_p) price = (float)json_object_get_double(jp);
    if (has_c) pct = (float)json_object_get_double(jc);
    json_object_put(root);
    if (!has_p) return false;

    bool found = false;
    pthread_mutex_lock(&stocks_mu);
    for (int i = 0; i < stocks_n; i++) {
        if (strcmp(stocks_sym[i], sym) == 0) {
            stocks_price[i] = price;
            stocks_pct[i] = pct;
            stocks_ok[i] = true;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&stocks_mu);
    return found;
}

static bool stocks_fetch_symbol(const char *sym) {
    char url[256];
    // Encode ^ as %5E
    char enc[32];
    int j = 0;
    for (const char *p = sym; *p && j < (int)sizeof(enc) - 1; p++) {
        if (*p == '^') {
            if (j + 3 >= (int)sizeof(enc)) break;
            enc[j++] = '%';
            enc[j++] = '5';
            enc[j++] = 'E';
        } else {
            enc[j++] = *p;
        }
    }
    enc[j] = '\0';
    snprintf(url, sizeof(url),
             "https://query1.finance.yahoo.com/v8/finance/chart/%s"
             "?interval=1d&range=5d",
             enc);
    char *body = http_get(url, 8);
    if (!body) return false;
    bool ok = stocks_parse_one(sym, body);
    free(body);
    return ok;
}

static bool stocks_load_cache(void) {
    char path[512];
    stocks_cache_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    json_object *root = json_tokener_parse(buf);
    if (!root) return false;
    int any = 0;
    for (int i = 0; i < stocks_n; i++) {
        json_object *item = NULL;
        if (json_object_object_get_ex(root, stocks_sym[i], &item)) {
            json_object *pp = NULL, *cc = NULL;
            if (json_object_object_get_ex(item, "price", &pp))
                stocks_price[i] = (float)json_object_get_double(pp);
            if (json_object_object_get_ex(item, "pct", &cc))
                stocks_pct[i] = (float)json_object_get_double(cc);
            stocks_ok[i] = true;
            any++;
        }
    }
    json_object_put(root);
    return any > 0;
}

static void stocks_save_cache(void) {
    char path[512];
    stocks_cache_path(path, sizeof(path));
    json_object *root = json_object_new_object();
    pthread_mutex_lock(&stocks_mu);
    for (int i = 0; i < stocks_n; i++) {
        if (!stocks_ok[i]) continue;
        json_object *item = json_object_new_object();
        json_object_object_add(item, "price",
                               json_object_new_double(stocks_price[i]));
        json_object_object_add(item, "pct",
                               json_object_new_double(stocks_pct[i]));
        json_object_object_add(root, stocks_sym[i], item);
    }
    pthread_mutex_unlock(&stocks_mu);
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(json_object_to_json_string(root), f);
        fclose(f);
    }
    json_object_put(root);
}

static void *stocks_thread(void *arg) {
    (void)arg;
    bool boot = true;
    for (;;) {
        pthread_mutex_lock(&stocks_mu);
        bool down = stocks_shutdown;
        time_t last = stocks_last_ok;
        int n = stocks_n;
        pthread_mutex_unlock(&stocks_mu);
        if (down) break;

        // First data is loaded synchronously in stocks_start; thread only
        // handles periodic refresh after that. Schedule on the wall clock,
        // not GetTime(): the lock is restarted constantly and the machine
        // suspends while it is up, so a monotonic "seconds since start"
        // timer basically never reaches STOCKS_REFRESH_SEC.
        bool due = (last == 0 || difftime(time(NULL), last) >= STOCKS_REFRESH_SEC);
        if (boot) {
            boot = false;
        } else if (due) {
            for (int i = 0; i < n; i++) {
                char sym[16];
                pthread_mutex_lock(&stocks_mu);
                snprintf(sym, sizeof(sym), "%.15s", stocks_sym[i]);
                pthread_mutex_unlock(&stocks_mu);
                stocks_fetch_symbol(sym);
            }
            pthread_mutex_lock(&stocks_mu);
            stocks_last_ok = time(NULL);
            pthread_mutex_unlock(&stocks_mu);
            stocks_save_cache();
        }

        for (int i = 0; i < 50 && !stocks_shutdown; i++)
            usleep(20 * 1000);
    }
    return NULL;
}

static void stocks_draw(int sw, int sh) {
    (void)sh;
    if (!stocks_enabled || !stocks_visible) return;

    const int F_SYM = 18;
    const int F_VAL = 22;
    int row = F_VAL + 6;
    int margin = 16;
    int pad = 10;

    int label_w = 0;
    for (int i = 0; i < stocks_n; i++) {
        int w = w_measure(stocks_sym[i], F_SYM);
        if (w > label_w) label_w = w;
    }
    int val_w = w_measure("-000.00  -00.00%", F_VAL);
    int colw = label_w + 8 + val_w;
    int panel_w = colw + pad * 2;
    int panel_h = stocks_n * row + pad * 2;
    int px = sw - margin - panel_w;
    int py = margin;

    Color panel = { 10, 12, 18, 160 };
    DrawRectangle(px, py, panel_w, panel_h, panel);

    pthread_mutex_lock(&stocks_mu);
    for (int i = 0; i < stocks_n; i++) {
        int ry = py + pad + i * row;
        Color c_sym = { 150, 155, 168, 230 };
        w_draw(stocks_sym[i], px + pad, ry + 4, F_SYM, c_sym);

        char line[64];
        if (stocks_ok[i]) {
            snprintf(line, sizeof(line), "%.2f  %+.2f%%",
                     stocks_price[i], stocks_pct[i]);
        } else {
            snprintf(line, sizeof(line), "—");
        }
        Color c_val;
        if (!stocks_ok[i])
            c_val = (Color){ 120, 124, 135, 220 };
        else if (stocks_pct[i] > 0.05f)
            c_val = (Color){ 140, 200, 150, 240 }; // soft green
        else if (stocks_pct[i] < -0.05f)
            c_val = (Color){ 230, 150, 150, 240 }; // soft rose
        else
            c_val = (Color){ 190, 194, 205, 240 };
        // Right-align inside the value column: the panel keeps the widest
        // estimate so it never jitters per row, but every line ends on the
        // same right edge (decimal points line up).
        int lw = w_measure(line, F_VAL);
        w_draw(line, px + pad + colw - lw, ry, F_VAL, c_val);
    }
    pthread_mutex_unlock(&stocks_mu);
}

static void stocks_start(void) {
    if (!stocks_enabled) return;
    stocks_apply_defaults();

    // Blocking first load: when --stocks is on, wait for data before the
    // main loop so the panel isn't empty for the first frames. Cache is
    // keyed by symbol; fetch any symbol still missing (e.g. list grew) and
    // re-fetch everything when the cache is older than one refresh — a
    // fresh cache always loads fully, so without the age check every new
    // lock session would show frozen prices forever. Refresh continues on
    // the worker thread after that.
    stocks_load_cache();
    char path[512];
    stocks_cache_path(path, sizeof(path));
    struct stat st;
    bool stale = (stat(path, &st) != 0 ||
                  difftime(time(NULL), st.st_mtime) >= STOCKS_REFRESH_SEC);
    bool missing = false;
    for (int i = 0; i < stocks_n; i++)
        if (!stocks_ok[i]) missing = true;
    if (missing || stale) {
        fprintf(stderr, "[memelock] stocks: fetching%s…\n",
                stale && !missing ? " (stale cache)" : "");
        bool any = false;
        for (int i = 0; i < stocks_n; i++) {
            if (stocks_ok[i] && !stale) continue;
            char sym[16];
            pthread_mutex_lock(&stocks_mu);
            snprintf(sym, sizeof(sym), "%.15s", stocks_sym[i]);
            pthread_mutex_unlock(&stocks_mu);
            if (stocks_fetch_symbol(sym)) any = true;
        }
        // Don't stamp a failed refresh as fresh, or the next start sees a
        // young mtime and skips the fetch again.
        if (any) stocks_save_cache();
    }
    stocks_last_ok = time(NULL);

    stocks_thr_started = (pthread_create(&stocks_thr, NULL, stocks_thread, NULL) == 0);
}

static void stocks_stop(void) {
    if (!stocks_enabled || !stocks_thr_started) return;
    pthread_mutex_lock(&stocks_mu);
    stocks_shutdown = true;
    pthread_mutex_unlock(&stocks_mu);
    pthread_join(stocks_thr, NULL);
    stocks_thr_started = false;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n"
           "\n"
           "Options:\n"
           "  -h, --help              show this help and exit\n"
           "  -b, -b=N                background blur radius (default 5)\n"
           "  -d, -d=N                background darken, 0..255 (default 160;\n"
           "                          0 = none, 255 = pitch black)\n"
           "  --min-blur=N            minimum blur radius, 0..64 (default 5)\n"
           "                          blur 0 = full-res original (darken still applies)\n"
           "  --weather               weather widget visible at start (default)\n"
           "  --no-weather            disable weather widget\n"
           "  --city=NAME[,CC]        city for weather (e.g. Vilnius or Paris,FR)\n"
           "  --lat=LAT --lon=LON     exact coordinates for weather\n"
           "  --layout[=PATH]         live-reload weather layout file\n"
           "                          (default ~/.cache/memelock/layout.txt)\n"
           "  --snow                  enable snow spawning (default)\n"
           "  --no-snow               disable snow spawning\n"
           "  --meteors/--no-meteors  falling meteors (default on)\n"
           "  --dvd                   enable DVD logo bounce (default off)\n"
           "  --no-dvd                disable DVD logo (default)\n"
           "  --snow-speed=N          snowfall speed multiplier (default 1.0)\n"
           "  --dvd-speed=N           DVD logo speed multiplier (default 1.0)\n"
           "  --snow-tint=MODE        flake color: white | ice | mix (default mix)\n"
           "  --no-clock              hide the top-center clock\n"
           "  --fade-password=N       idle sec before * box fades (default 5, 0=off)\n"
           "  --wind=0                disable ambient wind gusts\n"
           "  --microwave / --no-microwave  timer widget (default visible, idle)\n"
           "  --quotes / --no-quotes  quote line under clock (default on)\n"
           "  --stocks[=A,B,C]        stock list top-right (default off;\n"
           "                          also --stock=SYM (repeatable);\n"
           "                          bare --stocks uses ^GSPC,INTC,TSLA;\n"
           "                          first load blocks until fetched)\n"
            "  --raylib-log            enable raylib's own log output (off by default)\n"
            "  --crash-key             enable Ctrl+K deliberate crash (testing only)\n"
            "  --no-supervisor         run the lock directly, no monitor process\n"
            "  --supervisor-log=PATH   supervisor event log\n"
            "                          (default ~/.cache/memelock/supervisor.log)\n"
           "\n"
           "While locked: Ctrl+R toggles the weather widget,\n"
           "              Ctrl+S toggles snow spawn, Ctrl+X clears the pile,\n"
           "              Ctrl+M toggles meteors,\n"
           "              Ctrl+, / Ctrl+. adjust blur, Ctrl+B types a blur value,\n"
           "              Ctrl+H raises the min-blur floor (never lowers),\n"
           "              Ctrl+Shift+, / Ctrl+Shift+. adjust darken by 5,\n"
           "              Ctrl+D types a darken value, Ctrl+V toggles the DVD logo,\n"
            "              Ctrl+T microwave hide, Ctrl++ / KP+ microwave +30,\n"
            "              Ctrl+Q next quote, Ctrl+O stocks.\n"
            "              Ctrl+K deliberate crash (only with --crash-key).\n",
           prog);
}

int app_main(int argc, char **argv) {
    bool raylib_log = false;
    float fade_password_s = 5.0f;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--raylib-log") == 0) {
            raylib_log = true;
        } else if (strcmp(argv[i], "--no-clock") == 0) {
            clock_enabled = false;
        } else if (strncmp(argv[i], "--fade-password=", 16) == 0) {
            float v = strtof(argv[i] + 16, NULL);
            if (v >= 0.0f) fade_password_s = v;
        } else if (strncmp(argv[i], "--wind=", 7) == 0) {
            float v = strtof(argv[i] + 7, NULL);
            wind_allow = (v > 0.0f) ? 1.0f : 0.0f;
        } else if (strcmp(argv[i], "--microwave") == 0) {
            mw_enabled = true;
            mw_visible = true;
        } else if (strcmp(argv[i], "--no-microwave") == 0) {
            mw_enabled = false;
            mw_visible = false;
        } else if (strcmp(argv[i], "--quotes") == 0) {
            quotes_enabled = true;
            quotes_visible = true;
        } else if (strcmp(argv[i], "--no-quotes") == 0) {
            quotes_enabled = false;
            quotes_visible = false;
        } else if (strcmp(argv[i], "--stocks") == 0) {
            stocks_enabled = true;
        } else if (strncmp(argv[i], "--stocks=", 9) == 0) {
            stocks_enabled = true;
            stocks_add_list(argv[i] + 9);
        } else if (strncmp(argv[i], "--stock=", 8) == 0) {
            stocks_enabled = true;
            stocks_add_list(argv[i] + 8);
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bg_blur = atoi(argv[++i]);
        } else if (strncmp(argv[i], "-b=", 3) == 0) {
            bg_blur = atoi(argv[i] + 3);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            if (v < 0 || v > 255) {
                fprintf(stderr, "invalid -d value (need 0..255): %s\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
            bg_darken = v;
        } else if (strncmp(argv[i], "-d=", 3) == 0) {
            int v = atoi(argv[i] + 3);
            if (v < 0 || v > 255) {
                fprintf(stderr, "invalid -d value (need 0..255): %s\n", argv[i] + 3);
                print_usage(argv[0]);
                return 1;
            }
            bg_darken = v;
        } else if (strncmp(argv[i], "--min-blur=", 11) == 0) {
            int v = atoi(argv[i] + 11);
            if (v >= 0 && v <= 64) bg_blur_min = v;
        } else if (strncmp(argv[i], "--snow-speed=", 13) == 0) {
            float v = strtof(argv[i] + 13, NULL);
            if (v > 0.0f) snow_speed_mult = v;
        } else if (strncmp(argv[i], "--dvd-speed=", 12) == 0) {
            float v = strtof(argv[i] + 12, NULL);
            if (v > 0.0f) dvd_speed_mult = v;
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
        } else if (strcmp(argv[i], "--snow") == 0) {
            snow_spawning = true;
        } else if (strcmp(argv[i], "--no-snow") == 0) {
            snow_spawning = false;
        } else if (strcmp(argv[i], "--meteors") == 0) {
            meteors_enabled = true;
        } else if (strcmp(argv[i], "--no-meteors") == 0) {
            meteors_enabled = false;
        } else if (strcmp(argv[i], "--dvd") == 0) {
            dvd_enabled = true;
        } else if (strcmp(argv[i], "--no-dvd") == 0) {
            dvd_enabled = false;
        } else if (strcmp(argv[i], "--crash-key") == 0) {
            crash_key_enabled = true;
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

    // Quiet raylib by default (GLFW/GL chatter). Our [memelock] fprintfs
    // still go to stderr. Must run before InitWindow to catch init logs.
    SetTraceLogLevel(raylib_log ? LOG_ALL : LOG_NONE);

    // Snapshot desktop before the lock window covers it (CPU only).
    bg_capture();

    SetConfigFlags(FLAG_FULLSCREEN_MODE | FLAG_WINDOW_UNDECORATED | FLAG_WINDOW_TOPMOST);
    InitWindow(screen_width, screen_height, "mule");

    // Shared UI font (clock/quotes/stocks/weather) + curl for any fetcher.
    weather_load_font();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Soft-fail audio for the microwave dink (lock still works without it).
    InitAudioDevice();
    if (IsAudioDeviceReady()) {
        // Cozy warm ding: soft attack, longer gentle decay, low bell tone.
        const int sample_rate = 44100;
        const int frames = sample_rate * 55 / 100;
        Wave wave = {0};
        wave.frameCount = frames;
        wave.sampleRate = sample_rate;
        wave.sampleSize = 16;
        wave.channels = 1;
        short *samples = calloc((size_t)frames, sizeof(short));
        if (samples) {
            for (int i = 0; i < frames; i++) {
                float t = (float)i / (float)sample_rate;
                float attack = (t < 0.012f) ? (t / 0.012f) : 1.0f;
                float env = expf(-t * 5.0f) * attack;
                float s = sinf(2.0f * PI * 523.25f * t) * 0.55f
                        + sinf(2.0f * PI * 784.0f * t) * 0.28f
                        + sinf(2.0f * PI * 1046.5f * t) * 0.10f;
                float trem = 1.0f + 0.06f * sinf(2.0f * PI * 5.5f * t);
                samples[i] = (short)(s * env * trem * 12000.0f);
            }
            wave.data = samples;
            mw_dink = LoadSoundFromWave(wave);
            UnloadWave(wave); // frees samples after upload
            mw_audio_ok = (mw_dink.frameCount > 0);
        }
    }

    // GL context exists — first paint is synchronous; live changes use worker.
    bg_rebuild_sync();
    bg_worker_start();

    int monitor = GetCurrentMonitor();
    SetWindowSize(GetMonitorWidth(monitor), GetMonitorHeight(monitor));

    // Must run after InitWindow (need the X window to exist).
    // Grabs all keyboard input so awesomewm global keybinds
    // (incl. kill client) never fire.
    lock_setup_x11();
    lock_grab_startup(); // bounded (~3s max), before first frame only

    weather_start();
    quotes_start();
    stocks_start();
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
    dvd_tex_load();

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

        if (xpass_submit && !prompt_open) {
            xpass_submit = false;
            if (auth_start(xpassword)) {
                memset(xpassword, 0, sizeof(xpassword));
                xpass_len = 0;
            }
        } else if (xpass_submit) {
            xpass_submit = false;
        }

        {
            bool aok = false;
            if (auth_poll(&aok)) {
                if (aok) {
                    unlocked = true;
                    break;
                }
                xauth_failed = true;
                fail_time = GetTime();
            }
        }

        if (xauth_failed && (GetTime() - fail_time > 1.5)) {
            xauth_failed = false;
        }

        snow_update(GetFrameTime());
        dvd_update(GetFrameTime());
        mw_update(GetFrameTime());
        bg_poll_upload(); // swap in finished worker texture without blocking

        // Password * box idle-fade (0 disables). Ease toward target.
        {
            double idle = GetTime() - passwd_last_key;
            float target = 1.0f;
            if (fade_password_s > 0.0f && idle > (double)fade_password_s &&
                xpass_len == 0 && !xauth_failed && !auth_busy)
                target = 0.0f;
            float rate = (target > passwd_fade) ? 8.0f : 3.0f; // snap in, ease out
            if (passwd_fade < target) {
                passwd_fade += rate * GetFrameTime();
                if (passwd_fade > target) passwd_fade = target;
            } else if (passwd_fade > target) {
                passwd_fade -= rate * GetFrameTime();
                if (passwd_fade < target) passwd_fade = target;
            }
            // Snap fully invisible once close enough (no residual ghost frame).
            if (target == 0.0f && passwd_fade < 0.004f) passwd_fade = 0.0f;
            if (xpass_len > 0 || xauth_failed || auth_busy) passwd_fade = 1.0f;
        }

        BeginDrawing();
        ClearBackground(BLACK);
        {
            int sw0 = GetScreenWidth();
            int sh0 = GetScreenHeight();
            bg_draw(sw0, sh0);
        }
        snow_draw();
        dvd_draw();

        int sw = GetScreenWidth();
        int sh = GetScreenHeight();

        // Soft center UI palette (comfy, not pure black/white/red).
        const int ui_pad = 18;
        const Color ui_bg = { 16, 14, 20, 185 };
        const Color ui_fg = { 235, 232, 240, 255 };
        const Color ui_err = { 235, 140, 150, 255 };
        const Color ui_wait = { 220, 190, 120, 255 };

        // Top-center clock + quote.
        clock_draw(sw, sh);

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

        // Fade * box fully when idle (no ghost frame, no leftover hint).
        {
            unsigned char a_panel = (unsigned char)(ui_bg.a * passwd_fade);
            unsigned char a_text = (unsigned char)(255 * passwd_fade);
            if (passwd_fade >= 0.01f && a_panel > 0 && a_text > 0) {
                Color panel_c = ui_bg;
                panel_c.a = a_panel;
                Color text_c = ui_fg;
                text_c.a = a_text;
                DrawRectangleRounded(
                    (Rectangle){ content_x - ui_pad, box_y,
                                 content_w + ui_pad * 2, (float)box_h },
                    0.15f, 4, panel_c);
                if (text_width > 0) {
                    // DrawText has no alpha override — scale via tint color.
                    DrawText(display, content_x, text_y, text_size, text_c);
                }
            }
        }

        if (xauth_failed) {
            const char *err = "wrong password";
            int err_size = 40;
            int err_width = MeasureText(err, err_size);
            int err_x = (sw - err_width) / 2;
            int err_y = sh / 2 + 110;
            DrawRectangleRounded(
                (Rectangle){ err_x - ui_pad, err_y - ui_pad,
                             err_width + ui_pad * 2, (float)(err_size + ui_pad * 2) },
                0.15f, 4, ui_bg);
            DrawText(err, err_x, err_y, err_size, ui_err);
        } else if (auth_busy) {
            const char *msg = "checking…";
            int msg_size = 40;
            int msg_width = MeasureText(msg, msg_size);
            int msg_x = (sw - msg_width) / 2;
            int msg_y = sh / 2 + 110;
            DrawRectangleRounded(
                (Rectangle){ msg_x - ui_pad, msg_y - ui_pad,
                             msg_width + ui_pad * 2, (float)(msg_size + ui_pad * 2) },
                0.15f, 4, ui_bg);
            DrawText(msg, msg_x, msg_y, msg_size, ui_wait);
        }

        // Weather widget — compact layout, bottom-left (Ctrl+R toggles).
        layout_poll();
        weather_draw(sw, sh);

        // Stocks top-right (opt-in). Microwave bottom-right (Ctrl+T).
        stocks_draw(sw, sh);
        mw_draw(sw, sh);

        // Modular number/text field — top-left (Ctrl+B opens blur field).
        prompt_draw();

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
    quotes_stop();
    stocks_stop();
    bg_unload();
    dvd_tex_unload();
    if (mw_audio_ok) {
        UnloadSound(mw_dink);
        mw_audio_ok = false;
    }
    if (IsAudioDeviceReady()) CloseAudioDevice();
    curl_global_cleanup();
    CloseWindow();
    return 0;
}

// --- Supervisor: monitor process that respawns the lock on crash ---
// The lock (app_main above) is the child; this parent only waits, logs,
// and reforks. Clean unlock = child exits 0 -> supervisor exits 0.
// Non-zero exit or signal death -> immediate respawn; 5 such deaths
// within 60s -> give up (exit non-zero) instead of looping forever.
//
// Logging decision: supervisor event log only (starts, exits, signals,
// uptimes). The child's own [memelock] stderr is NOT redirected —
// capturing it means fd plumbing + rotation policy, clunk not worth it
// for a handful of lifecycle lines.
#define SUP_MAX_CRASHES 5
#define SUP_CRASH_WINDOW_S 60.0

static volatile pid_t sup_child = -1;
static volatile sig_atomic_t sup_got_term = 0;
static volatile sig_atomic_t sup_got_int = 0;

static void sup_forward(int sig) {
    pid_t c = sup_child;
    if (c > 0) kill(c, sig);
    if (sig == SIGTERM) sup_got_term = 1;
    if (sig == SIGINT) sup_got_int = 1;
}

static void sup_log(const char *path, const char *fmt, ...) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    time_t t = time(NULL);
    struct tm tm;
    char ts[32];
    if (localtime_r(&t, &tm) && strftime(ts, sizeof(ts), "%F %T", &tm))
        fprintf(f, "%s ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

int main(int argc, char **argv) {
    // Strip supervisor-only flags before the child ever sees argv
    // (app_main rejects unknown options, so they must not pass through).
    char *fargv[4096];
    int fargc = 0;
    fargv[fargc++] = argv[0];
    bool no_sup = false;
    bool want_help = false;
    char logpath[1024];
    bool have_logpath = false;
    logpath[0] = '\0';
    for (int i = 1; i < argc && fargc < (int)(sizeof(fargv) / sizeof(fargv[0])) - 1; i++) {
        if (strcmp(argv[i], "--no-supervisor") == 0) {
            no_sup = true;
        } else if (strncmp(argv[i], "--supervisor-log=", 17) == 0) {
            snprintf(logpath, sizeof(logpath), "%s", argv[i] + 17);
            have_logpath = true;
        } else if (strcmp(argv[i], "--supervisor-log") == 0 && i + 1 < argc) {
            snprintf(logpath, sizeof(logpath), "%s", argv[++i]);
            have_logpath = true;
        } else {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
                want_help = true;
            fargv[fargc++] = argv[i];
        }
    }
    fargv[fargc] = NULL;

    if (no_sup || want_help)
        return app_main(fargc, fargv);

    if (!have_logpath)
        weather_cache_path(logpath, sizeof(logpath), "supervisor.log");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sup_forward;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    // One-line command for the log (truncated, never contains secrets —
    // the password only ever lives in X input memory, not argv).
    char cmd[512];
    {
        size_t o = 0;
        for (int i = 0; i < argc && o < sizeof(cmd) - 1; i++) {
            int w = snprintf(cmd + o, sizeof(cmd) - o, "%s%s",
                             i ? " " : "", argv[i]);
            if (w < 0) break;
            o += (size_t)w;
        }
        cmd[sizeof(cmd) - 1] = '\0';
    }
    sup_log(logpath, "[sup] start pid=%d cmd:%s", (int)getpid(), cmd);

    double crashes[SUP_MAX_CRASHES];
    int ncrash = 0;
    int attempt = 0;

    for (;;) {
        attempt++;
        time_t born = time(NULL);
        pid_t pid = fork();
        if (pid < 0) {
            sup_log(logpath, "[sup] fork failed: %s", strerror(errno));
            fprintf(stderr, "[memelock] supervisor: fork failed: %s\n",
                    strerror(errno));
            return 1;
        }
        if (pid == 0) {
            // Child: plain fork, no exec — parent held no X/GL/threads yet.
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            signal(SIGHUP, SIG_DFL);
            return app_main(fargc, fargv);
        }

        sup_child = pid;
        sup_log(logpath, "[sup] child pid=%d spawned (attempt %d)",
                (int)pid, attempt);

        int st = 0;
        pid_t w;
        do {
            w = waitpid(pid, &st, 0);
        } while (w < 0 && errno == EINTR);
        sup_child = -1;
        long uptime = (long)(time(NULL) - born);

        if (w < 0) {
            sup_log(logpath, "[sup] waitpid failed: %s", strerror(errno));
            return 1;
        }
        if (sup_got_term || sup_got_int) {
            // We were asked to die and already forwarded it: stay dead,
            // don't respawn the lock out from under the shutdown.
            sup_log(logpath, "[sup] got %s, child done, exiting",
                    sup_got_term ? "SIGTERM" : "SIGINT");
            return 128 + (sup_got_term ? SIGTERM : SIGINT);
        }
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
            sup_log(logpath, "[sup] child pid=%d unlocked (exit 0 after %lds)",
                    (int)pid, uptime);
            return 0;
        }

        char why[128];
        if (WIFEXITED(st))
            snprintf(why, sizeof(why), "exit status %d", WEXITSTATUS(st));
        else if (WIFSIGNALED(st))
            snprintf(why, sizeof(why), "killed by %s", strsignal(WTERMSIG(st)));
        else
            snprintf(why, sizeof(why), "died (status 0x%x)", st);

        // Crash-loop guard: 5 abnormal deaths inside 60s -> give up.
        // (Also catches deterministic early exits like bad flags, which
        // would otherwise respawn forever.)
        double now = (double)time(NULL);
        if (ncrash < SUP_MAX_CRASHES)
            crashes[ncrash++] = now;
        else {
            memmove(crashes, crashes + 1, sizeof(crashes) - sizeof(crashes[0]));
            crashes[ncrash - 1] = now;
        }
        if (ncrash == SUP_MAX_CRASHES &&
            now - crashes[0] < SUP_CRASH_WINDOW_S) {
            sup_log(logpath, "[sup] child pid=%d %s after %lds; "
                    "%d deaths in %.0fs -> giving up, screen LEFT UNLOCKED",
                    (int)pid, why, uptime,
                    SUP_MAX_CRASHES, now - crashes[0]);
            fprintf(stderr, "[memelock] supervisor: crash-loop, giving up "
                    "(see %s)\n", logpath);
            return 1;
        }

        sup_log(logpath, "[sup] child pid=%d %s after %lds; respawning",
                (int)pid, why, uptime);
    }
}
