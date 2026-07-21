"""
MAX - app mobile para engenheiros de redes, produzido by Marcos Max.
Testes: Ping, Wi-Fi (SSID/RSSI no Android), Speedtest (stdlib only),
Scanner de Portas e Varredura de Rede (descoberta de hosts + hostname + portas).

Compilado para Android via Buildozer / GitHub Actions.
"""

import json
import socket
import ssl
import struct
import subprocess
import platform
import threading
import time
import math
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except Exception:  # noqa: BLE001
    # Sem certifi (ou sem certificados encontrados) -- melhor rodar sem
    # verificar o certificado do que quebrar toda requisicao HTTPS. Isso
    # so afeta o teste de velocidade (download de um arquivo publico).
    _SSL_CONTEXT = ssl._create_unverified_context()

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle, Rectangle, Line, Ellipse
from kivy.metrics import dp
from kivy.uix.screenmanager import ScreenManager, Screen, NoTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.image import Image as KivyImage
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.checkbox import CheckBox
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.scrollview import ScrollView
from kivy.uix.widget import Widget
import os

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(ASSETS_DIR, "logo_header.png")
LOGO_RATIO = 357 / 88  # largura/altura da imagem original do logo MAX

IS_ANDROID = platform.system() == "Linux" and "ANDROID_ARGUMENT" in __import__("os").environ


def _write_crash_log(text):
    """Best-effort crash dump to a file the user can find without adb."""
    candidates = []
    private = os.environ.get("ANDROID_PRIVATE")
    if private:
        candidates.append(os.path.join(os.path.dirname(private), "max_crash_log.txt"))
    ext_storage = os.environ.get("EXTERNAL_STORAGE")
    if ext_storage:
        candidates.append(os.path.join(ext_storage, "max_crash_log.txt"))
    candidates.append("/sdcard/max_crash_log.txt")
    candidates.append(os.path.join(ASSETS_DIR, "max_crash_log.txt"))
    for path in candidates:
        try:
            with open(path, "w") as f:
                f.write(text)
            return path
        except Exception:  # noqa: BLE001
            continue
    return None


def _ssh_checkpoint(text):
    """Append a debug checkpoint line to a plain file, flushed immediately.

    Used to narrow down exactly which step of the SSH/JSch connection
    triggers a native crash (one that Python's own try/except cannot
    catch, so the usual crash log never gets written). Each line is
    written and the file closed right away, so even if the process dies
    on the very next JNI call, this checkpoint survives on disk."""
    try:
        with open("/sdcard/max_ssh_debug.txt", "a") as f:
            f.write(text + "\n")
    except Exception:  # noqa: BLE001
        pass


def _ssh_hosts_path():
    """Where the list of saved SSH connections lives. Uses the app's own
    private data dir (App.user_data_dir) -- unlike /sdcard, this never
    needs a storage permission and is available on every Android version,
    which is why it was chosen over the old /sdcard-based debug files."""
    app = App.get_running_app()
    base = app.user_data_dir if app is not None else ASSETS_DIR
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:  # noqa: BLE001
        pass
    return os.path.join(base, "ssh_hosts.json")


def _load_ssh_hosts():
    try:
        with open(_ssh_hosts_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:  # noqa: BLE001
        pass
    return []


def _save_ssh_hosts(hosts):
    try:
        with open(_ssh_hosts_path(), "w", encoding="utf-8") as f:
            json.dump(hosts, f)
    except Exception:  # noqa: BLE001
        pass


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]

# (label, screen name, vector icon kind, short description) for every tool
# screen -- shared by the Home dashboard's grid and the "Mais"/"Todas"
# sheet, so both stay in sync automatically.
TOOL_CATALOG = [
    ("Ping", "ping", "ping", "Teste de conectividade ICMP"),
    ("Wi-Fi", "wifi", "wifi", "Informacoes da rede e redes proximas"),
    ("Speedtest", "speed", "speed", "Velocidade de download da internet"),
    ("Portas", "ports", "ports", "Verifique portas TCP abertas"),
    ("Varredura", "scan", "scan", "Descubra hosts ativos na rede"),
    ("Terminal", "terminal", "shell", "Comandos de shell, sem root"),
    ("SSH", "ssh", "ssh", "Terminal remoto interativo"),
]

TERMINAL_COMMANDS = [
    ("ping -c 4 8.8.8.8", "Testa conectividade com a internet (mesmo mecanismo da aba Ping)"),
    ("ping -c 4 1.1.1.1", "Testa outro servidor DNS publico"),
    ("getprop net.dns1", "DNS primario configurado"),
    ("getprop net.dns2", "DNS secundario configurado"),
    ("getprop net.hostname", "Nome do host do dispositivo"),
    ("id", "Usuario e permissoes atuais"),
    ("uname -a", "Informacoes do sistema/kernel"),
    ("cat /proc/version", "Versao do kernel"),
    ("cat /proc/cpuinfo", "Informacoes do processador"),
    ("df", "Espaco em disco por particao montada"),
    ("ip addr", "Interfaces de rede -- bloqueado (netlink) sem root na maioria dos Android 8+"),
    ("ip route", "Tabela de rotas -- bloqueado (netlink) sem root na maioria dos Android 8+"),
    ("cat /proc/net/arp", "Tabela ARP -- bloqueado sem root no Android 10+"),
    ("dumpsys wifi | head -n 40", "Status do Wi-Fi -- geralmente bloqueado sem root"),
]


def _int_to_ip(value):
    """Convert Android's little-endian int IP representation to dotted string."""
    if value is None:
        return "?"
    try:
        packed = struct.pack("<i", value)
        return socket.inet_ntoa(packed)
    except Exception:  # noqa: BLE001
        return "?"


def _freq_to_channel(freq):
    """Best-effort Wi-Fi frequency (MHz) -> channel number conversion."""
    if not freq:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5 + 1
    return None


def _go_home():
    """Shared "back" callback used by every tool screen's TopBar: returns
    to the Home dashboard. A plain module function (rather than a method
    on each screen) so every screen can share the same callback without
    needing its own back-navigation plumbing."""
    app = App.get_running_app()
    if app:
        app.switch_screen("home")


def _signal_quality(rssi):
    try:
        rssi = int(rssi)
    except (TypeError, ValueError):
        return "desconhecido"
    if rssi >= -50:
        return "excelente"
    if rssi >= -60:
        return "bom"
    if rssi >= -70:
        return "regular"
    return "fraco"


def _signal_level_info(rssi):
    """Like _signal_quality, but also returns a 0-4 bar count and a color,
    used to draw the signal-bars icon on the Home dashboard's network
    card (mirrors the redesign mockup's status-bar-style signal icon)."""
    try:
        rssi = int(rssi)
    except (TypeError, ValueError):
        return 0, TEXT_MUTED, "Desconhecido"
    if rssi >= -50:
        return 4, SUCCESS, "Excelente"
    if rssi >= -60:
        return 3, SUCCESS, "Bom"
    if rssi >= -70:
        return 2, WARNING, "Regular"
    return 1, DANGER, "Fraco"


def _time_ago(ts):
    """Human-readable "how long ago", used in the Home dashboard's
    "Atividade recente" feed."""
    delta = time.time() - ts
    if delta < 60:
        return "agora ha pouco"
    if delta < 3600:
        return "ha %d min" % int(delta // 60)
    if delta < 86400:
        return "ha %dh" % int(delta // 3600)
    return "ha %dd" % int(delta // 86400)

# ---------------------------------------------------------------------------
# Theme -- paleta escura baseada no redesign visual v2 (cyan/dark, cards
# arredondados, tipografia bem contrastada).
# ---------------------------------------------------------------------------
BG = (0.0588, 0.0667, 0.0824, 1)          # #0F1115
SURFACE = (0.0902, 0.1020, 0.1294, 1)     # #171A21 (cards)
SURFACE_2 = (0.1176, 0.1333, 0.1686, 1)   # #1E222B (inputs / superficie mais clara)
ACCENT = (0.2392, 0.7451, 0.8588, 1)      # #3DBEDB (cyan)
TEXT = (0.9490, 0.9569, 0.9686, 1)        # #F2F4F7
TEXT_MUTED = (0.3608, 0.3922, 0.4510, 1)  # #5C6473
TEXT_SECONDARY = (0.5412, 0.5765, 0.6392, 1)  # #8A93A3
SUCCESS = (0.2039, 0.8275, 0.6000, 1)     # #34D399
WARNING = (0.9843, 0.7490, 0.1412, 1)     # #FBBF24
DANGER = (0.9725, 0.4431, 0.4431, 1)      # #F87171

try:
    Window.clearcolor = BG
except Exception:  # noqa: BLE001
    pass


def run_in_thread(fn):
    """Decorator: run fn in a background thread so the UI never freezes."""
    def wrapper(*args, **kwargs):
        t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
        t.start()
    return wrapper


def get_local_subnet():
    """Best-effort guess of the device's own /24 subnet, e.g. 192.168.0.0/24."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.ip_interface("%s/24" % local_ip).network
        return str(network)
    except Exception:  # noqa: BLE001
        return "192.168.0.0/24"


def resolve_hostname(ip, timeout=0.6):
    """Best-effort reverse DNS lookup. Returns None if unresolved."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name
    except Exception:  # noqa: BLE001
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def probe_host(ip, ports, timeout=0.35):
    """Check a single host: is it alive, which ports respond open, and its hostname."""
    open_ports = []
    alive = False
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        try:
            result = sock.connect_ex((ip, port))
        except OSError:
            result = -1
        elapsed = time.time() - start
        sock.close()
        if result == 0:
            open_ports.append(port)
            alive = True
        elif elapsed < timeout * 0.85:
            alive = True

    hostname = resolve_hostname(ip) if alive else None
    return alive, open_ports, hostname


# ---------------------------------------------------------------------------
# Reusable styled widgets
# ---------------------------------------------------------------------------
class RoundedBG:
    """Mixin: paints a rounded rectangle background behind the widget."""

    def __init__(self, bg_color=SURFACE, radius=None, **kwargs):
        if radius is None:
            radius = dp(16)
        super().__init__(**kwargs)
        with self.canvas.before:
            self._bg_color_instr = Color(*bg_color)
            self._bg_rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[radius])
        self.bind(pos=self._update_rounded_bg, size=self._update_rounded_bg)

    def _update_rounded_bg(self, *_):
        self._bg_rect.pos = self.pos
        self._bg_rect.size = self.size

    def set_bg_color(self, color):
        self._bg_color_instr.rgba = color


class Card(RoundedBG, BoxLayout):
    """Rounded surface container used to group related controls."""

    def __init__(self, **kwargs):
        kwargs.setdefault("orientation", "vertical")
        kwargs.setdefault("padding", (dp(18), dp(18)))
        kwargs.setdefault("spacing", dp(14))
        kwargs.setdefault("size_hint_y", None)
        super().__init__(bg_color=SURFACE, radius=dp(18), **kwargs)
        self.bind(minimum_height=self.setter("height"))


class SectionLabel(Label):
    def __init__(self, **kwargs):
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(20))
        kwargs.setdefault("halign", "left")
        kwargs.setdefault("valign", "middle")
        kwargs.setdefault("font_size", "12sp")
        kwargs.setdefault("color", TEXT_MUTED)
        super().__init__(**kwargs)
        self.bind(size=lambda *_: setattr(self, "text_size", self.size))


class FieldInput(TextInput):
    """Single-line text field with text vertically centered in a fixed
    height (Kivy's TextInput otherwise clips the glyph tops when a fixed
    padding doesn't match the actual line height)."""

    def __init__(self, **kwargs):
        kwargs.setdefault("multiline", False)
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(50))
        kwargs.setdefault("font_size", "15sp")
        kwargs.setdefault("padding_x", dp(16))
        super().__init__(
            background_normal="",
            background_active="",
            background_color=SURFACE_2,
            foreground_color=TEXT,
            cursor_color=ACCENT,
            hint_text_color=TEXT_MUTED,
            **kwargs
        )
        self.bind(height=self._update_padding_y, line_height=self._update_padding_y)
        self._update_padding_y()

    def _update_padding_y(self, *_):
        self.padding_y = max(0, (self.height - self.line_height) / 2)


class SSHRawInput(TextInput):
    """A "raw terminal" input: every keystroke is forwarded immediately to
    the SSH channel (via the on_char/on_backspace callbacks), like a real
    terminal emulator (PuTTY, Termux etc) -- instead of the usual
    type-a-line-then-press-send pattern. The widget's own text buffer is
    kept intentionally always empty: what appears on screen is only the
    remote server's own echo, arriving through the terminal output above
    this field, exactly like a real SSH client. `insert_text` is
    overridden because that's how Kivy delivers typed characters from
    Android's on-screen keyboard (not key-by-key events); `do_backspace`
    is overridden because Android backspace goes through that method
    rather than a key code on most keyboards."""

    def __init__(self, on_char, on_backspace, **kwargs):
        super().__init__(**kwargs)
        self._on_char = on_char
        self._on_backspace = on_backspace

    def insert_text(self, substring, from_undo=False):
        if substring and self._on_char:
            self._on_char(substring)
        # Nao insere de verdade -- o "eco" do que foi digitado vem do
        # proprio servidor SSH, la' no terminal acima deste campo.
        return

    def do_backspace(self, from_undo=False, mode="bkspc"):
        if self._on_backspace:
            self._on_backspace()

    def keyboard_on_key_down(self, window, keycode, text, modifiers):
        code = keycode[1] if isinstance(keycode, (tuple, list)) else keycode
        arrows = {"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D"}
        if code in arrows:
            if self._on_char:
                self._on_char(arrows[code])
            return True
        return super().keyboard_on_key_down(window, keycode, text, modifiers)


class PrimaryButton(RoundedBG, ButtonBehavior, BoxLayout):
    """Primary call-to-action pill button with rounded corners."""

    def __init__(self, text, **kwargs):
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(50))
        super().__init__(bg_color=ACCENT, radius=dp(25), **kwargs)
        self.label = Label(text=text, color=BG, bold=True, font_size="15sp")
        self.add_widget(self.label)
        self.bind(on_press=lambda *_: self.set_bg_color((0.20, 0.60, 0.72, 1)))
        self.bind(on_release=lambda *_: self.set_bg_color(ACCENT))

    def set_text(self, text):
        self.label.text = text


class SmallDangerButton(RoundedBG, ButtonBehavior, BoxLayout):
    """Compact pill button used for destructive/ending actions (e.g. the
    "Encerrar" button on an active SSH session) -- dark red background,
    red text, matching the redesign's danger styling."""

    def __init__(self, text, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(92), dp(36)))
        super().__init__(bg_color=(0.25, 0.12, 0.12, 1), radius=dp(18), **kwargs)
        self.label = Label(text=text, color=DANGER, bold=True, font_size="12sp")
        self.add_widget(self.label)


class RefreshIcon(Widget):
    """Small circular-arrow icon drawn with vector graphics. Not all
    bundled Android fonts include the unicode refresh glyph (it was
    rendering as a blank box), so this draws the arrow directly instead
    of relying on a font glyph."""

    def __init__(self, color=ACCENT, **kwargs):
        kwargs.setdefault("size_hint", (1, 1))
        super().__init__(**kwargs)
        with self.canvas:
            Color(*color)
            self._arc = Line(width=dp(1.6))
            self._arrow = Line(width=dp(1.6))
        self.bind(pos=self._redraw, size=self._redraw)

    def _redraw(self, *_):
        cx, cy = self.center
        r = min(self.width, self.height) / 2 * 0.55
        if r <= 0:
            return
        start_deg, end_deg = 40, 320
        self._arc.circle = (cx, cy, r, start_deg, end_deg)
        end_rad = math.radians(end_deg)
        ax = cx + r * math.cos(end_rad)
        ay = cy + r * math.sin(end_rad)
        tangent = end_rad + math.pi / 2
        head = r * 0.6
        p1x = ax + head * math.cos(tangent + 2.6)
        p1y = ay + head * math.sin(tangent + 2.6)
        p2x = ax + head * math.cos(tangent - 2.6)
        p2y = ay + head * math.sin(tangent - 2.6)
        self._arrow.points = [p1x, p1y, ax, ay, p2x, p2y]


class SignalBarsIcon(Widget):
    """4 vertical bars of increasing height, like the Wi-Fi signal icon in
    the redesign mockup's Home network card. `set_level(n, color)` fills
    the first n bars with `color` and leaves the rest muted."""

    BAR_COUNT = 4

    def __init__(self, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(26), dp(16)))
        super().__init__(**kwargs)
        self._level = 0
        self._bar_colors = []
        self._bar_rects = []
        with self.canvas:
            for _ in range(self.BAR_COUNT):
                c = Color(*SURFACE_2)
                r = Rectangle()
                self._bar_colors.append(c)
                self._bar_rects.append(r)
        self.bind(pos=self._redraw, size=self._redraw)

    def set_level(self, level, active_color=SUCCESS):
        self._level = max(0, min(self.BAR_COUNT, level))
        for i, c in enumerate(self._bar_colors):
            c.rgba = active_color if i < self._level else SURFACE_2
        self._redraw()

    def _redraw(self, *_):
        n = self.BAR_COUNT
        gap = self.width * 0.14
        bar_w = (self.width - gap * (n - 1)) / n
        for i, rect in enumerate(self._bar_rects):
            frac = (i + 1) / n
            h = max(dp(2), self.height * frac)
            rect.pos = (self.x + i * (bar_w + gap), self.y)
            rect.size = (bar_w, h)


class ToolIcon(Widget):
    """Small vector line-icon drawn on canvas (no icon font is bundled with
    the app, so every glyph used in tiles/rows/buttons is hand-drawn with
    Line/Ellipse primitives instead, matching RefreshIcon/SignalBarsIcon
    above). `kind` selects which glyph to draw."""

    def __init__(self, kind, color=None, **kwargs):
        kwargs.setdefault("size_hint", (1, 1))
        super().__init__(**kwargs)
        self.kind = kind
        self.icon_color = color or BG
        self.bind(pos=self._redraw, size=self._redraw)

    def _redraw(self, *_):
        self.canvas.clear()
        w, h = self.width, self.height
        if w <= 0 or h <= 0:
            return
        cx, cy = self.center
        lw = max(dp(1.4), min(w, h) * 0.09)
        draw = getattr(self, "_draw_%s" % self.kind, self._draw_default)
        with self.canvas:
            Color(*self.icon_color)
            draw(cx, cy, w, h, lw)

    def _draw_default(self, cx, cy, w, h, lw):
        Line(circle=(cx, cy, min(w, h) * 0.28), width=lw)

    def _draw_ping(self, cx, cy, w, h, lw):
        x0 = cx - w * 0.34
        pts = [
            x0, cy,
            x0 + w * 0.16, cy,
            x0 + w * 0.25, cy + h * 0.30,
            x0 + w * 0.37, cy - h * 0.32,
            x0 + w * 0.48, cy,
            x0 + w * 0.68, cy,
        ]
        Line(points=pts, width=lw, joint="round", cap="round")

    def _draw_wifi(self, cx, cy, w, h, lw):
        base_y = cy - h * 0.18
        for r in (0.42, 0.26, 0.12):
            Line(circle=(cx, base_y, min(w, h) * r, 35, 145), width=lw)
        d = lw * 1.3
        Ellipse(pos=(cx - d / 2, base_y - d / 2), size=(d, d))

    def _draw_speed(self, cx, cy, w, h, lw):
        r = min(w, h) * 0.32
        Line(circle=(cx, cy, r, -200, 20), width=lw)
        Line(points=[cx, cy, cx + r * 0.55, cy + r * 0.5], width=lw, joint="round", cap="round")
        d = lw * 1.5
        Ellipse(pos=(cx - d / 2, cy - d / 2), size=(d, d))

    def _draw_ports(self, cx, cy, w, h, lw):
        body_w, body_h = w * 0.42, h * 0.32
        Line(rounded_rectangle=(cx - body_w / 2, cy - body_h / 2, body_w, body_h, dp(2)), width=lw)
        Line(circle=(cx, cy + body_h * 0.34, body_w * 0.32, 0, 180), width=lw)

    def _draw_scan(self, cx, cy, w, h, lw):
        top = (cx, cy + h * 0.30)
        left = (cx - w * 0.26, cy - h * 0.20)
        right = (cx + w * 0.26, cy - h * 0.20)
        Line(points=[top[0], top[1], left[0], left[1]], width=lw)
        Line(points=[top[0], top[1], right[0], right[1]], width=lw)
        Line(points=[left[0], left[1], right[0], right[1]], width=lw)
        r = min(w, h) * 0.075
        for px, py in (top, left, right):
            Ellipse(pos=(px - r, py - r), size=(r * 2, r * 2))

    def _draw_shell(self, cx, cy, w, h, lw):
        Line(rounded_rectangle=(cx - w * 0.36, cy - h * 0.30, w * 0.72, h * 0.60, dp(3)), width=lw)
        Line(
            points=[cx - w * 0.18, cy + h * 0.08, cx - w * 0.05, cy, cx - w * 0.18, cy - h * 0.08],
            width=lw, joint="round", cap="round",
        )
        Line(points=[cx, cy - h * 0.12, cx + w * 0.17, cy - h * 0.12], width=lw, cap="round")

    def _draw_ssh(self, cx, cy, w, h, lw):
        Line(rounded_rectangle=(cx - w * 0.34, cy - h * 0.02, w * 0.68, h * 0.46, dp(3)), width=lw)
        Line(points=[cx - w * 0.14, cy - h * 0.30, cx + w * 0.14, cy - h * 0.30], width=lw, cap="round")
        Line(points=[cx, cy - h * 0.02, cx, cy - h * 0.30], width=lw)

    def _draw_more(self, cx, cy, w, h, lw):
        r = min(w, h) * 0.065
        for dx in (-0.24, 0, 0.24):
            Ellipse(pos=(cx + w * dx - r, cy - r), size=(r * 2, r * 2))

    def _draw_gear(self, cx, cy, w, h, lw):
        r = min(w, h) * 0.22
        Line(circle=(cx, cy, r), width=lw)
        Line(circle=(cx, cy, r * 0.4), width=lw)
        for i in range(6):
            ang = math.radians(i * 60)
            x1 = cx + math.cos(ang) * r * 1.15
            y1 = cy + math.sin(ang) * r * 1.15
            x2 = cx + math.cos(ang) * r * 1.42
            y2 = cy + math.sin(ang) * r * 1.42
            Line(points=[x1, y1, x2, y2], width=lw)

    def _draw_person(self, cx, cy, w, h, lw):
        r = min(w, h) * 0.16
        Ellipse(pos=(cx - r, cy + h * 0.08 - r), size=(r * 2, r * 2))
        Line(circle=(cx, cy - h * 0.16, min(w, h) * 0.26, 200, 340), width=lw)

    def _draw_chevron(self, cx, cy, w, h, lw):
        s = min(w, h) * 0.24
        Line(
            points=[cx - s * 0.4, cy - s, cx + s * 0.4, cy, cx - s * 0.4, cy + s],
            width=lw, joint="round", cap="round",
        )

    def _draw_back(self, cx, cy, w, h, lw):
        s = min(w, h) * 0.24
        Line(
            points=[cx + s * 0.4, cy - s, cx - s * 0.4, cy, cx + s * 0.4, cy + s],
            width=lw, joint="round", cap="round",
        )

    def _draw_down(self, cx, cy, w, h, lw):
        # "download" arrow used next to the Speedtest gauge's "MBPS" label
        # -- drawn as a vector glyph because the down-arrow unicode
        # character isn't in the bundled font (renders as a tofu box).
        s = min(w, h) * 0.32
        Line(points=[cx, cy - s, cx, cy + s], width=lw, cap="round")
        Line(
            points=[cx - s * 0.6, cy - s * 0.1, cx, cy - s, cx + s * 0.6, cy - s * 0.1],
            width=lw, joint="round", cap="round",
        )


class SmallIconButton(RoundedBG, ButtonBehavior, BoxLayout):
    """Compact square button for a single symbol (e.g. refresh)."""

    def __init__(self, text=None, icon_widget=None, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(50), dp(50)))
        super().__init__(bg_color=SURFACE_2, radius=dp(14), **kwargs)
        if icon_widget is not None:
            self.add_widget(icon_widget)
        else:
            self.label = Label(text=text or "", color=ACCENT, bold=True, font_size="20sp")
            self.add_widget(self.label)
        self.bind(on_press=lambda *_: self.set_bg_color((0.22, 0.24, 0.29, 1)))
        self.bind(on_release=lambda *_: self.set_bg_color(SURFACE_2))


class CommandChip(RoundedBG, ButtonBehavior, BoxLayout):
    """Tappable example-command card: fills the terminal input on tap."""

    def __init__(self, command, description, on_pick, **kwargs):
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(46))
        kwargs.setdefault("orientation", "vertical")
        kwargs.setdefault("padding", (dp(12), dp(4)))
        super().__init__(bg_color=SURFACE_2, radius=dp(10), **kwargs)

        cmd_label = Label(
            text=command, font_size="13sp", bold=True, color=ACCENT,
            halign="left", valign="middle", size_hint_y=None, height=dp(20),
        )
        cmd_label.bind(size=lambda *_: setattr(cmd_label, "text_size", cmd_label.size))

        desc_label = Label(
            text=description, font_size="11sp", color=TEXT_MUTED,
            halign="left", valign="middle", size_hint_y=None, height=dp(18),
        )
        desc_label.bind(size=lambda *_: setattr(desc_label, "text_size", desc_label.size))

        self.add_widget(cmd_label)
        self.add_widget(desc_label)
        self.bind(on_release=lambda *_: on_pick(command))


class ResultBox(ScrollView):
    """Scrollable read-only output area used on every screen."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.label = Label(
            text="Resultados aparecem aqui...",
            size_hint_y=None,
            halign="left",
            valign="top",
            markup=True,
            font_size="14sp",
            color=TEXT,
            line_height=1.25,
        )
        self.label.bind(texture_size=self._update_height)
        self.label.bind(width=lambda *_: setattr(
            self.label, "text_size", (self.label.width, None)
        ))
        self.add_widget(self.label)

    def _update_height(self, *_):
        self.label.height = self.label.texture_size[1]

    def set_text(self, text):
        self.label.text = text


class NavButton(ButtonBehavior, BoxLayout):
    """Tab button: inactive tabs are plain muted text; the active tab gets
    a solid capsule ("chip") that hugs the text, Material-style."""

    def __init__(self, text, on_press_cb, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.label = Label(
            text=text,
            color=TEXT_MUTED,
            font_size="13sp",
            bold=False,
            halign="center",
            valign="middle",
            shorten=True,
        )
        self.label.bind(size=lambda *_: setattr(self.label, "text_size", self.label.size))
        with self.canvas.before:
            self._bg_color = Color(0, 0, 0, 0)
            self._bg_rect = RoundedRectangle(pos=self.pos, size=(0, 0), radius=[dp(15)])
        self.bind(pos=self._update_graphics, size=self._update_graphics)
        self.label.bind(texture_size=self._update_graphics)
        self.add_widget(self.label)
        self.bind(on_release=lambda *_: on_press_cb())

    def _update_graphics(self, *_):
        text_w = self.label.texture_size[0] if self.label.texture_size else 0
        pill_h = dp(30)
        pill_w = min(max(0, self.width - dp(4)), max(dp(44), text_w + dp(28)))
        pill_x = self.center_x - pill_w / 2
        pill_y = self.center_y - pill_h / 2
        self._bg_rect.pos = (pill_x, pill_y)
        self._bg_rect.size = (pill_w, pill_h)
        self._bg_rect.radius = [pill_h / 2]

    def set_active(self, active):
        if active:
            self.label.color = BG
            self.label.bold = True
            self._bg_color.rgba = ACCENT
        else:
            self.label.color = TEXT_MUTED
            self.label.bold = False
            self._bg_color.rgba = (0, 0, 0, 0)


class BackButton(RoundedBG, ButtonBehavior, BoxLayout):
    """Rounded-square back button used in the per-screen TopBar."""

    def __init__(self, on_back, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(36), dp(36)))
        super().__init__(bg_color=SURFACE_2, radius=dp(12), **kwargs)
        self.add_widget(ToolIcon(
            kind="back", color=ACCENT,
            size_hint=(0.5, 0.5), pos_hint={"center_x": 0.5, "center_y": 0.5},
        ))
        self.bind(on_release=lambda *_: on_back())


class TopBar(BoxLayout):
    """Per-screen header: back arrow + title (+ optional subtitle) and an
    optional right-side widget, replacing the old persistent top logo bar.
    Every tool screen now owns its own header, matching the redesigned
    visual (each screen is "full bleed" with its own title area)."""

    def __init__(self, title, subtitle=None, on_back=None, right_widget=None, **kwargs):
        kwargs.setdefault("orientation", "vertical")
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("padding", (0, dp(14), 0, dp(4)))
        kwargs.setdefault("spacing", dp(2))
        super().__init__(**kwargs)

        top_row = BoxLayout(size_hint_y=None, height=dp(36), spacing=dp(10))
        if on_back is not None:
            top_row.add_widget(BackButton(on_back))
        title_label = Label(
            text=title, font_size="19sp", bold=True, color=TEXT,
            halign="left", valign="middle",
        )
        title_label.bind(size=lambda *_: setattr(title_label, "text_size", title_label.size))
        top_row.add_widget(title_label)
        if right_widget is not None:
            top_row.add_widget(right_widget)
        self.add_widget(top_row)

        if subtitle:
            sub_label = Label(
                text=subtitle, font_size="12sp", color=TEXT_SECONDARY,
                halign="left", valign="middle", size_hint_y=None, height=dp(18),
            )
            sub_label.bind(size=lambda *_: setattr(sub_label, "text_size", sub_label.size))
            self.add_widget(sub_label)
            self.height = dp(74)
        else:
            self.height = dp(52)


class ToolTile(RoundedBG, ButtonBehavior, BoxLayout):
    """Square tile used in the Home dashboard's tool grid: an accent icon
    badge (vector glyph, since we don't bundle an icon font) plus a label.
    Tapping navigates straight to that tool's screen."""

    def __init__(self, label, icon, on_press_cb, **kwargs):
        kwargs.setdefault("orientation", "vertical")
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(92))
        kwargs.setdefault("padding", (dp(6), dp(12)))
        kwargs.setdefault("spacing", dp(8))
        super().__init__(bg_color=SURFACE, radius=dp(16), **kwargs)

        badge_wrap = BoxLayout(size_hint=(None, None), size=(dp(36), dp(36)), pos_hint={"center_x": 0.5})
        with badge_wrap.canvas.before:
            Color(*ACCENT)
            self._badge_rect = RoundedRectangle(pos=badge_wrap.pos, size=badge_wrap.size, radius=[dp(10)])
        badge_wrap.bind(pos=self._sync_badge, size=self._sync_badge)
        badge_wrap.add_widget(ToolIcon(
            kind=icon, color=BG, size_hint=(0.6, 0.6), pos_hint={"center_x": 0.5, "center_y": 0.5},
        ))
        self.add_widget(badge_wrap)

        text_label = Label(
            text=label, color=TEXT, font_size="12sp", halign="center", valign="middle",
            size_hint_y=None, height=dp(28),
        )
        text_label.bind(size=lambda *_: setattr(text_label, "text_size", text_label.size))
        self.add_widget(text_label)

        self.bind(on_release=lambda *_: on_press_cb())

    def _sync_badge(self, widget, *_):
        self._badge_rect.pos = widget.pos
        self._badge_rect.size = widget.size


class MoreListItem(RoundedBG, ButtonBehavior, BoxLayout):
    """Row used inside the "Mais" bottom sheet and lists like SSH's saved
    hosts: icon badge + label + sub + trailing chevron."""

    def __init__(self, label, sub, icon, on_press_cb, **kwargs):
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(64))
        kwargs.setdefault("padding", (dp(14), dp(8)))
        kwargs.setdefault("spacing", dp(14))
        super().__init__(bg_color=SURFACE_2, radius=dp(14), **kwargs)

        badge_wrap = BoxLayout(size_hint=(None, None), size=(dp(38), dp(38)))
        with badge_wrap.canvas.before:
            Color(*ACCENT)
            self._badge_rect = RoundedRectangle(pos=badge_wrap.pos, size=badge_wrap.size, radius=[dp(10)])
        badge_wrap.bind(pos=self._sync_badge, size=self._sync_badge)
        badge_wrap.add_widget(ToolIcon(
            kind=icon, color=BG, size_hint=(0.6, 0.6), pos_hint={"center_x": 0.5, "center_y": 0.5},
        ))
        self.add_widget(badge_wrap)

        text_col = BoxLayout(orientation="vertical", spacing=dp(2))
        title_label = Label(
            text=label, color=TEXT, font_size="14sp", bold=True,
            halign="left", valign="middle",
        )
        title_label.bind(size=lambda *_: setattr(title_label, "text_size", title_label.size))
        sub_label = Label(
            text=sub, color=TEXT_SECONDARY, font_size="11sp",
            halign="left", valign="middle",
        )
        sub_label.bind(size=lambda *_: setattr(sub_label, "text_size", sub_label.size))
        text_col.add_widget(title_label)
        text_col.add_widget(sub_label)
        self.add_widget(text_col)

        self.add_widget(ToolIcon(
            kind="chevron", color=TEXT_MUTED,
            size_hint=(None, None), size=(dp(14), dp(24)),
        ))

        self.bind(on_release=lambda *_: on_press_cb())

    def _sync_badge(self, widget, *_):
        self._badge_rect.pos = widget.pos
        self._badge_rect.size = widget.size


class _Scrim(ButtonBehavior, Widget):
    """Invisible full-screen tap target used to dismiss the More sheet."""
    pass


class MoreSheet(FloatLayout):
    """Bottom-sheet overlay listing the tools that don't get their own
    bottom-nav slot (Portas, Varredura, Terminal, SSH). Hidden by default
    (opacity 0 + disabled) so it doesn't intercept touches until opened."""

    def __init__(self, items, on_close, **kwargs):
        super().__init__(**kwargs)
        self.opacity = 0
        self.disabled = True

        self.scrim = _Scrim()
        with self.scrim.canvas:
            Color(0, 0, 0, 0.55)
            self._scrim_rect = Rectangle(pos=self.scrim.pos, size=self.scrim.size)
        self.scrim.bind(pos=self._sync_scrim, size=self._sync_scrim)
        self.scrim.bind(on_release=lambda *_: on_close())
        self.add_widget(self.scrim)

        panel = BoxLayout(
            orientation="vertical", size_hint=(1, None), height=dp(340),
            pos_hint={"x": 0, "y": 0},
            padding=(dp(18), dp(18), dp(18), dp(18)), spacing=dp(10),
        )
        with panel.canvas.before:
            Color(*SURFACE)
            self._panel_rect = RoundedRectangle(
                pos=panel.pos, size=panel.size, radius=[dp(20), dp(20), 0, 0]
            )
        panel.bind(pos=self._sync_panel, size=self._sync_panel)

        panel.add_widget(SectionLabel(text="MAIS FERRAMENTAS"))
        for label, sub, badge, cb in items:
            item = MoreListItem(label, sub, badge, on_press_cb=lambda cb=cb: (on_close(), cb()))
            panel.add_widget(item)

        self.add_widget(panel)

    def _sync_scrim(self, widget, *_):
        self._scrim_rect.pos = widget.pos
        self._scrim_rect.size = widget.size

    def _sync_panel(self, widget, *_):
        self._panel_rect.pos = widget.pos
        self._panel_rect.size = widget.size

    def show(self):
        self.opacity = 1
        self.disabled = False

    def hide(self):
        self.opacity = 0
        self.disabled = True


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------
class PingScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(16))
        root.add_widget(TopBar("Ping", "Teste de conectividade ICMP", on_back=_go_home))

        card = Card()
        card.add_widget(SectionLabel(text="Host / IP"))
        self.host_input = FieldInput(text="8.8.8.8", hint_text="ex: 8.8.8.8")
        card.add_widget(self.host_input)
        self.run_btn = PrimaryButton("Testar ping")
        self.run_btn.bind(on_release=self.start_ping)
        card.add_widget(self.run_btn)

        self.result = ResultBox()

        root.add_widget(card)
        root.add_widget(self.result)
        self.add_widget(root)

    def start_ping(self, *_):
        host = self.host_input.text.strip() or "8.8.8.8"
        self.result.set_text("Testando ping em %s..." % host)
        self._ping(host)

    @run_in_thread
    def _ping(self, host):
        count_flag = "-n" if platform.system() == "Windows" else "-c"
        candidates = ["ping", "/system/bin/ping"]
        output, error = None, None
        for binary in candidates:
            try:
                proc = subprocess.run(
                    [binary, count_flag, "4", host],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = proc.stdout or proc.stderr
                break
            except FileNotFoundError:
                continue
            except Exception as e:  # noqa: BLE001
                error = str(e)

        text = output if output else ("Erro: %s" % (error or "ping indisponivel"))
        success = "bytes from" in text or "0% packet loss" in text
        app = App.get_running_app()
        if app is not None:
            Clock.schedule_once(lambda dt: app.log_activity(
                "Ping · %s" % host, "Concluido" if success else "Sem resposta",
                color=SUCCESS if success else DANGER,
            ))
        Clock.schedule_once(lambda dt: self.result.set_text(text))


class WifiScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(16))
        root.add_widget(TopBar("Wi-Fi", "Informacoes da rede e redes proximas", on_back=_go_home))

        card = Card()
        self.run_btn = PrimaryButton("Verificar Wi-Fi")
        self.run_btn.bind(on_release=self.start_check)
        card.add_widget(self.run_btn)
        self.scan_btn = PrimaryButton("Escanear redes proximas")
        self.scan_btn.bind(on_release=self.start_scan)
        card.add_widget(self.scan_btn)

        self.result = ResultBox()

        root.add_widget(card)
        root.add_widget(self.result)
        self.add_widget(root)

    def start_check(self, *_):
        self.result.set_text("Lendo informacoes de Wi-Fi...")
        self._check()

    @run_in_thread
    def _check(self):
        if IS_ANDROID:
            try:
                from jnius import autoclass, cast

                PythonActivity = autoclass("org.kivy.android.PythonActivity")
                Context = autoclass("android.content.Context")
                activity = PythonActivity.mActivity
                wifi_manager = cast(
                    "android.net.wifi.WifiManager",
                    activity.getSystemService(Context.WIFI_SERVICE),
                )
                info = wifi_manager.getConnectionInfo()
                dhcp = None
                try:
                    dhcp = wifi_manager.getDhcpInfo()
                except Exception:  # noqa: BLE001
                    dhcp = None

                ssid = info.getSSID()
                bssid = info.getBSSID()
                mac = info.getMacAddress()
                rssi = info.getRssi()
                link_speed = info.getLinkSpeed()
                frequency = info.getFrequency()
                network_id = info.getNetworkId()
                ip_addr = _int_to_ip(info.getIpAddress())

                gateway = _int_to_ip(dhcp.gateway) if dhcp else "?"
                netmask = _int_to_ip(dhcp.netmask) if dhcp else "?"
                dns1 = _int_to_ip(dhcp.dns1) if dhcp else "?"
                dns2 = _int_to_ip(dhcp.dns2) if dhcp else "?"

                channel = _freq_to_channel(frequency)
                quality = _signal_quality(rssi)

                text = (
                    "[b]SSID:[/b] %s\n"
                    "[b]BSSID:[/b] %s\n"
                    "[b]MAC do dispositivo:[/b] %s\n"
                    "[b]IP:[/b] %s\n"
                    "[b]Gateway:[/b] %s\n"
                    "[b]Mascara:[/b] %s\n"
                    "[b]DNS 1:[/b] %s\n"
                    "[b]DNS 2:[/b] %s\n"
                    "[b]Sinal (RSSI):[/b] %s dBm (%s)\n"
                    "[b]Velocidade do link:[/b] %s Mbps\n"
                    "[b]Frequencia:[/b] %s MHz (canal %s)\n"
                    "[b]ID da rede:[/b] %s\n\n"
                    "Nota: no Android 8+ e' preciso conceder permissao de "
                    "Localizacao para o SSID aparecer corretamente. O MAC "
                    "pode aparecer como 02:00:00:00:00:00 por restricao "
                    "de privacidade do sistema."
                ) % (
                    ssid, bssid, mac, ip_addr, gateway, netmask, dns1, dns2,
                    rssi, quality, link_speed, frequency,
                    channel if channel else "?", network_id,
                )
            except Exception as e:  # noqa: BLE001
                text = (
                    "Nao foi possivel ler o Wi-Fi via Android API.\n"
                    "Erro: %s" % e
                )
        else:
            text = (
                "Leitura de Wi-Fi via API Android so funciona no celular.\n"
                "Rodando em desktop apenas para teste da interface."
            )

        Clock.schedule_once(lambda dt: self.result.set_text(text))

    def start_scan(self, *_):
        if not IS_ANDROID:
            self.result.set_text(
                "Escaneamento de redes so funciona no celular (API Android)."
            )
            return
        self.result.set_text("Escaneando redes proximas...")
        self._scan()

    @run_in_thread
    def _scan(self):
        try:
            from jnius import autoclass, cast

            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            Context = autoclass("android.content.Context")
            activity = PythonActivity.mActivity
            wifi_manager = cast(
                "android.net.wifi.WifiManager",
                activity.getSystemService(Context.WIFI_SERVICE),
            )
            wifi_manager.startScan()
            time.sleep(2.5)
            results = wifi_manager.getScanResults()

            networks = []
            for i in range(results.size()):
                r = results.get(i)
                ssid = r.SSID or "(oculto)"
                bssid = r.BSSID
                level = r.level
                freq = r.frequency
                capabilities = r.capabilities or ""
                if "WPA" in capabilities:
                    security = "WPA/WPA2"
                elif "WEP" in capabilities:
                    security = "WEP"
                else:
                    security = "Aberta"
                channel = _freq_to_channel(freq)
                networks.append((level, ssid, bssid, channel, security))

            networks.sort(key=lambda n: -n[0])

            if not networks:
                text = (
                    "Nenhuma rede encontrada. Alguns aparelhos limitam a "
                    "frequencia de scans -- tente novamente em alguns "
                    "segundos, ou confira se a Localizacao esta ativada."
                )
            else:
                lines = ["[b]Redes encontradas: %d[/b]\n" % len(networks)]
                for level, ssid, bssid, channel, security in networks:
                    lines.append(
                        "[b][color=45B8D9]%s[/color][/b]  (%s)\n"
                        "Sinal: %s dBm  |  Canal: %s  |  Seguranca: %s"
                        % (ssid, bssid, level, channel if channel else "?", security)
                    )
                text = "\n\n".join(lines)
        except Exception as e:  # noqa: BLE001
            text = "Erro ao escanear redes: %s" % e

        Clock.schedule_once(lambda dt: self.result.set_text(text))


class SpeedGauge(FloatLayout):
    """Circular dial showing the last measured download speed, matching
    the redesign mockup's "0.0 MBPS" ring (replaces the old plain button
    + text-only result for the Speedtest screen)."""

    def __init__(self, **kwargs):
        kwargs.setdefault("size_hint", (None, None))
        kwargs.setdefault("size", (dp(200), dp(200)))
        super().__init__(**kwargs)
        with self.canvas:
            Color(*SURFACE_2)
            self._ring = Line(width=dp(10))
        self.bind(pos=self._redraw, size=self._redraw)

        self.value_label = Label(
            text="0.0", font_size="34sp", bold=True, color=TEXT,
            size_hint=(1, None), height=dp(44),
            pos_hint={"center_x": 0.5, "center_y": 0.58},
            halign="center", valign="middle",
        )
        self.add_widget(self.value_label)

        sub_row = BoxLayout(
            size_hint=(None, None), size=(dp(56), dp(18)), spacing=dp(3),
            pos_hint={"center_x": 0.5, "center_y": 0.40},
        )
        self.sub_label = Label(
            text="MBPS", font_size="12sp", bold=True, color=ACCENT,
            size_hint=(None, 1), width=dp(42),
            halign="right", valign="middle",
        )
        self.sub_label.bind(size=lambda *_: setattr(self.sub_label, "text_size", self.sub_label.size))
        sub_row.add_widget(self.sub_label)
        sub_row.add_widget(ToolIcon(
            kind="down", color=ACCENT, size_hint=(None, None), size=(dp(12), dp(12)),
        ))
        self.add_widget(sub_row)
        self._redraw()

    def _redraw(self, *_):
        r = min(self.width, self.height) / 2 - dp(6)
        if r <= 0:
            return
        self._ring.circle = (self.center_x, self.center_y, r)

    def set_value(self, mbps):
        self.value_label.text = "%.1f" % mbps

    def set_text(self, text):
        self.value_label.text = text


class SpeedtestScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(24))
        root.add_widget(TopBar("Speedtest", "Velocidade de download", on_back=_go_home))

        gauge_wrap = BoxLayout(size_hint_y=None, height=dp(220))
        self.gauge = SpeedGauge(pos_hint={"center_x": 0.5, "center_y": 0.5})
        gauge_wrap.add_widget(self.gauge)
        root.add_widget(gauge_wrap)

        self.run_btn = PrimaryButton("Rodar speedtest")
        self.run_btn.bind(on_release=self.start_test)
        root.add_widget(self.run_btn)

        self.result = ResultBox()

        root.add_widget(self.result)
        self.add_widget(root)

    def start_test(self, *_):
        self.gauge.set_text("...")
        self.result.set_text("Rodando speedtest, isso pode levar alguns segundos...")
        self._speedtest()

    @run_in_thread
    def _speedtest(self):
        import urllib.request

        test_urls = [
            "https://speed.cloudflare.com/__down?bytes=10000000",
            "https://speed.hetzner.de/10MB.bin",
            "https://proof.ovh.net/files/10Mb.dat",
            "https://ipv4.download.thinkbroadband.com/10MB.zip",
            "https://speedtest.tele2.net/10MB.zip",
        ]
        max_seconds = 8.0

        errors = []
        text = None
        result_mbps = None
        for test_url in test_urls:
            try:
                start = time.time()
                total_bytes = 0
                with urllib.request.urlopen(test_url, timeout=10, context=_SSL_CONTEXT) as resp:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if time.time() - start > max_seconds:
                            break
                elapsed = time.time() - start

                if elapsed > 0 and total_bytes > 0:
                    mbps = (total_bytes * 8 / 1_000_000) / elapsed
                    result_mbps = mbps
                    text = (
                        "[b]Download:[/b] %.2f Mbps\n"
                        "[b]Baixado:[/b] %.1f MB em %.1fs\n"
                        "[b]Servidor:[/b] %s\n\n"
                        "Nota: teste simplificado (somente download), "
                        "sem dependencias externas."
                    ) % (mbps, total_bytes / 1_000_000, elapsed, test_url)
                    break
                else:
                    errors.append("%s: sem dados recebidos" % test_url)
            except Exception as e:  # noqa: BLE001
                errors.append("%s: %s" % (test_url, e))

        if text is None:
            text = (
                "Nao foi possivel rodar o speedtest em nenhum servidor:\n\n"
                + "\n".join(errors)
                + "\n\nVerifique a conexao com a internet do aparelho."
            )

        if result_mbps is not None:
            Clock.schedule_once(lambda dt: self.gauge.set_value(result_mbps))
        else:
            Clock.schedule_once(lambda dt: self.gauge.set_text("0.0"))

        app = App.get_running_app()
        if app is not None:
            if result_mbps is not None:
                Clock.schedule_once(lambda dt: app.log_activity(
                    "Speedtest", "%.1f Mbps" % result_mbps, color=SUCCESS,
                ))
            else:
                Clock.schedule_once(lambda dt: app.log_activity(
                    "Speedtest", "Falhou", color=DANGER,
                ))

        Clock.schedule_once(lambda dt: self.result.set_text(text))


class PortScanScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(16))
        root.add_widget(TopBar("Scanner de portas", "Verifique portas TCP abertas", on_back=_go_home))

        card = Card()
        card.add_widget(SectionLabel(text="Host / IP"))
        self.host_input = FieldInput(text="192.168.0.1")
        card.add_widget(self.host_input)
        card.add_widget(SectionLabel(text="Portas (separadas por virgula)"))
        self.ports_input = FieldInput(text="21,22,23,25,53,80,110,143,443,445,3389,8080")
        card.add_widget(self.ports_input)
        self.run_btn = PrimaryButton("Escanear portas")
        self.run_btn.bind(on_release=self.start_scan)
        card.add_widget(self.run_btn)

        self.result = ResultBox()

        root.add_widget(card)
        root.add_widget(self.result)
        self.add_widget(root)

    def start_scan(self, *_):
        host = self.host_input.text.strip()
        raw_ports = self.ports_input.text.strip()
        try:
            ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
        except ValueError:
            self.result.set_text("Lista de portas invalida.")
            return

        if not host or not ports:
            self.result.set_text("Informe host e ao menos uma porta.")
            return

        self.result.set_text("Escaneando %d portas em %s..." % (len(ports), host))
        self._scan(host, ports)

    @run_in_thread
    def _scan(self, host, ports):
        open_ports = []
        closed_count = 0

        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            Clock.schedule_once(
                lambda dt: self.result.set_text("Nao foi possivel resolver o host: %s" % host)
            )
            return

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((resolved_ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
            else:
                closed_count += 1

        lines = ["[b]Host:[/b] %s (%s)" % (host, resolved_ip), ""]
        if open_ports:
            lines.append("[b]Portas abertas:[/b] " + ", ".join(str(p) for p in open_ports))
        else:
            lines.append("Nenhuma porta aberta encontrada.")
        lines.append("[b]Portas fechadas/filtradas:[/b] %d" % closed_count)

        text = "\n".join(lines)
        Clock.schedule_once(lambda dt: self.result.set_text(text))


class NetworkScanScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(16))
        root.add_widget(TopBar("Varredura de rede", "Descubra hosts ativos", on_back=_go_home))

        card = Card()
        card.add_widget(SectionLabel(text="Rede (CIDR)"))
        subnet_row = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        self.subnet_input = FieldInput(text="detectando rede...")
        subnet_row.add_widget(self.subnet_input)
        self.refresh_btn = SmallIconButton(icon_widget=RefreshIcon())
        self.refresh_btn.bind(on_release=self.refresh_subnet)
        subnet_row.add_widget(self.refresh_btn)
        card.add_widget(subnet_row)
        card.add_widget(SectionLabel(text="Portas a checar (separadas por virgula)"))
        self.ports_input = FieldInput(text="22,80,443,445,3389")
        card.add_widget(self.ports_input)
        self.run_btn = PrimaryButton("Varrer rede")
        self.run_btn.bind(on_release=self.start_scan)
        card.add_widget(self.run_btn)

        self.result = ResultBox()

        root.add_widget(card)
        root.add_widget(self.result)
        self.add_widget(root)

        self._found_lines = []
        self._detect_subnet()

    @run_in_thread
    def _detect_subnet(self):
        subnet = get_local_subnet()
        Clock.schedule_once(lambda dt: setattr(self.subnet_input, "text", subnet))

    def refresh_subnet(self, *_):
        self.subnet_input.text = "detectando rede..."
        self._detect_subnet()

    def start_scan(self, *_):
        raw_subnet = self.subnet_input.text.strip() or get_local_subnet()
        raw_ports = self.ports_input.text.strip()

        try:
            ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
        except ValueError:
            self.result.set_text("Lista de portas invalida.")
            return

        try:
            if "/" not in raw_subnet:
                raw_subnet = raw_subnet + "/24"
            network = ipaddress.ip_network(raw_subnet, strict=False)
        except ValueError:
            self.result.set_text("Rede invalida. Use algo como 192.168.0.0/24.")
            return

        hosts = list(network.hosts())
        if len(hosts) > 1024:
            self.result.set_text(
                "Rede muito grande (%d hosts). Use uma faixa /22 ou menor." % len(hosts)
            )
            return

        self._found_lines = []
        self.result.set_text(
            "Varrendo %s (%d hosts)... isso pode levar de 10 a 60s." % (str(network), len(hosts))
        )
        self._scan(hosts, ports)

    @run_in_thread
    def _scan(self, hosts, ports):
        alive_hosts = []

        with ThreadPoolExecutor(max_workers=60) as pool:
            futures = {pool.submit(probe_host, str(ip), ports): str(ip) for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    alive, open_ports, hostname = future.result()
                except Exception:  # noqa: BLE001
                    continue
                if alive:
                    alive_hosts.append((ip, open_ports, hostname))
                    self._found_lines.append(self._format_host(ip, open_ports, hostname))
                    snapshot = list(self._found_lines)
                    Clock.schedule_once(
                        lambda dt, s=snapshot: self.result.set_text(
                            "[b]Encontrados ate agora: %d[/b]\n\n" % len(s) + "\n\n".join(s)
                        )
                    )

        alive_hosts.sort(key=lambda item: tuple(int(p) for p in item[0].split(".")))
        lines = [self._format_host(ip, open_ports, hostname) for ip, open_ports, hostname in alive_hosts]

        header = "[b]Hosts ativos encontrados: %d[/b]\n\n" % len(alive_hosts)
        final_text = header + ("\n\n".join(lines) if lines else "Nenhum host respondeu.")
        Clock.schedule_once(lambda dt: self.result.set_text(final_text))

        app = App.get_running_app()
        if app is not None:
            count = len(alive_hosts)
            Clock.schedule_once(lambda dt: app.log_activity(
                "Varredura de rede", "%d hosts encontrados" % count, color=ACCENT,
            ))

    @staticmethod
    def _format_host(ip, open_ports, hostname):
        ports_text = ", ".join(str(p) for p in open_ports) if open_ports else "nenhuma das checadas"
        name_text = hostname if hostname else "(nome nao identificado)"
        return "[b][color=45B8D9]%s[/color][/b]  [color=999999]%s[/color]\nPortas abertas: %s" % (
            ip, name_text, ports_text
        )


class TerminalScreen(Screen):
    """Simple shell-command runner. On Android this uses the device's
    restricted /system/bin/sh (no root), so only basic tools are available
    (ping, ip, cat, ls, netstat when present, etc.) -- no su/root access."""

    HISTORY_LIMIT = 20

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(16))
        root.add_widget(TopBar("Terminal", "Comandos de shell, sem root", on_back=_go_home))

        card = Card()
        card.add_widget(SectionLabel(text="Comando"))
        self.cmd_input = FieldInput(text="ip addr", hint_text="ex: ping -c 4 8.8.8.8")
        card.add_widget(self.cmd_input)
        self.run_btn = PrimaryButton("Executar")
        self.run_btn.bind(on_release=self.start_run)
        card.add_widget(self.run_btn)

        examples_card = Card()
        examples_card.add_widget(SectionLabel(text="Comandos de exemplo (toque para usar)"))
        examples_scroll = ScrollView(size_hint_y=None, height=dp(180))
        examples_grid = GridLayout(cols=1, spacing=dp(8), size_hint_y=None)
        examples_grid.bind(minimum_height=examples_grid.setter("height"))
        for command, description in TERMINAL_COMMANDS:
            examples_grid.add_widget(CommandChip(command, description, on_pick=self._pick_command))
        examples_scroll.add_widget(examples_grid)
        examples_card.add_widget(examples_scroll)

        self.result = ResultBox()
        self.result.set_text(
            "Digite um comando simples e toque em Executar.\n\n"
            "Nota: o app roda sem root, num shell restrito do proprio "
            "Android. Comandos que leem /proc/net/* ou usam sockets "
            "netlink (ip addr, ip route) sao bloqueados pelo sistema "
            "para qualquer app sem root, independente de qualquer "
            "permissao que o app declare -- e' uma restricao de "
            "seguranca do proprio Android. Comandos como ping, getprop, "
            "id, uname e df costumam funcionar normalmente."
        )

        root.add_widget(card)
        root.add_widget(examples_card)
        root.add_widget(self.result)
        self.add_widget(root)

    def _pick_command(self, command):
        self.cmd_input.text = command

    def start_run(self, *_):
        command = self.cmd_input.text.strip()
        if not command:
            self.result.set_text("Digite um comando primeiro.")
            return
        self.result.set_text("Executando: %s ..." % command)
        self._run(command)

    @run_in_thread
    def _run(self, command):
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            if not output.strip():
                output = "(sem saida, codigo de retorno: %d)" % proc.returncode
            else:
                output = output.rstrip() + "\n\n(codigo de retorno: %d)" % proc.returncode
        except subprocess.TimeoutExpired:
            output = "Comando excedeu o tempo limite (20s)."
        except Exception as e:  # noqa: BLE001
            output = "Erro ao executar: %s" % e

        text = "[b]$ %s[/b]\n\n%s" % (command, output)
        Clock.schedule_once(lambda dt: self.result.set_text(text))


class SSHScreen(Screen):
    """Terminal SSH interativo, estilo PuTTY: conecta a um servidor remoto
    via usuario/senha e mantem um shell aberto, com digitacao direta no
    terminal (sem campo de comando separado) e uma lista de hosts salvos
    para reconectar rapido.

    Implementado com JSch (biblioteca SSH2 100% Java, sem nenhum codigo
    nativo) via pyjnius, em vez de paramiko. paramiko dependia de bcrypt,
    pynacl e cryptography -- todas bibliotecas com codigo nativo (C/Rust)
    que se mostraram extremamente frageis ou impossiveis de cross-compilar
    para Android nesta toolchain (python-for-android + NDK r25b). Como o
    JSch e' Java puro, o Gradle simplesmente baixa a biblioteca pronta
    (ver android.add_jars no buildozer.spec) -- nao ha' nada para compilar.

    A tela tem duas "vistas" trocadas via clear_widgets()/add_widget():
    _show_setup() (lista de hosts salvos + formulario de nova conexao) e
    _show_terminal() (terminal em tela cheia, estilo PuTTY de verdade)."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.saved_hosts = _load_ssh_hosts()

        self.session = None
        self.channel = None
        self.input_stream = None
        self.output_stream = None
        self._connected = False
        self._buffer = ""
        self._last_host = ""
        self._last_user = ""

        self.root_box = BoxLayout(orientation="vertical")
        self.add_widget(self.root_box)
        self._show_setup()

    # ------------------------------------------------------------------
    # Vista 1: hosts salvos + formulario de nova conexao
    # ------------------------------------------------------------------
    def _show_setup(self):
        self.root_box.clear_widgets()
        self.root_box.padding = (dp(18), dp(18))
        self.root_box.spacing = dp(14)
        profile_btn = SmallIconButton(
            icon_widget=ToolIcon(
                kind="person", color=ACCENT, size_hint=(0.55, 0.55),
                pos_hint={"center_x": 0.5, "center_y": 0.5},
            ),
            size=(dp(36), dp(36)),
        )
        profile_btn.bind(on_release=self._focus_new_connection)
        self.root_box.add_widget(TopBar(
            "SSH", "Terminal remoto interativo", on_back=_go_home, right_widget=profile_btn,
        ))

        scroll = ScrollView()
        inner = BoxLayout(orientation="vertical", spacing=dp(14), size_hint_y=None)
        inner.bind(minimum_height=inner.setter("height"))

        if self.saved_hosts:
            inner.add_widget(SectionLabel(text="HOSTS SALVOS"))
            for idx in range(len(self.saved_hosts)):
                inner.add_widget(self._build_saved_host_row(idx))

        inner.add_widget(SectionLabel(text="NOVA CONEXAO"))
        card = Card()
        card.add_widget(SectionLabel(text="Nome (opcional)"))
        self.name_input = FieldInput(hint_text="ex: NAS Synology")
        card.add_widget(self.name_input)

        card.add_widget(SectionLabel(text="Host e porta"))
        row1 = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8))
        self.host_input = FieldInput(hint_text="ex: 192.168.0.10", size_hint_x=0.7)
        self.port_input = FieldInput(text="22", size_hint_x=0.3)
        row1.add_widget(self.host_input)
        row1.add_widget(self.port_input)
        card.add_widget(row1)

        card.add_widget(SectionLabel(text="Usuario"))
        self.user_input = FieldInput(hint_text="ex: root")
        card.add_widget(self.user_input)

        card.add_widget(SectionLabel(text="Senha"))
        self.pass_input = FieldInput(password=True)
        card.add_widget(self.pass_input)

        save_row = BoxLayout(size_hint_y=None, height=dp(34), spacing=dp(8))
        # CheckBox nao tem uma propriedade "color" generica no Kivy (a
        # aparencia dela vem de imagens internas, nao de uma cor simples),
        # entao nao da' pra recolorir facil -- deixa no estilo padrao.
        self.save_check = CheckBox(size_hint=(None, None), size=(dp(28), dp(28)))
        save_row.add_widget(self.save_check)
        save_label = Label(
            text="Salvar este host (com senha) para conectar rapido depois",
            font_size="12sp", color=TEXT_SECONDARY, halign="left", valign="middle",
        )
        save_label.bind(size=lambda *_: setattr(save_label, "text_size", save_label.size))
        save_row.add_widget(save_label)
        card.add_widget(save_row)

        self.connect_btn = PrimaryButton("Conectar")
        self.connect_btn.bind(on_release=lambda *_: self.connect(maybe_save=True))
        card.add_widget(self.connect_btn)

        self.status_label = Label(
            text="Desconectado", size_hint_y=None, height=dp(20),
            font_size="12sp", color=TEXT_MUTED,
        )
        card.add_widget(self.status_label)

        inner.add_widget(card)
        scroll.add_widget(inner)
        self.root_box.add_widget(scroll)

    def _focus_new_connection(self, *_):
        if getattr(self, "host_input", None) is not None:
            self.host_input.focus = True

    def _build_saved_host_row(self, idx):
        h = self.saved_hosts[idx]
        row = BoxLayout(size_hint_y=None, height=dp(64), spacing=dp(8))
        label = h.get("name") or ("%s@%s" % (h.get("user") or "?", h.get("host") or "?"))
        sub = "%s@%s:%s" % (h.get("user") or "?", h.get("host") or "?", h.get("port") or "22")
        item = MoreListItem(label, sub, "ssh", on_press_cb=lambda i=idx: self._connect_saved(i))
        row.add_widget(item)
        del_btn = SmallIconButton(text="x")
        del_btn.bind(on_release=lambda *_, i=idx: self._delete_saved(i))
        row.add_widget(del_btn)
        return row

    def _delete_saved(self, idx):
        try:
            del self.saved_hosts[idx]
        except IndexError:
            return
        _save_ssh_hosts(self.saved_hosts)
        self._show_setup()

    def _connect_saved(self, idx):
        try:
            h = self.saved_hosts[idx]
        except IndexError:
            return
        self.connect(
            host=h.get("host", ""), port=h.get("port", "22"),
            user=h.get("user", ""), password=h.get("password", ""),
            maybe_save=False,
        )

    # ------------------------------------------------------------------
    # Vista 2: terminal em tela cheia (estilo PuTTY)
    # ------------------------------------------------------------------
    def _show_terminal(self):
        self.root_box.clear_widgets()
        self.root_box.padding = (dp(14), dp(14))
        self.root_box.spacing = dp(10)

        header = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(10))
        header.add_widget(BackButton(on_back=self.disconnect))

        title_col = BoxLayout(orientation="vertical")
        title_row = BoxLayout(size_hint_y=None, height=dp(20), spacing=dp(6))
        dot = Widget(size_hint=(None, None), size=(dp(9), dp(9)))
        with dot.canvas:
            Color(*SUCCESS)
            dot_ellipse = Ellipse(pos=dot.pos, size=dot.size)
        dot.bind(pos=lambda w, *_: setattr(dot_ellipse, "pos", w.pos))
        title_row.add_widget(dot)
        session_label = Label(
            text="%s@%s" % (self._last_user or "?", self._last_host or "?"),
            color=TEXT, bold=True, font_size="15sp",
            halign="left", valign="middle",
        )
        session_label.bind(size=lambda *_: setattr(session_label, "text_size", session_label.size))
        title_row.add_widget(session_label)
        title_col.add_widget(title_row)

        sub_label = Label(
            text="Sessao SSH ativa", color=TEXT_MUTED, font_size="11sp",
            halign="left", valign="middle", size_hint_y=None, height=dp(16),
        )
        sub_label.bind(size=lambda *_: setattr(sub_label, "text_size", sub_label.size))
        title_col.add_widget(sub_label)
        header.add_widget(title_col)

        end_btn = SmallDangerButton("Encerrar")
        end_btn.bind(on_release=self.disconnect)
        header.add_widget(end_btn)
        self.root_box.add_widget(header)

        self.terminal = ResultBox()
        self.terminal.label.color = SUCCESS
        self.terminal.set_text("")
        self.root_box.add_widget(self.terminal)

        quick_row = BoxLayout(size_hint_y=None, height=dp(38), spacing=dp(6))
        for label, seq in (("Tab", "\t"), ("^C", "\x03"), ("Esc", "\x1b"), ("Up", "\x1b[A"), ("Down", "\x1b[B")):
            # Passa "size" explicito (alem de size_hint) porque
            # SmallIconButton tem um kwargs.setdefault("size", ...) interno
            # que, se "size" nao estiver nos kwargs, e' inserido DEPOIS e
            # acaba sobrescrevendo a altura que a gente quer aqui.
            btn = SmallIconButton(text=label, size_hint=(1, None), size=(dp(50), dp(38)))
            btn.label.font_size = "12sp"
            btn.bind(on_release=lambda *_, s=seq: self._send_raw(s))
            quick_row.add_widget(btn)
        self.root_box.add_widget(quick_row)

        self.raw_input = SSHRawInput(
            on_char=self._send_raw,
            on_backspace=lambda: self._send_raw("\x7f"),
            hint_text="Toque aqui e digite -- funciona como um terminal",
            size_hint_y=None, height=dp(46), multiline=False,
            font_size="15sp", padding_x=dp(16),
            background_normal="", background_active="",
            background_color=SURFACE_2, foreground_color=SUCCESS,
            cursor_color=ACCENT, hint_text_color=TEXT_MUTED,
        )
        self.raw_input.bind(on_text_validate=lambda *_: self._send_raw("\r"))
        self.root_box.add_widget(self.raw_input)
        Clock.schedule_once(lambda dt: setattr(self.raw_input, "focus", True), 0.3)

    def _send_raw(self, text):
        if not self._connected or not self.output_stream:
            return
        try:
            data = bytearray(text.encode("utf-8"))
            self.output_stream.write(data)
            self.output_stream.flush()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Conexao (JSch) -- mesma logica ja validada, so' mudou pra onde ela
    # manda o usuario quando conecta/desconecta.
    # ------------------------------------------------------------------
    def connect(self, host=None, port=None, user=None, password=None, maybe_save=False):
        if host is None:
            host = self.host_input.text.strip()
        else:
            host = host.strip()
        if not host:
            self.status_label.text = "Informe o host."
            return
        raw_port = port if port is not None else self.port_input.text.strip()
        try:
            port_num = int(str(raw_port).strip() or "22")
        except ValueError:
            self.status_label.text = "Porta invalida."
            return
        if user is None:
            user = self.user_input.text.strip()
        if password is None:
            password = self.pass_input.text

        if maybe_save and getattr(self, "save_check", None) is not None and self.save_check.active:
            name = self.name_input.text.strip() or ("%s@%s" % (user or "?", host))
            entry = {"name": name, "host": host, "port": str(port_num), "user": user, "password": password}
            replaced = False
            for i, existing in enumerate(self.saved_hosts):
                if existing.get("host") == host and existing.get("user") == user:
                    self.saved_hosts[i] = entry
                    replaced = True
                    break
            if not replaced:
                self.saved_hosts.append(entry)
            _save_ssh_hosts(self.saved_hosts)

        self._last_host = host
        self._last_user = user
        self.status_label.text = "Conectando..."
        self.connect_btn.set_text("Conectando...")
        self._connect_thread(host, port_num, user, password)

    @run_in_thread
    def _connect_thread(self, host, port, user, password):
        if not IS_ANDROID:
            Clock.schedule_once(
                lambda dt: self._set_status(
                    "SSH so funciona no celular (usa JSch via Android/Java)."
                )
            )
            return
        self._checkpoint("=== nova tentativa de conexao ===")
        try:
            self._checkpoint("1) import jnius.autoclass")
            from jnius import autoclass

            self._checkpoint("2) autoclass com.jcraft.jsch.JSch")
            JSch = autoclass("com.jcraft.jsch.JSch")
            self._checkpoint("3) JSch()")
            jsch = JSch()
            self._checkpoint("4) jsch.getSession(...)")
            session = jsch.getSession(user, host, port)
            self._checkpoint("5) session.setPassword(...)")
            session.setPassword(password)
            self._checkpoint("6) session.setConfig(...)")
            session.setConfig("StrictHostKeyChecking", "no")
            self._checkpoint("7) session.connect(15000)")
            session.connect(15000)
            self._checkpoint("8) session conectada")

            self._checkpoint("9) session.openChannel('shell')")
            channel = session.openChannel("shell")
            self._checkpoint("10) channel.setPtyType")
            channel.setPtyType("xterm")
            self._checkpoint("11) channel.setPty(True)")
            channel.setPty(True)
            self._checkpoint("12) channel.getInputStream()")
            input_stream = channel.getInputStream()
            self._checkpoint("13) channel.getOutputStream()")
            output_stream = channel.getOutputStream()
            self._checkpoint("14) channel.connect(5000)")
            channel.connect(5000)
            self._checkpoint("15) channel conectado -- sucesso")

            self.session = session
            self.channel = channel
            self.input_stream = input_stream
            self.output_stream = output_stream
            self._connected = True
            self._buffer = ""
            Clock.schedule_once(lambda dt: self._on_connected())
            self._read_loop()
        except Exception as e:  # noqa: BLE001
            # Python apaga a variavel "e" assim que o bloco except termina,
            # entao a lambda precisa capturar o texto do erro como valor
            # padrao (err=str(e)) -- senao, quando o Clock realmente chama
            # essa lambda no proximo frame, "e" ja nao existe mais e da
            # NameError (mascarando o erro real de conexao).
            err = str(e)
            self._checkpoint("EXCECAO PYTHON: %s" % err)
            Clock.schedule_once(lambda dt, err=err: self._set_status("Erro ao conectar: %s" % err))

    def _checkpoint(self, text):
        """Show a debug checkpoint directly on screen (status label) and
        also try to log it to a file, in case storage access works after
        all. Sleeps briefly after updating so Kivy actually gets to draw
        the new text before the next (possibly crashing) step runs --
        otherwise a near-instant native crash could kill the process
        before the label's new text is ever rendered to the screen. Only
        touches self.status_label, which only exists while the setup view
        (before a successful connection) is showing -- exactly when this
        runs."""
        _ssh_checkpoint(text)
        Clock.schedule_once(lambda dt: setattr(self.status_label, "text", text))
        time.sleep(0.15)

    def _on_connected(self):
        self._show_terminal()

    def _set_status(self, text):
        if getattr(self, "status_label", None) is not None:
            self.status_label.text = text
        if getattr(self, "connect_btn", None) is not None:
            self.connect_btn.set_text("Conectar")
        self._connected = False

    def _read_loop(self):
        buf = bytearray(4096)
        while self._connected and self.channel:
            try:
                if self.input_stream.available() > 0:
                    n = self.input_stream.read(buf)
                    if n == -1:
                        break
                    if n > 0:
                        chunk = bytes(buf[:n]).decode("utf-8", errors="replace")
                        self._buffer += chunk
                        if len(self._buffer) > 30000:
                            self._buffer = self._buffer[-30000:]
                        snapshot = self._buffer
                        Clock.schedule_once(lambda dt, s=snapshot: self._update_terminal(s))
                if self.channel.isClosed():
                    break
                time.sleep(0.1)
            except Exception:  # noqa: BLE001
                break
        was_connected = self._connected
        self._connected = False
        if was_connected:
            # Desconexao "espontanea" (queda de rede, servidor derrubou a
            # sessao etc) -- volta pra tela de setup sozinha.
            Clock.schedule_once(lambda dt: self._show_setup())

    def _update_terminal(self, text):
        if getattr(self, "terminal", None) is None:
            return
        self.terminal.set_text(text)
        self.terminal.scroll_y = 0

    def disconnect(self, *_):
        self._connected = False
        try:
            if self.channel:
                self.channel.disconnect()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.session:
                self.session.disconnect()
        except Exception:  # noqa: BLE001
            pass
        self.channel = None
        self.session = None
        self._show_setup()


class SettingsScreen(Screen):
    """Minimal settings/about screen, reached from the Home dashboard's
    gear icon -- the app has no configurable options yet, so this just
    shows app/version info."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        root = BoxLayout(orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(16))
        root.add_widget(TopBar("Configuracoes", "Sobre o aplicativo", on_back=_go_home))

        card = Card()
        card.add_widget(SectionLabel(text="APP"))
        for text, size, color, bold in (
            ("MAX Network Toolkit", "16sp", TEXT, True),
            ("Versao 1.0", "13sp", TEXT_SECONDARY, False),
            ("produzido by Marcos Max", "12sp", TEXT_MUTED, False),
        ):
            label = Label(
                text=text, color=color, font_size=size, bold=bold,
                halign="left", valign="middle", size_hint_y=None, height=dp(22),
            )
            label.bind(size=lambda *_, lb=label: setattr(lb, "text_size", lb.size))
            card.add_widget(label)
        root.add_widget(card)
        self.add_widget(root)


class ActivityRow(RoundedBG, BoxLayout):
    """Row used in the Home dashboard's "Atividade recente" feed: a
    status dot + bold title + muted subtitle (which tool ran, and when)."""

    def __init__(self, title, subtitle, color=SUCCESS, **kwargs):
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(54))
        kwargs.setdefault("padding", (dp(14), dp(8)))
        kwargs.setdefault("spacing", dp(12))
        super().__init__(bg_color=SURFACE, radius=dp(14), **kwargs)

        dot = Widget(size_hint=(None, None), size=(dp(8), dp(8)))
        with dot.canvas:
            Color(*color)
            dot_ellipse = Ellipse(pos=dot.pos, size=dot.size)
        dot.bind(pos=lambda w, *_: setattr(dot_ellipse, "pos", w.pos))
        self.add_widget(dot)

        col = BoxLayout(orientation="vertical", spacing=dp(2))
        title_label = Label(
            text=title, color=TEXT, bold=True, font_size="13sp",
            halign="left", valign="middle",
        )
        title_label.bind(size=lambda *_: setattr(title_label, "text_size", title_label.size))
        sub_label = Label(
            text=subtitle, color=TEXT_SECONDARY, font_size="11sp",
            halign="left", valign="middle",
        )
        sub_label.bind(size=lambda *_: setattr(sub_label, "text_size", sub_label.size))
        col.add_widget(title_label)
        col.add_widget(sub_label)
        self.add_widget(col)


class HomeScreen(Screen):
    """Painel inicial (dashboard): status rapido da rede atual + atalhos
    para todas as ferramentas, no estilo do redesign (grade de cards).
    E' a tela raiz -- tem seu proprio cabecalho (MAX / Network Toolkit +
    engrenagem de configuracoes) em vez do antigo logo fixo acima do
    ScreenManager, igual as demais telas."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        scroll = ScrollView()
        root = BoxLayout(
            orientation="vertical", padding=(dp(18), dp(18)), spacing=dp(18),
            size_hint_y=None,
        )
        root.bind(minimum_height=root.setter("height"))

        home_header = BoxLayout(size_hint_y=None, height=dp(54), spacing=dp(10))
        title_col = BoxLayout(orientation="vertical")
        max_lbl = Label(
            text="MAX", font_size="11sp", bold=True, color=TEXT_MUTED,
            halign="left", valign="bottom", size_hint_y=None, height=dp(16),
        )
        max_lbl.bind(size=lambda *_: setattr(max_lbl, "text_size", max_lbl.size))
        title_col.add_widget(max_lbl)
        title_lbl = Label(
            text="Network Toolkit", font_size="20sp", bold=True, color=TEXT,
            halign="left", valign="top", size_hint_y=None, height=dp(30),
        )
        title_lbl.bind(size=lambda *_: setattr(title_lbl, "text_size", title_lbl.size))
        title_col.add_widget(title_lbl)
        home_header.add_widget(title_col)

        gear_btn = SmallIconButton(icon_widget=ToolIcon(
            kind="gear", color=ACCENT, size_hint=(0.55, 0.55),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
        ))
        gear_btn.bind(on_release=self._open_settings)
        home_header.add_widget(gear_btn)
        root.add_widget(home_header)

        self.status_card = Card()

        top_row = BoxLayout(size_hint_y=None, height=dp(26), spacing=dp(10))
        self.ssid_label = Label(
            text="Lendo rede...", color=TEXT, font_size="16sp", bold=True,
            halign="left", valign="middle",
        )
        self.ssid_label.bind(size=lambda *_: setattr(self.ssid_label, "text_size", self.ssid_label.size))
        top_row.add_widget(self.ssid_label)
        self.signal_bars = SignalBarsIcon()
        top_row.add_widget(self.signal_bars)
        self.status_card.add_widget(top_row)

        info_row = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        self.ip_value = self._make_stat_column(info_row, "IP LOCAL")
        self.gateway_value = self._make_stat_column(info_row, "GATEWAY")
        self.signal_value = self._make_stat_column(info_row, "SINAL")
        self.status_card.add_widget(info_row)

        refresh_btn = PrimaryButton("Atualizar status da rede")
        refresh_btn.bind(on_release=self.refresh_status)
        self.status_card.add_widget(refresh_btn)
        root.add_widget(self.status_card)

        root.add_widget(SectionLabel(text="FERRAMENTAS"))
        grid = GridLayout(cols=4, spacing=dp(10), size_hint_y=None)
        grid.bind(minimum_height=grid.setter("height"))
        for label, screen_name, icon, _sub in TOOL_CATALOG:
            grid.add_widget(ToolTile(label, icon, on_press_cb=lambda n=screen_name: self._goto(n)))
        grid.add_widget(ToolTile("Todas", "more", on_press_cb=self._open_all_tools))
        root.add_widget(grid)

        root.add_widget(SectionLabel(text="ATIVIDADE RECENTE"))
        self.activity_box = BoxLayout(orientation="vertical", spacing=dp(10), size_hint_y=None)
        self.activity_box.bind(minimum_height=self.activity_box.setter("height"))
        root.add_widget(self.activity_box)

        scroll.add_widget(root)
        self.add_widget(scroll)
        self._checked_once = False

    @staticmethod
    def _make_stat_column(parent, caption):
        """Builds one "IP LOCAL / 192.168.0.34"-style column (small muted
        caption above a bold value), adds it to `parent`, and returns the
        value Label so callers can update it later."""
        col = BoxLayout(orientation="vertical", spacing=dp(2))
        cap = Label(
            text=caption, font_size="10sp", color=TEXT_MUTED,
            halign="left", valign="middle", size_hint_y=None, height=dp(14),
        )
        cap.bind(size=lambda *_: setattr(cap, "text_size", cap.size))
        value = Label(
            text="--", font_size="14sp", bold=True, color=TEXT,
            halign="left", valign="middle", size_hint_y=None, height=dp(22),
            shorten=True,
        )
        value.bind(size=lambda *_: setattr(value, "text_size", value.size))
        col.add_widget(cap)
        col.add_widget(value)
        parent.add_widget(col)
        return value

    def _goto(self, name):
        app = App.get_running_app()
        if app:
            app.switch_screen(name)

    def _open_settings(self, *_):
        app = App.get_running_app()
        if app:
            app.switch_screen("settings")

    def _open_all_tools(self):
        app = App.get_running_app()
        if app:
            app.toggle_more_sheet()

    def on_pre_enter(self, *_):
        if not self._checked_once:
            self._checked_once = True
            self.refresh_status()
        self._refresh_activity()

    def _refresh_activity(self):
        app = App.get_running_app()
        log = getattr(app, "activity_log", None) or []
        self.activity_box.clear_widgets()
        if not log:
            placeholder = Label(
                text="Nenhuma atividade recente ainda.", color=TEXT_MUTED, font_size="12sp",
                size_hint_y=None, height=dp(30), halign="left", valign="middle",
            )
            placeholder.bind(size=lambda *_: setattr(placeholder, "text_size", placeholder.size))
            self.activity_box.add_widget(placeholder)
            return
        for entry in log[:5]:
            subtitle = "%s · %s" % (entry["subtitle"], _time_ago(entry["ts"]))
            self.activity_box.add_widget(
                ActivityRow(entry["title"], subtitle, color=entry["color"])
            )

    def refresh_status(self, *_):
        self.ssid_label.text = "Lendo rede..."
        self._fetch_status()

    def _apply_status(self, ssid, ip_addr, gateway, quality_text, level, color):
        self.ssid_label.text = ssid
        self.ip_value.text = ip_addr
        self.gateway_value.text = gateway
        self.signal_value.text = quality_text
        self.signal_value.color = color
        self.signal_bars.set_level(level, active_color=color)

    @run_in_thread
    def _fetch_status(self):
        if not IS_ANDROID:
            Clock.schedule_once(
                lambda dt: self._apply_status("So' funciona no celular", "--", "--", "--", 0, TEXT_MUTED)
            )
            return
        try:
            from jnius import autoclass, cast

            PythonActivity = autoclass("org.kivy.android.PythonActivity")
            Context = autoclass("android.content.Context")
            activity = PythonActivity.mActivity
            wifi_manager = cast(
                "android.net.wifi.WifiManager",
                activity.getSystemService(Context.WIFI_SERVICE),
            )
            info = wifi_manager.getConnectionInfo()
            dhcp = None
            try:
                dhcp = wifi_manager.getDhcpInfo()
            except Exception:  # noqa: BLE001
                dhcp = None
            ssid = info.getSSID() or "?"
            # A API do Android costuma devolver o SSID entre aspas literais
            # (ex: "\"MinhaRede\""); o mockup mostra sem aspas, entao tiramos.
            if len(ssid) >= 2 and ssid.startswith('"') and ssid.endswith('"'):
                ssid = ssid[1:-1]
            rssi = info.getRssi()
            ip_addr = _int_to_ip(info.getIpAddress())
            gateway = _int_to_ip(dhcp.gateway) if dhcp else "?"
            level, color, quality_text = _signal_level_info(rssi)
        except Exception as e:  # noqa: BLE001
            err = str(e)
            Clock.schedule_once(
                lambda dt: self._apply_status("Erro ao ler a rede", "--", "--", "--", 0, TEXT_MUTED)
            )
            return

        Clock.schedule_once(
            lambda dt: self._apply_status(ssid, ip_addr, gateway, quality_text, level, color)
        )


class LoadingOverlay(BoxLayout):
    """Full-screen loading indicator with a real animated bar, shown
    briefly while the app boots (replaces the old static splash image)."""

    def __init__(self, **kwargs):
        kwargs.setdefault("orientation", "vertical")
        kwargs.setdefault("spacing", dp(18))
        super().__init__(**kwargs)

        with self.canvas.before:
            Color(*BG)
            self._bg_rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._sync_bg, size=self._sync_bg)

        self.add_widget(Widget())

        title_h = dp(56)
        title = KivyImage(
            source=LOGO_PATH,
            size_hint=(None, None),
            size=(title_h * LOGO_RATIO, title_h),
            pos_hint={"center_x": 0.5},
            allow_stretch=True,
            keep_ratio=True,
        )
        self.add_widget(title)

        bar_wrap = BoxLayout(
            size_hint=(None, None), size=(dp(240), dp(8)),
            pos_hint={"center_x": 0.5},
        )
        with bar_wrap.canvas.before:
            Color(*SURFACE_2)
            self._track_rect = RoundedRectangle(pos=bar_wrap.pos, size=bar_wrap.size, radius=[dp(4)])
        bar_wrap.bind(pos=self._sync_track, size=self._sync_track)

        self._fill_width = dp(80)
        with bar_wrap.canvas:
            Color(*ACCENT)
            self._fill_rect = RoundedRectangle(pos=bar_wrap.pos, size=(self._fill_width, dp(8)), radius=[dp(4)])

        self.add_widget(bar_wrap)

        subtitle = Label(
            text="carregando...", font_size="12sp", color=TEXT_MUTED,
            size_hint_y=None, height=dp(20),
        )
        self.add_widget(subtitle)
        self.add_widget(Widget())

        self._bar_wrap = bar_wrap
        self._anim_x = 0
        self._anim_event = Clock.schedule_interval(self._animate_bar, 1 / 30.0)

    def stop(self):
        if self._anim_event:
            self._anim_event.cancel()
            self._anim_event = None

    def _sync_bg(self, widget, *_):
        self._bg_rect.pos = widget.pos
        self._bg_rect.size = widget.size

    def _sync_track(self, widget, *_):
        self._track_rect.pos = widget.pos
        self._track_rect.size = widget.size

    def _animate_bar(self, dt):
        track_width = self._bar_wrap.width
        self._anim_x = (self._anim_x + dt * 260) % (track_width + self._fill_width)
        x = self._bar_wrap.x - self._fill_width + self._anim_x
        self._fill_rect.pos = (x, self._bar_wrap.y)
        self._fill_rect.size = (self._fill_width, dp(8))


# ---------------------------------------------------------------------------
# App shell
# ---------------------------------------------------------------------------
class MaxApp(App):
    def build(self):
        self.title = "MAX"
        if IS_ANDROID:
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([
                    Permission.ACCESS_FINE_LOCATION,
                    Permission.ACCESS_COARSE_LOCATION,
                ])
            except Exception:  # noqa: BLE001
                pass
            try:
                # Pre-carrega a classe JSch (biblioteca Java de terceiros,
                # empacotada via Gradle) na thread principal. pyjnius so
                # consegue localizar classes que nao sao do proprio Android
                # (via FindClass) a partir da thread que tem acesso ao
                # classloader do app -- normalmente so a thread principal no
                # startup. Se a primeira vez que "JSch" e' referenciada for
                # dentro da thread em segundo plano usada pela aba SSH, o
                # aplicativo pode fechar sem gerar excecao Python nenhuma
                # (falha nativa, nao capturavel por try/except). Fazendo
                # essa chamada aqui, a classe fica em cache e funciona
                # normalmente depois, mesmo de outras threads.
                from jnius import autoclass
                autoclass("com.jcraft.jsch.JSch")
            except Exception:  # noqa: BLE001
                pass
        try:
            return self._build_ui()
        except Exception:  # noqa: BLE001
            import traceback

            error_text = traceback.format_exc()
            saved_path = _write_crash_log(error_text)
            if saved_path:
                error_text = ("(salvo tambem em: %s)\n\n" % saved_path) + error_text
            container = ScrollView()
            label = Label(
                text="Erro ao iniciar o app:\n\n" + error_text,
                size_hint_y=None,
                color=(1, 1, 1, 1),
                font_size="12sp",
                halign="left",
                valign="top",
                padding=(dp(16), dp(16)),
            )
            label.bind(
                width=lambda *_: setattr(label, "text_size", (label.width, None)),
                texture_size=lambda *_: setattr(label, "height", label.texture_size[1]),
            )
            container.add_widget(label)
            return container

    def _build_ui(self):
        self.activity_log = []

        outer = FloatLayout()
        root = BoxLayout(orientation="vertical")

        with root.canvas.before:
            Color(*BG)
            self._bg_rect = Rectangle(pos=root.pos, size=root.size)
        root.bind(pos=self._sync_bg, size=self._sync_bg)

        all_screens = [
            HomeScreen(name="home"),
            PingScreen(name="ping"),
            WifiScreen(name="wifi"),
            SpeedtestScreen(name="speed"),
            PortScanScreen(name="ports"),
            NetworkScanScreen(name="scan"),
            TerminalScreen(name="terminal"),
            SSHScreen(name="ssh"),
            SettingsScreen(name="settings"),
        ]

        self.sm = ScreenManager(transition=NoTransition())
        for screen in all_screens:
            self.sm.add_widget(screen)

        # Navegacao inferior com 5 itens (Home, Ping, Wi-Fi, Speed, Mais),
        # igual ao redesign -- as demais ferramentas (Portas, Varredura,
        # Terminal, SSH) ficam na folha "Mais".
        nav_bar = BoxLayout(size_hint_y=None, height=dp(56))
        with nav_bar.canvas.before:
            Color(*SURFACE)
            self._nav_rect = RoundedRectangle(pos=nav_bar.pos, size=nav_bar.size, radius=[0])
        nav_bar.bind(pos=self._sync_nav_bg, size=self._sync_nav_bg)

        # Grupos de telas que cada botao da barra inferior deve destacar.
        self._nav_groups = [
            ("home", ["home"]),
            ("ping", ["ping"]),
            ("wifi", ["wifi"]),
            ("speed", ["speed"]),
            ("more", ["ports", "scan", "terminal", "ssh"]),
        ]

        self.nav_buttons = []
        nav_bar.add_widget(self._make_nav_button("Home", "home", lambda: self.switch_screen("home")))
        nav_bar.add_widget(self._make_nav_button("Ping", "ping", lambda: self.switch_screen("ping")))
        nav_bar.add_widget(self._make_nav_button("Wi-Fi", "wifi", lambda: self.switch_screen("wifi")))
        nav_bar.add_widget(self._make_nav_button("Speed", "speed", lambda: self.switch_screen("speed")))
        nav_bar.add_widget(self._make_nav_button("Mais", "more", self.toggle_more_sheet))

        self.more_sheet = MoreSheet(
            items=[
                (label, sub, icon, self._make_switch_cb(screen_name))
                for label, screen_name, icon, sub in TOOL_CATALOG
            ],
            on_close=self.hide_more_sheet,
            size_hint=(1, 1),
        )

        footer = Label(
            text="produzido by Marcos Max",
            size_hint_y=None,
            height=dp(26),
            font_size="11sp",
            color=TEXT_MUTED,
        )

        root.add_widget(self.sm)
        root.add_widget(nav_bar)
        root.add_widget(footer)

        self.switch_screen("home")

        outer.add_widget(root)
        outer.add_widget(self.more_sheet)
        self._loading_overlay = LoadingOverlay(size_hint=(1, 1))
        outer.add_widget(self._loading_overlay)
        Clock.schedule_once(self._hide_loading, 2.5)

        return outer

    def _make_nav_button(self, label_text, key, on_press_cb):
        btn = NavButton(label_text, on_press_cb=on_press_cb)
        self.nav_buttons.append((key, btn))
        return btn

    def _make_switch_cb(self, screen_name):
        return lambda: self.switch_screen(screen_name)

    def log_activity(self, title, subtitle, color=SUCCESS):
        """Records one entry for the Home dashboard's "Atividade recente"
        feed. Kept in memory only (cleared on app restart) -- this is a
        lightweight activity log, not a persisted history."""
        self.activity_log.insert(0, {
            "title": title, "subtitle": subtitle, "color": color, "ts": time.time(),
        })
        del self.activity_log[8:]

    def toggle_more_sheet(self):
        if self.more_sheet.disabled:
            self.more_sheet.show()
        else:
            self.more_sheet.hide()

    def hide_more_sheet(self):
        self.more_sheet.hide()

    def _hide_loading(self, *_):
        overlay = getattr(self, "_loading_overlay", None)
        if overlay is None:
            return
        overlay.stop()
        if overlay.parent:
            overlay.parent.remove_widget(overlay)
        self._loading_overlay = None

    def _sync_bg(self, widget, *_):
        self._bg_rect.pos = widget.pos
        self._bg_rect.size = widget.size

    def _sync_nav_bg(self, widget, *_):
        self._nav_rect.pos = widget.pos
        self._nav_rect.size = widget.size

    def switch_screen(self, name):
        self.sm.current = name
        self.hide_more_sheet()
        for key, members in self._nav_groups:
            for btn_key, btn in self.nav_buttons:
                if btn_key == key:
                    btn.set_active(name in members)


if __name__ == "__main__":
    try:
        MaxApp().run()
    except Exception:  # noqa: BLE001
        import traceback
        _write_crash_log(traceback.format_exc())
        raise
