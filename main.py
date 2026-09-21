import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
import hashlib
import random
import operator

from crypto.encryption import (
    encrypt_data,
    decrypt_data,
    PBKDF2_ITERATIONS
)

from crypto.hashing import sha256_file

from security.passwords import (
    generate_password,
    analyze_password
)

from security.threat_detection import (
    analyze_message,
    analyze_url
)

from database.database import (
    connect,
    add_log,
    get_logs,
    clear_logs,
    get_counts
)

from vault.secure_vault import (
    save_secret,
    get_secrets,
    get_secret,
    delete_secret
)

from sharing.file_server import ShareManager


class SecureVault(tk.Tk):

    BG = "#07111F"
    SIDEBAR = "#09182B"
    CARD = "#0E1B2D"
    CARD2 = "#1B3552"
    INPUT = "#081321"
    BORDER = "#1D4261"

    TEXT = "#F3F7FF"
    MUTED = "#A9BED4"

    BLUE = "#3AA8FF"
    CYAN = "#29DFFF"
    GREEN = "#35D39A"
    PURPLE = "#9C86FF"
    ORANGE = "#FFB454"
    RED = "#FF5C75"

    def __init__(self):

        super().__init__()

        self.title("SecureVault | Cybersecurity Platform")
        self.geometry("1400x900")
        self.minsize(1050, 680)

        self.configure(bg=self.BG)

        self.share_manager = ShareManager()

        self.current_page = None
        self.nav_buttons = {}

        self.particle_data = []
        self.animation_running = True
        self.animation_scanlines = []
        self.background_resize_job = None

        self.dashboard_values = {}

        self.setup_style()
        self.create_variables()
        self.create_interface()

        self.refresh_dashboard()
        self.refresh_vault()
        self.refresh_logs()

        self.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

        self.after(
            100,
            self.animate_background
        )

    # =========================================================
    # STYLE
    # =========================================================

    def setup_style(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Modern.Treeview",
            background=self.CARD,
            foreground=self.TEXT,
            fieldbackground=self.CARD,
            borderwidth=0,
            rowheight=42,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Modern.Treeview.Heading",
            background=self.CARD2,
            foreground=self.MUTED,
            borderwidth=0,
            font=("Segoe UI", 9, "bold"),
            padding=10
        )

        style.map(
            "Modern.Treeview",
            background=[
                ("selected", "#173B63")
            ],
            foreground=[
                ("selected", self.CYAN)
            ]
        )

        style.configure(
            "Modern.TCombobox",
            fieldbackground=self.INPUT,
            background=self.INPUT,
            foreground=self.TEXT,
            borderwidth=0,
            arrowsize=15
        )

        style.map(
            "Modern.TCombobox",
            fieldbackground=[
                ("readonly", self.INPUT)
            ],
            foreground=[
                ("readonly", self.TEXT)
            ]
        )

        style.configure(
            "Modern.TNotebook",
            background=self.BG,
            borderwidth=0
        )

        style.configure(
            "Vertical.TScrollbar",
            background=self.CARD2,
            troughcolor=self.BG,
            bordercolor=self.BG,
            arrowcolor=self.MUTED
        )

        style.map(
            "Vertical.TScrollbar",
            background=[
                ("active", self.CYAN),
                ("pressed", self.BLUE)
            ]
        )

    # =========================================================
    # VARIABLES
    # =========================================================

    def create_variables(self):

        self.file_password = tk.StringVar()

        self.vault_master = tk.StringVar()
        self.vault_title = tk.StringVar()

        self.vault_category = tk.StringVar(
            value="Private Note"
        )

        self.integrity_file = tk.StringVar()

        self.generated_password = tk.StringVar()

        self.spam_sender = tk.StringVar()
        self.spam_subject = tk.StringVar()

        self.url_value = tk.StringVar()

        self.share_duration = tk.StringVar(
            value="30 minutes"
        )

        self.share_status = tk.StringVar(
            value="No active share"
        )

        self.status_text = tk.StringVar(
            value="System ready"
        )

        self.dashboard_values = {}

    # =========================================================
    # MAIN INTERFACE
    # =========================================================

    def create_interface(self):

        self.main_container = tk.Frame(
            self,
            bg=self.BG
        )

        self.main_container.pack(
            fill="both",
            expand=True
        )

        self.create_sidebar()

        self.content_area = tk.Frame(
            self.main_container,
            bg=self.BG
        )

        self.content_area.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.create_topbar()

        self.page_container = tk.Frame(
            self.content_area,
            bg=self.BG
        )

        self.page_container.pack(
            fill="both",
            expand=True
        )

        self.create_statusbar()

        self.show_page("Dashboard")

    # =========================================================
    # SIDEBAR
    # =========================================================

    def create_sidebar(self):

        self.sidebar = tk.Frame(
            self.main_container,
            bg=self.SIDEBAR,
            width=250
        )

        self.sidebar.pack(
            side="left",
            fill="y"
        )

        self.sidebar.pack_propagate(False)

        brand = tk.Frame(
            self.sidebar,
            bg=self.SIDEBAR
        )

        brand.pack(
            fill="x",
            padx=22,
            pady=(25, 30)
        )

        logo = tk.Canvas(
            brand,
            width=45,
            height=45,
            bg=self.SIDEBAR,
            highlightthickness=0
        )

        logo.pack(
            side="left"
        )

        logo.create_oval(
            5,
            5,
            40,
            40,
            outline=self.CYAN,
            width=2
        )

        logo.create_oval(
            10,
            10,
            35,
            35,
            outline="#155B78",
            width=1
        )

        logo.create_text(
            22,
            22,
            text="S",
            fill=self.CYAN,
            font=("Segoe UI", 18, "bold")
        )

        brand_text = tk.Frame(
            brand,
            bg=self.SIDEBAR
        )

        brand_text.pack(
            side="left",
            padx=10
        )

        tk.Label(
            brand_text,
            text="SECUREVAULT",
            bg=self.SIDEBAR,
            fg=self.TEXT,
            font=("Segoe UI", 13, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            brand_text,
            text="SECURITY PLATFORM",
            bg=self.SIDEBAR,
            fg=self.CYAN,
            font=("Segoe UI", 7, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            self.sidebar,
            text="WORKSPACE",
            bg=self.SIDEBAR,
            fg="#50627A",
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=25,
            pady=(0, 10)
        )

        navigation = [
            ("Dashboard", "⌂"),
            ("File Security", "▣"),
            ("Integrity", "◈"),
            ("Password Tools", "◆"),
            ("Secure Vault", "▤"),
            ("Secure Sharing", "⇄"),
            ("Spam & Phishing", "⚠"),
            ("Activity Logs", "≡"),
            ("Settings", "⚙")
        ]

        for name, icon in navigation:
            self.create_nav_button(
                name,
                icon
            )

        spacer = tk.Frame(
            self.sidebar,
            bg=self.SIDEBAR
        )

        spacer.pack(
            fill="both",
            expand=True
        )

        security_box = tk.Frame(
            self.sidebar,
            bg="#0E192A",
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        security_box.pack(
            fill="x",
            padx=15,
            pady=18
        )

        tk.Label(
            security_box,
            text="●  SYSTEM SECURE",
            bg="#0E192A",
            fg=self.GREEN,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            padx=14,
            pady=(13, 4)
        )

        tk.Label(
            security_box,
            text="Local protection active",
            bg="#0E192A",
            fg=self.MUTED,
            font=("Segoe UI", 8)
        ).pack(
            anchor="w",
            padx=14,
            pady=(0, 13)
        )

    def create_nav_button(
        self,
        name,
        icon
    ):

        button = tk.Frame(
            self.sidebar,
            bg=self.SIDEBAR,
            height=45,
            cursor="hand2"
        )

        button.pack(
            fill="x",
            padx=12,
            pady=2
        )

        button.pack_propagate(False)

        indicator = tk.Frame(
            button,
            bg=self.SIDEBAR,
            width=3
        )

        indicator.pack(
            side="left",
            fill="y"
        )

        label = tk.Label(
            button,
            text=f"{icon}   {name}",
            bg=self.SIDEBAR,
            fg=self.MUTED,
            anchor="w",
            font=("Segoe UI", 10)
        )

        label.pack(
            fill="both",
            expand=True,
            padx=14
        )

        self.nav_buttons[name] = (
            button,
            indicator,
            label
        )

        for widget in (
            button,
            indicator,
            label
        ):

            widget.bind(
                "<Button-1>",
                lambda event, n=name:
                self.show_page(n)
            )

            widget.bind(
                "<Enter>",
                lambda event, n=name:
                self.nav_hover(n, True)
            )

            widget.bind(
                "<Leave>",
                lambda event, n=name:
                self.nav_hover(n, False)
            )

    def nav_hover(
        self,
        name,
        entering
    ):

        if name == self.current_page:
            return

        button, indicator, label = (
            self.nav_buttons[name]
        )

        if entering:

            button.configure(
                bg="#101C2E"
            )

            label.configure(
                bg="#101C2E",
                fg=self.TEXT
            )

        else:

            button.configure(
                bg=self.SIDEBAR
            )

            label.configure(
                bg=self.SIDEBAR,
                fg=self.MUTED
            )

    # =========================================================
    # TOP BAR
    # =========================================================

    def create_topbar(self):

        topbar = tk.Frame(
            self.content_area,
            bg=self.BG,
            height=75
        )

        topbar.pack(
            fill="x"
        )

        topbar.pack_propagate(False)

        left = tk.Frame(
            topbar,
            bg=self.BG
        )

        left.pack(
            side="left",
            padx=28,
            fill="y"
        )

        self.page_title = tk.Label(
            left,
            text="Dashboard",
            bg=self.BG,
            fg=self.TEXT,
            font=("Segoe UI", 20, "bold")
        )

        self.page_title.pack(
            anchor="w",
            pady=(15, 0)
        )

        self.page_subtitle = tk.Label(
            left,
            text="Security overview and system monitoring",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 9)
        )

        self.page_subtitle.pack(
            anchor="w"
        )

        right = tk.Frame(
            topbar,
            bg=self.BG
        )

        right.pack(
            side="right",
            padx=25
        )

        self.clock_label = tk.Label(
            right,
            text="",
            bg=self.BG,
            fg=self.CYAN,
            font=("Consolas", 10, "bold")
        )

        self.clock_label.pack(
            side="left",
            padx=15
        )

        status = tk.Frame(
            right,
            bg="#0E192A",
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        status.pack(
            side="left"
        )

        tk.Label(
            status,
            text="●",
            bg="#0E192A",
            fg=self.GREEN,
            font=("Segoe UI", 12)
        ).pack(
            side="left",
            padx=(10, 4),
            pady=7
        )

        tk.Label(
            status,
            text="Protected",
            bg="#0E192A",
            fg=self.TEXT,
            font=("Segoe UI", 9, "bold")
        ).pack(
            side="left",
            padx=(0, 10)
        )

        self.update_clock()

    def update_clock(self):

        try:

            if not self.winfo_exists():
                return

            now = datetime.now().strftime(
                "%H:%M:%S"
            )

            self.clock_label.configure(
                text=now
            )

            self.after(
                1000,
                self.update_clock
            )

        except Exception:
            pass

    # =========================================================
    # STATUS BAR
    # =========================================================

    def create_statusbar(self):

        bar = tk.Frame(
            self.content_area,
            bg="#0A101C",
            height=30
        )

        bar.pack(
            fill="x",
            side="bottom"
        )

        bar.pack_propagate(False)

        tk.Label(
            bar,
            textvariable=self.status_text,
            bg="#0A101C",
            fg=self.MUTED,
            font=("Segoe UI", 8)
        ).pack(
            side="left",
            padx=15
        )

        tk.Label(
            bar,
            text=f"AES GCM  |  SHA 256  |  PBKDF2 {PBKDF2_ITERATIONS:,}",
            bg="#0A101C",
            fg="#50627A",
            font=("Segoe UI", 8)
        ).pack(
            side="right",
            padx=15
        )

    def set_status(self, text):

        self.status_text.set(text)

    # =========================================================
    # PAGE MANAGEMENT
    # =========================================================

    def clear_page(self):

        self.dashboard_values = {}
        self.particle_data = []
        self.animation_scanlines = []

        for widget in self.page_container.winfo_children():
            widget.destroy()

    def show_page(self, page):

        self.current_page = page
        self.clear_page()

        for name, values in self.nav_buttons.items():

            button, indicator, label = values

            if name == page:

                button.configure(
                    bg="#11233A"
                )

                indicator.configure(
                    bg=self.CYAN
                )

                label.configure(
                    bg="#11233A",
                    fg=self.TEXT,
                    font=("Segoe UI", 10, "bold")
                )

            else:

                button.configure(
                    bg=self.SIDEBAR
                )

                indicator.configure(
                    bg=self.SIDEBAR
                )

                label.configure(
                    bg=self.SIDEBAR,
                    fg=self.MUTED,
                    font=("Segoe UI", 10)
                )

        subtitles = {

            "Dashboard":
                "Security overview and system monitoring",

            "File Security":
                "AES GCM file encryption and decryption",

            "Integrity":
                "SHA 256 file integrity verification",

            "Password Tools":
                "Generate and evaluate secure passwords",

            "Secure Vault":
                "Encrypted storage for sensitive information",

            "Secure Sharing":
                "Temporary protected local file sharing",

            "Spam & Phishing":
                "Local threat and suspicious URL analysis",

            "Activity Logs":
                "Security operations and audit history",

            "Settings":
                "Security architecture and configuration"
        }

        self.page_title.configure(
            text=page
        )

        self.page_subtitle.configure(
            text=subtitles.get(page, "")
        )

        builders = {

            "Dashboard":
                self.build_dashboard,

            "File Security":
                self.build_file_security,

            "Integrity":
                self.build_integrity,

            "Password Tools":
                self.build_password_tools,

            "Secure Vault":
                self.build_vault,

            "Secure Sharing":
                self.build_sharing,

            "Spam & Phishing":
                self.build_threat_detection,

            "Activity Logs":
                self.build_logs,

            "Settings":
                self.build_settings
        }

        builder = builders.get(page)

        if builder:
            builder()

        self.after(
            100,
            self.refresh_dashboard
        )

    # =========================================================
    # BACKGROUND
    # =========================================================

    def create_background_canvas(self, parent):

        canvas = tk.Canvas(
            parent,
            bg=self.BG,
            highlightthickness=0
        )

        canvas.place(
            relx=0,
            rely=0,
            relwidth=1,
            relheight=1
        )

        for widget in parent.winfo_children():
            if widget is not canvas:
                widget.lift()

        self.animation_canvas = canvas

        canvas.bind(
            "<Configure>",
            lambda event: self.schedule_background_redraw(canvas)
        )

        self.redraw_background(canvas)

        scanline = canvas.create_line(
            0,
            0,
            max(canvas.winfo_width(), 1),
            0,
            fill="#1C6682",
            width=2,
            tags="animation"
        )

        self.animation_scanlines.append(
            [canvas, scanline, 0]
        )

        width = max(
            canvas.winfo_width(),
            1100
        )

        height = max(
            canvas.winfo_height(),
            650
        )

        for count in range(42):

            x = random.randint(0, width)
            y = random.randint(0, height)

            size = random.choice(
                [1, 1, 1, 2]
            )

            speed = random.uniform(
                0.15,
                0.45
            )

            particle = canvas.create_oval(
                x,
                y,
                x + size,
                y + size,
                fill=random.choice(
                    [
                        "#173450",
                        "#16405C",
                        "#1A2941",
                        "#15324A"
                    ]
                ),
                outline="",
                tags="particles"
            )

            self.particle_data.append(
                [
                    canvas,
                    particle,
                    x,
                    y,
                    speed
                ]
            )

        return canvas

    def schedule_background_redraw(self, canvas):

        if self.background_resize_job:
            self.after_cancel(self.background_resize_job)

        self.background_resize_job = self.after_idle(
            lambda: self.redraw_background(canvas)
        )

    def redraw_background(self, canvas):

        if not canvas.winfo_exists():
            return

        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)

        canvas.delete("background")

        # Deep navy base with a blue to violet atmospheric gradient
        top_color = (4, 10, 22)
        bottom_color = (12, 27, 50)
        gradient_steps = max(height // 5, 140)

        for index in range(gradient_steps):
            progress = index / max(gradient_steps - 1, 1)
            color = "#{:02X}{:02X}{:02X}".format(
                int(top_color[0] + (bottom_color[0] - top_color[0]) * progress),
                int(top_color[1] + (bottom_color[1] - top_color[1]) * progress),
                int(top_color[2] + (bottom_color[2] - top_color[2]) * progress)
            )
            top = int(index * height / gradient_steps)
            bottom = int((index + 1) * height / gradient_steps) + 1
            canvas.create_rectangle(
                0,
                top,
                width,
                bottom,
                fill=color,
                outline="",
                tags="background"
            )

        # Soft color zones give the background more depth without affecting controls
        glow_specs = [
            (int(width * 0.10), int(height * 0.12), 360, "#0A3150"),
            (int(width * 0.82), int(height * 0.18), 430, "#17265B"),
            (int(width * 0.56), int(height * 0.82), 500, "#102B4A"),
            (int(width * 0.92), int(height * 0.78), 300, "#16224A")
        ]

        for gx, gy, radius, glow_color in glow_specs:
            layers = 14
            for layer in range(layers, 0, -1):
                scale = layer / layers
                r = int(radius * scale)
                canvas.create_oval(
                    gx - r,
                    gy - r,
                    gx + r,
                    gy + r,
                    fill=glow_color,
                    outline="",
                    tags="background"
                )

        # Fine cyber grid
        for y in range(32, height, 32):
            canvas.create_line(
                0,
                y,
                width,
                y,
                fill="#10243A",
                width=1,
                tags="background"
            )

        for x in range(32, width, 64):
            canvas.create_line(
                x,
                0,
                x,
                height,
                fill="#0C2035",
                width=1,
                tags="background"
            )

        # Subtle diagonal technical lines
        for offset in range(-height, width, 180):
            canvas.create_line(
                offset,
                0,
                offset + height,
                height,
                fill="#0B1D31",
                width=1,
                tags="background"
            )

        canvas.tag_lower("background")

    def animate_background(self):

        if not self.animation_running:
            return

        try:

            valid_particles = []

            for item in self.particle_data:

                canvas, particle, x, y, speed = item

                try:

                    canvas.move(
                        particle,
                        0,
                        speed
                    )

                    item[3] += speed

                    height = max(
                        canvas.winfo_height(),
                        650
                    )

                    if item[3] > height:

                        item[3] = 0

                        canvas.coords(
                            particle,
                            item[2],
                            0,
                            item[2] + 2,
                            2
                        )

                    valid_particles.append(item)

                except Exception:
                    continue

            self.particle_data = valid_particles

            for item in self.animation_scanlines:
                canvas, scanline, y = item

                try:
                    height = max(canvas.winfo_height(), 650)
                    y = (y + 1.8) % height
                    canvas.coords(scanline, 0, y, canvas.winfo_width(), y)
                    item[2] = y
                except Exception:
                    continue

        except Exception:
            pass

        try:

            self.after(
                45,
                self.animate_background
            )

        except Exception:
            pass

    # =========================================================
    # COMMON COMPONENTS
    # =========================================================

    def card(
        self,
        parent,
        padx=20,
        pady=20
    ):

        frame = tk.Frame(
            parent,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=padx,
            pady=pady
        )

        return frame

    def title_text(
        self,
        parent,
        title,
        description=""
    ):

        tk.Label(
            parent,
            text=title,
            bg=self.CARD,
            fg=self.TEXT,
            font=("Segoe UI", 14, "bold")
        ).pack(
            anchor="w"
        )

        if description:

            tk.Label(
                parent,
                text=description,
                bg=self.CARD,
                fg=self.MUTED,
                font=("Segoe UI", 9),
                wraplength=900,
                justify="left"
            ).pack(
                anchor="w",
                pady=(3, 15)
            )

    def input_box(
        self,
        parent,
        variable=None,
        width=40,
        show=None
    ):

        entry = tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            bg=self.INPUT,
            fg=self.TEXT,
            insertbackground=self.CYAN,
            selectbackground="#21486D",
            selectforeground=self.TEXT,
            relief="flat",
            highlightbackground=self.BORDER,
            highlightcolor=self.CYAN,
            highlightthickness=1,
            font=("Segoe UI", 10)
        )

        entry.configure(
            width=width
        )

        return entry

    def button(
        self,
        parent,
        text,
        command,
        primary=True,
        width=None
    ):

        bg = self.BLUE if primary else self.CARD2

        hover = (
            "#55B8FF"
            if primary
            else "#1C2B42"
        )

        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg="#FFFFFF",
            activebackground=hover,
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 9, "bold"),
            padx=16,
            pady=9
        )

        if width:
            btn.configure(width=width)

        btn.bind(
            "<Enter>",
            lambda event:
            btn.configure(bg=hover)
        )

        btn.bind(
            "<Leave>",
            lambda event:
            btn.configure(bg=bg)
        )

        return btn

    def gradient_bar(self, parent, height=4):

        canvas = tk.Canvas(
            parent,
            height=height,
            bg=self.CARD,
            highlightthickness=0,
            bd=0
        )

        def redraw(event=None):
            width = max(canvas.winfo_width(), 1)
            canvas.delete("gradient")

            colors = [
                (53, 167, 255),
                (36, 225, 255),
                (155, 123, 255),
                (53, 211, 154)
            ]

            steps = max(width, 80)

            for x in range(steps):
                progress = x / max(steps - 1, 1)
                position = progress * (len(colors) - 1)
                left = int(position)
                right = min(left + 1, len(colors) - 1)
                fraction = position - left

                r = int(colors[left][0] + (colors[right][0] - colors[left][0]) * fraction)
                g = int(colors[left][1] + (colors[right][1] - colors[left][1]) * fraction)
                b = int(colors[left][2] + (colors[right][2] - colors[left][2]) * fraction)

                color = "#{:02X}{:02X}{:02X}".format(r, g, b)
                x1 = int(x * width / steps)
                x2 = int((x + 1) * width / steps) + 1

                canvas.create_rectangle(
                    x1,
                    0,
                    x2,
                    height,
                    fill=color,
                    outline="",
                    tags="gradient"
                )

        canvas.bind("<Configure>", redraw)
        canvas.pack(fill="x", padx=0, pady=0)
        canvas.after_idle(redraw)
        return canvas

    def section_heading(
        self,
        parent,
        title,
        subtitle
    ):

        frame = tk.Frame(
            parent,
            bg=self.BG
        )

        frame.pack(
            fill="x",
            padx=28,
            pady=(20, 18)
        )

        tk.Label(
            frame,
            text=title,
            bg=self.BG,
            fg=self.TEXT,
            font=("Segoe UI", 17, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            frame,
            text=subtitle,
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 9),
            wraplength=900,
            justify="left"
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

    # =========================================================
    # DASHBOARD
    # =========================================================

    def build_dashboard(self):

        page = self.create_scroll_page()

        self.create_background_canvas(page)

        foreground = tk.Frame(
            page,
            bg=self.BG
        )

        foreground.pack(
            fill="both",
            expand=True
        )

        hero = tk.Frame(
            foreground,
            bg="#0B1D31",
            highlightbackground="#24557A",
            highlightthickness=1
        )

        hero.pack(
            fill="x",
            padx=28,
            pady=(20, 15)
        )

        hero_gradient = tk.Canvas(
            hero,
            height=5,
            bg="#0C2035",
            highlightthickness=0,
            bd=0
        )
        hero_gradient.place(
            x=0,
            y=0,
            relwidth=1
        )

        def draw_hero_gradient(event=None):
            width = max(hero_gradient.winfo_width(), 1)
            hero_gradient.delete("gradient")
            stops = [
                (53, 167, 255),
                (36, 225, 255),
                (155, 123, 255),
                (53, 211, 154)
            ]
            for x in range(width):
                progress = x / max(width - 1, 1)
                position = progress * (len(stops) - 1)
                left_index = int(position)
                right_index = min(left_index + 1, len(stops) - 1)
                fraction = position - left_index
                r = int(stops[left_index][0] + (stops[right_index][0] - stops[left_index][0]) * fraction)
                g = int(stops[left_index][1] + (stops[right_index][1] - stops[left_index][1]) * fraction)
                b = int(stops[left_index][2] + (stops[right_index][2] - stops[left_index][2]) * fraction)
                color = "#{:02X}{:02X}{:02X}".format(r, g, b)
                hero_gradient.create_line(x, 0, x, 5, fill=color, tags="gradient")

        hero_gradient.bind("<Configure>", draw_hero_gradient)

        left = tk.Frame(
            hero,
            bg="#0B1D31"
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=25,
            pady=22
        )

        tk.Label(
            left,
            text="YOUR DIGITAL SECURITY CENTER",
            bg="#0C2035",
            fg=self.CYAN,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            left,
            text="Everything protected.\nEverything under control.",
            bg="#0C2035",
            fg=self.TEXT,
            font=("Segoe UI", 24, "bold"),
            justify="left"
        ).pack(
            anchor="w",
            pady=(7, 5)
        )

        tk.Label(
            left,
            text=(
                "Encrypt files, protect secrets, verify integrity "
                "and analyze suspicious content from one secure workspace."
            ),
            bg="#0C2035",
            fg=self.MUTED,
            font=("Segoe UI", 10),
            wraplength=650,
            justify="left"
        ).pack(
            anchor="w"
        )

        actions = tk.Frame(
            left,
            bg="#0C2035"
        )

        actions.pack(
            anchor="w",
            pady=(18, 0)
        )

        self.button(
            actions,
            "  Encrypt a File  ",
            lambda: self.show_page("File Security")
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            actions,
            "  Scan Threats  ",
            lambda: self.show_page("Spam & Phishing"),
            primary=False
        ).pack(
            side="left"
        )

        shield = tk.Canvas(
            hero,
            width=180,
            height=170,
            bg="#0C2035",
            highlightthickness=0
        )

        shield.pack(
            side="right",
            padx=35
        )

        shield.create_oval(
            25,
            20,
            155,
            150,
            outline="#1B5275",
            width=2
        )

        shield.create_oval(
            42,
            37,
            138,
            133,
            outline="#4D98B8",
            width=2
        )

        shield.create_oval(
            58,
            53,
            122,
            117,
            outline="#1C5B7A",
            width=1
        )

        shield.create_text(
            90,
            78,
            text="✓",
            fill=self.CYAN,
            font=("Segoe UI", 45, "bold")
        )

        shield.create_text(
            90,
            122,
            text="SECURE",
            fill=self.GREEN,
            font=("Segoe UI", 8, "bold")
        )

        stats = tk.Frame(
            foreground,
            bg=self.BG
        )

        stats.pack(
            fill="x",
            padx=22
        )

        for i in range(5):
            stats.columnconfigure(
                i,
                weight=1
            )

        cards = [

            (
                "ENCRYPTED FILES",
                "0",
                self.BLUE,
                "▣"
            ),

            (
                "INTEGRITY CHECKS",
                "0",
                self.GREEN,
                "◈"
            ),

            (
                "VAULT ENTRIES",
                "0",
                self.PURPLE,
                "◆"
            ),

            (
                "SECURITY EVENTS",
                "0",
                self.ORANGE,
                "≡"
            ),

            (
                "ACTIVE SHARES",
                "0",
                self.CYAN,
                "⇄"
            )
        ]

        for i, item in enumerate(cards):

            title, value, color, icon = item

            self.create_stat_card(
                stats,
                i,
                title,
                value,
                color,
                icon
            )

        lower = tk.Frame(
            foreground,
            bg=self.BG
        )

        lower.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=15
        )

        module_card = tk.Frame(
            lower,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        module_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 8)
        )

        self.title_text(
            module_card,
            "Security Modules",
            "Protection layers currently available"
        )

        grid = tk.Frame(
            module_card,
            bg=self.CARD
        )

        grid.pack(
            fill="both",
            expand=True
        )

        modules = [

            ("AES GCM", "File encryption", self.BLUE),
            ("SHA 256", "Integrity verification", self.GREEN),
            ("Secure Vault", "Encrypted secrets", self.PURPLE),
            ("Threat Scanner", "Spam and phishing", self.RED),
            ("Local Sharing", "Temporary transfer", self.CYAN),
            ("Audit Logs", "Security history", self.ORANGE)
        ]

        for i, item in enumerate(modules):

            name, desc, color = item

            row = i // 2
            column = i % 2

            grid.rowconfigure(
                row,
                weight=1
            )

            grid.columnconfigure(
                column,
                weight=1
            )

            module = tk.Frame(
                grid,
                bg="#0B1A2C",
                highlightbackground=self.BORDER,
                highlightthickness=1
            )

            module.grid(
                row=row,
                column=column,
                padx=5,
                pady=5,
                sticky="nsew"
            )

            tk.Label(
                module,
                text="●",
                bg="#0B1A2C",
                fg=color,
                font=("Segoe UI", 12)
            ).pack(
                side="left",
                padx=12
            )

            text = tk.Frame(
                module,
                bg="#0B1A2C"
            )

            text.pack(
                side="left",
                anchor="center"
            )

            tk.Label(
                text,
                text=name,
                bg="#0B1A2C",
                fg=self.TEXT,
                font=("Segoe UI", 9, "bold")
            ).pack(
                anchor="w"
            )

            tk.Label(
                text,
                text=desc,
                bg="#0B1A2C",
                fg=self.MUTED,
                font=("Segoe UI", 8)
            ).pack(
                anchor="w"
            )

        score_card = tk.Frame(
            lower,
            bg=self.CARD,
            width=300,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        score_card.pack(
            side="right",
            fill="y",
            padx=(8, 0)
        )

        score_card.pack_propagate(False)
        self.gradient_bar(score_card, 4)

        self.title_text(
            score_card,
            "Security Status",
            "Current protection state"
        )

        score_canvas = tk.Canvas(
            score_card,
            width=180,
            height=180,
            bg=self.CARD,
            highlightthickness=0
        )

        score_canvas.pack(
            pady=5
        )

        score_canvas.create_oval(
            20,
            20,
            160,
            160,
            outline="#1A2B42",
            width=13
        )

        score_canvas.create_arc(
            20,
            20,
            160,
            160,
            start=90,
            extent=300,
            style="arc",
            outline=self.CYAN,
            width=13
        )

        score_canvas.create_text(
            90,
            80,
            text="SECURE",
            fill=self.TEXT,
            font=("Segoe UI", 12, "bold")
        )

        score_canvas.create_text(
            90,
            110,
            text="100%",
            fill=self.CYAN,
            font=("Segoe UI", 23, "bold")
        )

        tk.Label(
            score_card,
            text="All core modules operational",
            bg=self.CARD,
            fg=self.GREEN,
            font=("Segoe UI", 9, "bold")
        ).pack(
            pady=5
        )

    def create_stat_card(
        self,
        parent,
        column,
        title,
        value,
        color,
        icon
    ):

        card = tk.Frame(
            parent,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        card.grid(
            row=0,
            column=column,
            padx=6,
            sticky="nsew"
        )

        self.gradient_bar(card, 3)

        parent.columnconfigure(
            column,
            weight=1
        )

        tk.Label(
            card,
            text=icon,
            bg=self.CARD,
            fg=color,
            font=("Segoe UI", 20, "bold")
        ).pack(
            anchor="w",
            padx=16,
            pady=(13, 4)
        )

        value_label = tk.Label(
            card,
            text=value,
            bg=self.CARD,
            fg=self.TEXT,
            font=("Segoe UI", 23, "bold")
        )

        value_label.pack(
            anchor="w",
            padx=16
        )

        tk.Label(
            card,
            text=title,
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=16,
            pady=(0, 14)
        )

        self.dashboard_values[title] = value_label

    def refresh_dashboard(self):

        try:

            encrypted, hashes, vault, logs = get_counts()

            active = (
                1
                if self.share_manager.active()
                else 0
            )

            values = {

                "ENCRYPTED FILES": encrypted,
                "INTEGRITY CHECKS": hashes,
                "VAULT ENTRIES": vault,
                "SECURITY EVENTS": logs,
                "ACTIVE SHARES": active
            }

            for title, value in values.items():

                if title in self.dashboard_values:

                    self.dashboard_values[
                        title
                    ].configure(
                        text=str(value)
                    )

        except Exception:
            pass

    # =========================================================
    # FILE SECURITY
    # =========================================================

    def build_file_security(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "File Security Center",
            "Protect sensitive files using AES GCM authenticated encryption."
        )

        security_card = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        security_card.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            security_card,
            "AES GCM File Protection",
            "Select a file, provide a strong password and create a SecureVault protected package."
        )

        tk.Label(
            security_card,
            text="Encryption password",
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w"
        )

        password_row = tk.Frame(
            security_card,
            bg=self.CARD
        )

        password_row.pack(
            fill="x",
            pady=(5, 10)
        )

        self.input_box(
            password_row,
            self.file_password,
            55,
            "•"
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        self.button(
            password_row,
            "Generate Strong Password",
            self.generate_file_password
        ).pack(
            side="left",
            padx=(10, 0)
        )

        actions = tk.Frame(
            security_card,
            bg=self.CARD
        )

        actions.pack(
            anchor="w",
            pady=(5, 10)
        )

        self.button(
            actions,
            "Encrypt File",
            self.encrypt_file
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            actions,
            "Decrypt .secure File",
            self.decrypt_file,
            primary=False
        ).pack(
            side="left"
        )

        result = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        result.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=18
        )

        self.title_text(
            result,
            "Operation Console",
            "Encryption and decryption results appear here."
        )

        self.file_output = tk.Text(
            result,
            bg="#07101C",
            fg="#BFD7EF",
            insertbackground=self.CYAN,
            selectbackground="#1C4162",
            relief="flat",
            borderwidth=0,
            font=("Consolas", 10),
            padx=18,
            pady=18
        )

        self.file_output.pack(
            fill="both",
            expand=True
        )

    def generate_file_password(self):

        password = generate_password(
            20,
            True
        )

        self.file_password.set(password)

        self.set_status(
            "Strong encryption password generated"
        )

        add_log(
            "Password generated",
            "File encryption password generated."
        )

    def encrypt_file(self):

        path = filedialog.askopenfilename()

        if not path:
            return

        password = self.file_password.get()

        if not password:

            messagebox.showwarning(
                "Password Required",
                "Enter an encryption password first."
            )

            return

        try:

            with open(path, "rb") as file:
                data = file.read()

            digest = hashlib.sha256(
                data
            ).hexdigest()

            metadata = {

                "original_name":
                    os.path.basename(path),

                "original_size":
                    len(data),

                "sha256":
                    digest,

                "created":
                    datetime.now().isoformat()
            }

            encrypted = encrypt_data(
                data,
                password,
                metadata
            )

            output = path + ".secure"

            with open(output, "wb") as file:
                file.write(encrypted)

            self.file_output.delete(
                "1.0",
                "end"
            )

            self.file_output.insert(
                "end",

                "SECUREVAULT ENCRYPTION COMPLETE\n"
                "════════════════════════════════════════\n\n"

                f"Original file\n"
                f"  {path}\n\n"

                f"Protected file\n"
                f"  {output}\n\n"

                f"Original size\n"
                f"  {len(data):,} bytes\n\n"

                f"SHA 256\n"
                f"  {digest}\n\n"

                "Cryptography\n"
                "  AES GCM\n\n"

                "Key derivation\n"
                "  PBKDF2 SHA 256\n\n"

                f"Iterations\n"
                f"  {PBKDF2_ITERATIONS:,}\n"
            )

            add_log(
                "File encrypted",
                os.path.basename(path)
            )

            self.refresh_dashboard()

            self.set_status(
                "File encrypted successfully"
            )

            messagebox.showinfo(
                "Encryption Complete",
                "File encrypted successfully."
            )

        except Exception as error:

            messagebox.showerror(
                "Encryption Error",
                str(error)
            )

    def decrypt_file(self):

        path = filedialog.askopenfilename(
            filetypes=[
                (
                    "SecureVault files",
                    "*.secure"
                ),
                (
                    "All files",
                    "*.*"
                )
            ]
        )

        if not path:
            return

        password = self.file_password.get()

        if not password:

            messagebox.showwarning(
                "Password Required",
                "Enter the encryption password."
            )

            return

        try:

            with open(path, "rb") as file:
                package = file.read()

            data, metadata = decrypt_data(
                package,
                password
            )

            output_folder = filedialog.askdirectory()

            if not output_folder:
                return

            filename = metadata.get(
                "original_name",
                "decrypted_file"
            )

            output = os.path.join(
                output_folder,
                filename
            )

            with open(output, "wb") as file:
                file.write(data)

            current_hash = hashlib.sha256(
                data
            ).hexdigest()

            expected_hash = metadata.get(
                "sha256",
                ""
            )

            verified = (
                current_hash == expected_hash
            )

            self.file_output.delete(
                "1.0",
                "end"
            )

            self.file_output.insert(
                "end",

                "SECUREVAULT DECRYPTION COMPLETE\n"
                "════════════════════════════════════════\n\n"

                f"Output file\n"
                f"  {output}\n\n"

                f"SHA 256\n"
                f"  {current_hash}\n\n"

                "Integrity verification\n"
                f"  {'VERIFIED' if verified else 'NOT VERIFIED'}\n"
            )

            add_log(
                "File decrypted",
                os.path.basename(path)
            )

            self.refresh_dashboard()

            self.set_status(
                "File decrypted and integrity checked"
            )

            messagebox.showinfo(
                "Decryption Complete",
                "File decrypted successfully."
            )

        except Exception:

            messagebox.showerror(
                "Decryption Failed",
                "Wrong password or corrupted SecureVault file."
            )

    # =========================================================
    # INTEGRITY
    # =========================================================

    def build_integrity(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "File Integrity",
            "Generate SHA 256 fingerprints and store trusted baselines."
        )

        scanner = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        scanner.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            scanner,
            "Integrity Scanner",
            "A SHA 256 fingerprint changes when file content changes."
        )

        row = tk.Frame(
            scanner,
            bg=self.CARD
        )

        row.pack(
            fill="x"
        )

        self.input_box(
            row,
            self.integrity_file,
            70
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        self.button(
            row,
            "Choose File",
            self.choose_integrity_file,
            primary=False
        ).pack(
            side="left",
            padx=(8, 0)
        )

        actions = tk.Frame(
            scanner,
            bg=self.CARD
        )

        actions.pack(
            anchor="w",
            pady=15
        )

        self.button(
            actions,
            "Calculate SHA 256",
            self.calculate_hash
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            actions,
            "Save Baseline",
            self.save_baseline,
            primary=False
        ).pack(
            side="left"
        )

        result = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        result.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=18
        )

        self.title_text(
            result,
            "Integrity Report",
            "Calculated file fingerprint and metadata"
        )

        self.integrity_output = tk.Text(
            result,
            bg="#07101C",
            fg="#BFD7EF",
            insertbackground=self.CYAN,
            relief="flat",
            font=("Consolas", 10),
            padx=18,
            pady=18
        )

        self.integrity_output.pack(
            fill="both",
            expand=True
        )

    def choose_integrity_file(self):

        path = filedialog.askopenfilename()

        if path:

            self.integrity_file.set(path)

            self.set_status(
                "File selected for integrity analysis"
            )

    def calculate_hash(self):

        path = self.integrity_file.get()

        if not os.path.isfile(path):

            messagebox.showwarning(
                "File Required",
                "Select a valid file."
            )

            return

        try:

            digest = sha256_file(path)

            self.integrity_output.delete(
                "1.0",
                "end"
            )

            self.integrity_output.insert(
                "end",

                "SHA 256 INTEGRITY REPORT\n"
                "════════════════════════════════════════\n\n"

                f"File\n{path}\n\n"

                f"SHA 256\n{digest}\n\n"

                f"Size\n{os.path.getsize(path):,} bytes\n\n"

                "Modified\n"
                f"{datetime.fromtimestamp(os.path.getmtime(path))}\n"
            )

            add_log(
                "Integrity hash calculated",
                os.path.basename(path)
            )

            self.refresh_dashboard()

            self.set_status(
                "SHA 256 fingerprint calculated"
            )

        except Exception as error:

            messagebox.showerror(
                "Integrity Error",
                str(error)
            )

    def save_baseline(self):

        path = self.integrity_file.get()

        if not os.path.isfile(path):

            messagebox.showwarning(
                "File Required",
                "Select a valid file first."
            )

            return

        try:

            digest = sha256_file(path)

            connection = connect()

            connection.execute(
                """
                INSERT INTO hashes
                (file_name, file_path, file_hash, created_at)
                VALUES (?, ?, ?, datetime('now'))
                """,
                (
                    os.path.basename(path),
                    path,
                    digest
                )
            )

            connection.commit()
            connection.close()

            add_log(
                "Integrity baseline saved",
                os.path.basename(path)
            )

            self.refresh_dashboard()

            self.set_status(
                "SHA 256 baseline saved"
            )

            messagebox.showinfo(
                "Baseline Saved",
                "SHA 256 baseline saved."
            )

        except Exception as error:

            messagebox.showerror(
                "Baseline Error",
                str(error)
            )

    # =========================================================
    # PASSWORD TOOLS
    # =========================================================

    def build_password_tools(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "Password Security Center",
            "Generate high entropy passwords and evaluate password strength."
        )

        generator = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        generator.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            generator,
            "Secure Password Generator",
            "Generate passwords locally. Generated values are never written to activity logs."
        )

        controls = tk.Frame(
            generator,
            bg=self.CARD
        )

        controls.pack(
            fill="x"
        )

        tk.Label(
            controls,
            text="Length",
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 9, "bold")
        ).pack(
            side="left"
        )

        self.password_length = tk.Spinbox(
            controls,
            from_=8,
            to=128,
            width=8,
            bg=self.INPUT,
            fg=self.TEXT,
            buttonbackground=self.CARD2,
            insertbackground=self.CYAN,
            relief="flat",
            font=("Segoe UI", 10)
        )

        self.password_length.delete(
            0,
            "end"
        )

        self.password_length.insert(
            0,
            "20"
        )

        self.password_length.pack(
            side="left",
            padx=10
        )

        self.symbols = tk.BooleanVar(
            value=True
        )

        self.uppercase = tk.BooleanVar(
            value=True
        )

        self.lowercase = tk.BooleanVar(
            value=True
        )

        self.digits = tk.BooleanVar(
            value=True
        )

        self.exclude_ambiguous = tk.BooleanVar(
            value=False
        )

        tk.Checkbutton(
            controls,
            text="Include symbols",
            variable=self.symbols,
            bg=self.CARD,
            fg=self.TEXT,
            activebackground=self.CARD,
            activeforeground=self.TEXT,
            selectcolor=self.INPUT,
            font=("Segoe UI", 9)
        ).pack(
            side="left",
            padx=10
        )

        options = tk.Frame(
            generator,
            bg=self.CARD
        )

        options.pack(
            anchor="w",
            pady=(10, 0)
        )

        for text, variable in (
            ("Uppercase", self.uppercase),
            ("Lowercase", self.lowercase),
            ("Numbers", self.digits),
            ("Avoid ambiguous", self.exclude_ambiguous)
        ):
            tk.Checkbutton(
                options,
                text=text,
                variable=variable,
                bg=self.CARD,
                fg=self.TEXT,
                activebackground=self.CARD,
                activeforeground=self.TEXT,
                selectcolor=self.INPUT,
                font=("Segoe UI", 9)
            ).pack(
                side="left",
                padx=(0, 12)
            )

        self.button(
            controls,
            "Generate Password",
            self.generate_password_tool
        ).pack(
            side="left",
            padx=10
        )

        self.button(
            controls,
            "Copy",
            self.copy_generated_password,
            primary=False
        ).pack(
            side="left"
        )

        self.generated_entry = self.input_box(
            generator,
            self.generated_password,
            70
        )

        self.generated_entry.pack(
            fill="x",
            pady=(18, 5)
        )

        analyzer = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        analyzer.pack(
            fill="x",
            padx=28,
            pady=18
        )

        self.title_text(
            analyzer,
            "Password Strength Analyzer",
            "Analyze complexity without storing the password."
        )

        row = tk.Frame(
            analyzer,
            bg=self.CARD
        )

        row.pack(
            fill="x"
        )

        self.password_to_analyze = self.input_box(
            row,
            width=60,
            show="•"
        )

        self.password_to_analyze.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.button(
            row,
            "Analyze",
            self.analyze_password_tool
        ).pack(
            side="left",
            padx=(10, 0)
        )

        self.password_result = tk.Label(
            analyzer,
            text="READY",
            bg=self.CARD,
            fg=self.CYAN,
            font=("Segoe UI", 15, "bold")
        )

        self.password_result.pack(
            anchor="w",
            pady=(18, 5)
        )

        self.password_advice = tk.Label(
            analyzer,
            text="Enter a password to receive security recommendations.",
            bg=self.CARD,
            fg=self.MUTED,
            justify="left",
            font=("Segoe UI", 9)
        )

        self.password_advice.pack(
            anchor="w"
        )

    def generate_password_tool(self):

        try:

            length = int(
                self.password_length.get()
            )

        except ValueError:

            length = 20

        length = max(
            8,
            min(length, 128)
        )

        password = generate_password(
            length,
            self.symbols.get(),
            self.uppercase.get(),
            self.lowercase.get(),
            self.digits.get(),
            self.exclude_ambiguous.get()
        )

        self.generated_password.set(
            password
        )

        add_log(
            "Password generated",
            "Password value was not logged."
        )

        self.set_status(
            "Strong password generated locally"
        )

    def copy_generated_password(self):

        value = self.generated_password.get()

        if not value:
            return

        try:

            self.clipboard_clear()
            self.clipboard_append(value)
            self.update()

            self.set_status(
                "Generated password copied to clipboard"
            )

            messagebox.showinfo(
                "Copied",
                "Password copied to clipboard."
            )

        except Exception as error:

            messagebox.showerror(
                "Clipboard Error",
                str(error)
            )

    def analyze_password_tool(self):

        password = self.password_to_analyze.get()

        score, label, advice = analyze_password(
            password
        )

        self.password_result.configure(
            text=f"{label}   {score}/6"
        )

        if label in (
            "STRONG",
            "VERY STRONG"
        ):

            self.password_result.configure(
                fg=self.GREEN
            )

        elif label == "MEDIUM":

            self.password_result.configure(
                fg=self.ORANGE
            )

        else:

            self.password_result.configure(
                fg=self.RED
            )

        if advice:

            self.password_advice.configure(
                text="\n".join(
                    "• " + item
                    for item in advice
                )
            )

        else:

            self.password_advice.configure(
                text="No immediate weaknesses detected."
            )

        add_log(
            "Password strength checked",
            "Password value was not logged."
        )

        self.set_status(
            "Password strength analysis completed"
        )

    # =========================================================
    # VAULT
    # =========================================================

    def build_vault(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "Encrypted Secure Vault",
            "Store private notes, API keys, credentials and recovery information."
        )

        master = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        master.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            master,
            "Vault Access",
            "Your master password is used to decrypt selected vault entries."
        )

        master_row = tk.Frame(
            master,
            bg=self.CARD
        )

        master_row.pack(
            fill="x"
        )

        self.input_box(
            master_row,
            self.vault_master,
            50,
            "•"
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        form = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        form.pack(
            fill="x",
            padx=28,
            pady=18
        )

        self.title_text(
            form,
            "Create Secure Entry",
            "New information is encrypted before being stored."
        )

        row = tk.Frame(
            form,
            bg=self.CARD
        )

        row.pack(
            fill="x"
        )

        self.input_box(
            row,
            self.vault_title,
            35
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        categories = [
            "Private Note",
            "API Key",
            "Recovery Code",
            "Credential",
            "Secret"
        ]

        ttk.Combobox(
            row,
            textvariable=self.vault_category,
            values=categories,
            state="readonly",
            width=20,
            style="Modern.TCombobox"
        ).pack(
            side="left",
            padx=10
        )

        self.vault_secret = tk.Text(
            form,
            height=5,
            bg=self.INPUT,
            fg=self.TEXT,
            insertbackground=self.CYAN,
            relief="flat",
            font=("Segoe UI", 10),
            padx=12,
            pady=10
        )

        self.vault_secret.pack(
            fill="x",
            pady=12
        )

        actions = tk.Frame(
            form,
            bg=self.CARD
        )

        actions.pack(
            anchor="w"
        )

        self.button(
            actions,
            "Save Encrypted Secret",
            self.save_vault
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            actions,
            "Load Selected",
            self.load_vault,
            primary=False
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            actions,
            "Delete Selected",
            self.delete_vault,
            primary=False
        ).pack(
            side="left"
        )

        table_card = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        table_card.pack(
            fill="both",
            expand=True,
            padx=28
        )

        self.title_text(
            table_card,
            "Vault Entries",
            "Encrypted records currently stored"
        )

        self.vault_tree = ttk.Treeview(
            table_card,
            columns=(
                "id",
                "title",
                "category",
                "created"
            ),
            show="headings",
            style="Modern.Treeview"
        )

        widths = {
            "id": 70,
            "title": 280,
            "category": 180,
            "created": 220
        }

        for column, heading in [

            ("id", "ID"),
            ("title", "TITLE"),
            ("category", "CATEGORY"),
            ("created", "CREATED")

        ]:

            self.vault_tree.heading(
                column,
                text=heading
            )

            self.vault_tree.column(
                column,
                width=widths[column],
                anchor="w"
            )

        self.vault_tree.pack(
            fill="both",
            expand=True
        )

    def refresh_vault(self):

        if not hasattr(
            self,
            "vault_tree"
        ):
            return

        try:

            for item in self.vault_tree.get_children():
                self.vault_tree.delete(item)

            for row in get_secrets():

                self.vault_tree.insert(
                    "",
                    "end",
                    values=row
                )

        except Exception:
            pass

    def selected_vault(self):

        selected = self.vault_tree.selection()

        if not selected:
            return None

        values = self.vault_tree.item(
            selected[0]
        )["values"]

        return values[0]

    def save_vault(self):

        master = self.vault_master.get()
        title = self.vault_title.get().strip()

        secret = self.vault_secret.get(
            "1.0",
            "end"
        ).strip()

        if not master or not title or not secret:

            messagebox.showwarning(
                "Missing Information",
                "Enter master password, title and secret."
            )

            return

        try:

            save_secret(
                title,
                self.vault_category.get(),
                secret,
                master
            )

            self.vault_title.set("")

            self.vault_secret.delete(
                "1.0",
                "end"
            )

            self.refresh_vault()

            add_log(
                "Vault secret saved",
                title
            )

            self.refresh_dashboard()

            self.set_status(
                "Encrypted vault entry saved"
            )

            messagebox.showinfo(
                "Saved",
                "Encrypted secret saved."
            )

        except Exception as error:

            messagebox.showerror(
                "Vault Error",
                str(error)
            )

    def load_vault(self):

        secret_id = self.selected_vault()

        if not secret_id:

            messagebox.showwarning(
                "Selection Required",
                "Select a vault entry."
            )

            return

        master = self.vault_master.get()

        if not master:

            messagebox.showwarning(
                "Master Password",
                "Enter the master password."
            )

            return

        try:

            result = get_secret(
                secret_id,
                master
            )

            self.vault_title.set(
                result["title"]
            )

            self.vault_category.set(
                result["category"]
            )

            self.vault_secret.delete(
                "1.0",
                "end"
            )

            self.vault_secret.insert(
                "1.0",
                result["secret"]
            )

            add_log(
                "Vault secret opened",
                result["title"]
            )

            self.set_status(
                "Vault entry decrypted"
            )

        except Exception:

            messagebox.showerror(
                "Access Denied",
                "Incorrect master password."
            )

    def delete_vault(self):

        secret_id = self.selected_vault()

        if not secret_id:
            return

        if not messagebox.askyesno(
            "Confirm Deletion",
            "Delete the selected vault entry?"
        ):
            return

        try:

            delete_secret(secret_id)

            self.refresh_vault()

            add_log(
                "Vault entry deleted",
                ""
            )

            self.refresh_dashboard()

            self.set_status(
                "Vault entry deleted"
            )

        except Exception as error:

            messagebox.showerror(
                "Deletion Error",
                str(error)
            )

    # =========================================================
    # SHARING
    # =========================================================

    def build_sharing(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "Secure Local File Sharing",
            "Temporarily share protected .secure files with devices on a trusted local network."
        )

        card = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        card.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            card,
            "Temporary Share",
            "The URL does not contain the encryption password."
        )

        row = tk.Frame(
            card,
            bg=self.CARD
        )

        row.pack(
            fill="x"
        )

        ttk.Combobox(
            row,
            textvariable=self.share_duration,
            values=[
                "10 minutes",
                "30 minutes",
                "1 hour",
                "6 hours",
                "24 hours"
            ],
            state="readonly",
            width=18,
            style="Modern.TCombobox"
        ).pack(
            side="left"
        )

        self.button(
            row,
            "Start Share",
            self.start_share
        ).pack(
            side="left",
            padx=8
        )

        self.button(
            row,
            "Stop Share",
            self.stop_share,
            primary=False
        ).pack(
            side="left"
        )

        self.share_status_label = tk.Label(
            card,
            textvariable=self.share_status,
            bg=self.CARD,
            fg=self.GREEN,
            font=("Segoe UI", 10, "bold")
        )

        self.share_status_label.pack(
            anchor="w",
            pady=(15, 5)
        )

        output = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        output.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=18
        )

        self.title_text(
            output,
            "Share Console",
            "Temporary access information"
        )

        self.share_output = tk.Text(
            output,
            bg="#07101C",
            fg="#BFD7EF",
            insertbackground=self.CYAN,
            relief="flat",
            font=("Consolas", 10),
            padx=18,
            pady=18
        )

        self.share_output.pack(
            fill="both",
            expand=True
        )

        self.share_output.insert(
            "end",

            "SECURE LOCAL SHARING\n"
            "════════════════════════════════════════\n\n"

            "Only share .secure files.\n\n"

            "The encryption password is never included in the URL.\n\n"

            "The recipient must separately know the password.\n\n"

            "This service is intended for a trusted local network.\n"
        )

    def start_share(self):

        path = filedialog.askopenfilename(
            filetypes=[
                (
                    "SecureVault files",
                    "*.secure"
                )
            ]
        )

        if not path:
            return

        duration_map = {

            "10 minutes": 10,
            "30 minutes": 30,
            "1 hour": 60,
            "6 hours": 360,
            "24 hours": 1440
        }

        minutes = duration_map.get(
            self.share_duration.get(),
            30
        )

        try:

            url = self.share_manager.start(
                path,
                minutes
            )

            expiry = (
                datetime.now() +
                timedelta(
                    minutes=minutes
                )
            )

            self.share_status.set(
                "● ACTIVE  •  expires " +
                expiry.strftime(
                    "%H:%M:%S"
                )
            )

            self.share_status_label.configure(
                fg=self.GREEN
            )

            self.share_output.delete(
                "1.0",
                "end"
            )

            self.share_output.insert(
                "end",

                "TEMPORARY SHARE ACTIVE\n"
                "════════════════════════════════════════\n\n"

                f"File\n"
                f"  {os.path.basename(path)}\n\n"

                f"Temporary URL\n"
                f"  {url}\n\n"

                f"Expires\n"
                f"  {expiry}\n\n"

                "Password in URL\n"
                "  NO\n\n"

                "Network scope\n"
                "  Trusted local network only\n"
            )

            try:

                self.clipboard_clear()
                self.clipboard_append(url)
                self.update()

            except Exception:
                pass

            add_log(
                "Secure share started",
                os.path.basename(path)
            )

            self.refresh_dashboard()

            self.set_status(
                "Temporary secure share started"
            )

            messagebox.showinfo(
                "Share Created",
                "Temporary sharing URL copied to clipboard."
            )

        except Exception as error:

            messagebox.showerror(
                "Sharing Error",
                str(error)
            )

    def stop_share(self):

        try:
            self.share_manager.stop()
        except Exception:
            pass

        self.share_status.set(
            "No active share"
        )

        if hasattr(
            self,
            "share_status_label"
        ):

            self.share_status_label.configure(
                fg=self.MUTED
            )

        add_log(
            "Secure share stopped",
            ""
        )

        self.refresh_dashboard()

        self.set_status(
            "Secure share stopped"
        )

    # =========================================================
    # THREAT DETECTION
    # =========================================================

    def build_threat_detection(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "Spam & Phishing Intelligence",
            "Analyze suspicious messages and URLs using local heuristic detection."
        )

        message_card = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        message_card.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            message_card,
            "Message Analysis",
            "Paste suspicious email or message content for local analysis."
        )

        tk.Label(
            message_card,
            text="Sender",
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w"
        )

        self.input_box(
            message_card,
            self.spam_sender,
            70
        ).pack(
            fill="x",
            pady=(3, 7)
        )

        tk.Label(
            message_card,
            text="Subject",
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w"
        )

        self.input_box(
            message_card,
            self.spam_subject,
            70
        ).pack(
            fill="x",
            pady=(3, 10)
        )

        tk.Label(
            message_card,
            text="Message",
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w"
        )

        self.spam_message = tk.Text(
            message_card,
            height=7,
            bg=self.INPUT,
            fg=self.TEXT,
            insertbackground=self.CYAN,
            relief="flat",
            font=("Segoe UI", 10),
            padx=12,
            pady=10
        )

        self.spam_message.pack(
            fill="x",
            pady=(3, 0)
        )

        actions = tk.Frame(
            message_card,
            bg=self.CARD
        )

        actions.pack(
            anchor="w",
            pady=12
        )

        self.button(
            actions,
            "Analyze Message",
            self.analyze_spam
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            actions,
            "Clear",
            self.clear_threat,
            primary=False
        ).pack(
            side="left"
        )

        url_card = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        url_card.pack(
            fill="x",
            padx=28,
            pady=15
        )

        self.title_text(
            url_card,
            "URL Risk Scanner",
            "Check suspicious links locally before opening them."
        )

        url_row = tk.Frame(
            url_card,
            bg=self.CARD
        )

        url_row.pack(
            fill="x"
        )

        self.input_box(
            url_row,
            self.url_value,
            70
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        self.button(
            url_row,
            "Analyze URL",
            self.analyze_single_url
        ).pack(
            side="left",
            padx=(10, 0)
        )

        result = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        result.pack(
            fill="both",
            expand=True,
            padx=28
        )

        self.title_text(
            result,
            "Threat Intelligence Report",
            "Results generated by the local detection engine"
        )

        self.threat_output = tk.Text(
            result,
            bg="#07101C",
            fg="#BFD7EF",
            insertbackground=self.CYAN,
            relief="flat",
            font=("Consolas", 10),
            padx=18,
            pady=18
        )

        self.threat_output.pack(
            fill="both",
            expand=True
        )

    def analyze_spam(self):

        message = self.spam_message.get(
            "1.0",
            "end"
        ).strip()

        if not message:

            messagebox.showwarning(
                "Message Required",
                "Paste a message first."
            )

            return

        try:

            report = analyze_message(
                message,
                self.spam_subject.get(),
                self.spam_sender.get()
            )

            self.threat_output.delete(
                "1.0",
                "end"
            )

            self.threat_output.insert(
                "end",

                "THREAT INTELLIGENCE REPORT\n"
                "════════════════════════════════════════\n\n"

                f"CLASSIFICATION\n"
                f"  {report['classification']}\n\n"

                f"RISK LEVEL\n"
                f"  {report['risk']}\n\n"

                f"SPAM SCORE\n"
                f"  {report['spam_score']}%\n\n"

                f"PHISHING SCORE\n"
                f"  {report['phishing_score']}%\n\n"

                "SPAM INDICATORS\n"
            )

            spam_reasons = report.get(
                "spam_reasons",
                []
            )

            if spam_reasons:

                for reason in spam_reasons:

                    self.threat_output.insert(
                        "end",
                        "  • " + reason + "\n"
                    )

            else:

                self.threat_output.insert(
                    "end",
                    "  No major spam indicators detected.\n"
                )

            self.threat_output.insert(
                "end",
                "\nPHISHING INDICATORS\n"
            )

            phishing_reasons = report.get(
                "phishing_reasons",
                []
            )

            if phishing_reasons:

                for reason in phishing_reasons:

                    self.threat_output.insert(
                        "end",
                        "  • " + reason + "\n"
                    )

            else:

                self.threat_output.insert(
                    "end",
                    "  No major phishing indicators detected.\n"
                )

            self.threat_output.insert(
                "end",
                "\nURL ANALYSIS\n"
            )

            urls = report.get(
                "urls",
                []
            )

            if urls:

                for item in urls:

                    self.threat_output.insert(
                        "end",

                        f"\nURL\n"
                        f"  {item.get('url', '')}\n"

                        f"Host\n"
                        f"  {item.get('host', '')}\n"

                        f"Risk\n"
                        f"  {item.get('risk', '')}\n"

                        f"Score\n"
                        f"  {item.get('score', 0)}%\n"

                        f"Reasons\n"
                        f"  {', '.join(item.get('reasons', []))}\n"
                    )

            else:

                self.threat_output.insert(
                    "end",
                    "\nNo URL found.\n"
                )

            add_log(
                "Threat analysis",
                f"{report['classification']}, "
                f"spam={report['spam_score']}, "
                f"phishing={report['phishing_score']}"
            )

            self.refresh_dashboard()

            self.set_status(
                "Threat analysis completed"
            )

        except Exception as error:

            messagebox.showerror(
                "Threat Analysis Error",
                str(error)
            )

    def analyze_single_url(self):

        url = self.url_value.get().strip()

        if not url:

            messagebox.showwarning(
                "URL Required",
                "Enter a URL first."
            )

            return

        try:

            report = analyze_url(url)

            self.threat_output.delete(
                "1.0",
                "end"
            )

            self.threat_output.insert(
                "end",

                "URL SECURITY REPORT\n"
                "════════════════════════════════════════\n\n"

                f"URL\n"
                f"  {report['url']}\n\n"

                f"HOST\n"
                f"  {report['host']}\n\n"

                f"RISK\n"
                f"  {report['risk']}\n\n"

                f"SCORE\n"
                f"  {report['score']}%\n\n"

                "INDICATORS\n"
            )

            reasons = report.get(
                "reasons",
                []
            )

            if reasons:

                for reason in reasons:

                    self.threat_output.insert(
                        "end",
                        "  • " + reason + "\n"
                    )

            else:

                self.threat_output.insert(
                    "end",
                    "  No suspicious indicators detected.\n"
                )

            add_log(
                "URL analysis",
                report["host"]
            )

            self.refresh_dashboard()

            self.set_status(
                "URL risk analysis completed"
            )

        except Exception as error:

            messagebox.showerror(
                "URL Analysis Error",
                str(error)
            )

    def clear_threat(self):

        self.spam_sender.set("")
        self.spam_subject.set("")
        self.url_value.set("")

        if hasattr(
            self,
            "spam_message"
        ):

            self.spam_message.delete(
                "1.0",
                "end"
            )

        if hasattr(
            self,
            "threat_output"
        ):

            self.threat_output.delete(
                "1.0",
                "end"
            )

        self.set_status(
            "Threat analysis workspace cleared"
        )

    # =========================================================
    # LOGS
    # =========================================================

    def build_logs(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "Activity Logs",
            "Audit history of security operations. Password values are never stored."
        )

        controls = tk.Frame(
            page,
            bg=self.BG
        )

        controls.pack(
            fill="x",
            padx=28
        )

        self.button(
            controls,
            "Refresh Logs",
            self.refresh_logs
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.button(
            controls,
            "Clear Logs",
            self.clear_activity_logs,
            primary=False
        ).pack(
            side="left"
        )

        card = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        card.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=15
        )

        self.title_text(
            card,
            "Security Audit Trail",
            "Recent security operations"
        )

        self.logs_output = tk.Text(
            card,
            bg="#07101C",
            fg="#BFD7EF",
            insertbackground=self.CYAN,
            relief="flat",
            font=("Consolas", 9),
            padx=18,
            pady=18
        )

        self.logs_output.pack(
            fill="both",
            expand=True
        )

        self.refresh_logs()

    def refresh_logs(self):

        if not hasattr(
            self,
            "logs_output"
        ):
            return

        try:

            self.logs_output.delete(
                "1.0",
                "end"
            )

            rows = get_logs()

            if not rows:

                self.logs_output.insert(
                    "end",
                    "\n  No security events recorded yet.\n"
                )

                return

            for row in rows:

                timestamp = row[0]
                event = row[1]
                details = row[2]

                self.logs_output.insert(
                    "end",

                    f"[{timestamp}]\n"
                    f"  EVENT    {event}\n"
                    f"  DETAILS  {details}\n"
                    f"────────────────────────────────────────\n"
                )

        except Exception as error:

            self.logs_output.insert(
                "end",
                f"\nUnable to load logs: {error}\n"
            )

    def clear_activity_logs(self):

        if not messagebox.askyesno(
            "Confirm",
            "Clear all activity logs?"
        ):
            return

        try:

            clear_logs()

            self.refresh_logs()
            self.refresh_dashboard()

            self.set_status(
                "Activity logs cleared"
            )

        except Exception as error:

            messagebox.showerror(
                "Log Error",
                str(error)
            )

    # =========================================================
    # SETTINGS
    # =========================================================

    def build_settings(self):

        page = self.create_scroll_page()

        self.section_heading(
            page,
            "Security Architecture",
            "Cryptographic configuration and platform security information."
        )

        architecture = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        architecture.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            architecture,
            "Cryptographic Stack",
            "Algorithms used by SecureVault"
        )

        settings = [

            (
                "FILE ENCRYPTION",
                "AES GCM",
                self.BLUE
            ),

            (
                "KEY DERIVATION",
                f"PBKDF2 SHA 256 • {PBKDF2_ITERATIONS:,} iterations",
                self.PURPLE
            ),

            (
                "INTEGRITY",
                "SHA 256",
                self.GREEN
            ),

            (
                "SECRET STORAGE",
                "Encrypted SQLite records",
                self.CYAN
            ),

            (
                "FILE SHARING",
                "Temporary local network server",
                self.ORANGE
            ),

            (
                "THREAT DETECTION",
                "Local heuristic analysis",
                self.RED
            )
        ]

        for name, value, color in settings:

            row = tk.Frame(
                architecture,
                bg="#0B1A2C"
            )

            row.pack(
                fill="x",
                pady=4
            )

            tk.Label(
                row,
                text="●",
                bg="#0B1A2C",
                fg=color,
                font=("Segoe UI", 12)
            ).pack(
                side="left",
                padx=12
            )

            tk.Label(
                row,
                text=name,
                bg="#0B1A2C",
                fg=self.MUTED,
                font=("Segoe UI", 8, "bold")
            ).pack(
                side="left",
                padx=5
            )

            tk.Label(
                row,
                text=value,
                bg="#0B1A2C",
                fg=self.TEXT,
                font=("Segoe UI", 9)
            ).pack(
                side="right",
                padx=15,
                pady=10
            )

        note = tk.Frame(
            page,
            bg="#211A0C",
            highlightbackground="#4B391A",
            highlightthickness=1
        )

        note.pack(
            fill="x",
            padx=28,
            pady=18
        )

        tk.Label(
            note,
            text="SECURITY NOTICE",
            bg="#211A0C",
            fg=self.ORANGE,
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            padx=18,
            pady=(14, 5)
        )

        tk.Label(
            note,
            text=(
                "The spam and phishing module is a heuristic warning system. "
                "It cannot guarantee that a message is safe or malicious. "
                "The sharing server is designed for trusted local network use "
                "and should not be exposed directly to the public internet."
            ),
            bg="#211A0C",
            fg="#C9B98D",
            wraplength=950,
            justify="left",
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            padx=18,
            pady=(0, 15)
        )

        about = tk.Frame(
            page,
            bg=self.CARD,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        about.pack(
            fill="x",
            padx=28
        )

        self.title_text(
            about,
            "SecureVault",
            "Local cybersecurity and privacy workstation"
        )

        tk.Label(
            about,
            text=(
                "SecureVault combines file encryption, integrity verification, "
                "secure secret storage, password analysis, temporary sharing "
                "and local threat analysis in one desktop application."
            ),
            bg=self.CARD,
            fg=self.MUTED,
            wraplength=950,
            justify="left",
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )

    # =========================================================
    # SCROLL PAGE
    # =========================================================

    def create_scroll_page(self):

        outer = tk.Frame(
            self.page_container,
            bg=self.BG
        )

        outer.pack(
            fill="both",
            expand=True
        )

        canvas = tk.Canvas(
            outer,
            bg=self.BG,
            highlightthickness=0
        )

        scrollbar = ttk.Scrollbar(
            outer,
            orient="vertical",
            command=canvas.yview,
            style="Vertical.TScrollbar"
        )

        content = tk.Frame(
            canvas,
            bg=self.BG
        )

        window_id = canvas.create_window(
            (0, 0),
            window=content,
            anchor="nw"
        )

        def update_scroll_region(event=None):

            canvas.configure(
                scrollregion=canvas.bbox("all")
            )

        def resize_content(event):

            canvas.itemconfigure(
                window_id,
                width=event.width
            )

        content.bind(
            "<Configure>",
            update_scroll_region
        )

        canvas.bind(
            "<Configure>",
            resize_content
        )

        canvas.configure(
            yscrollcommand=scrollbar.set
        )

        canvas.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.scroll_canvas = canvas

        def mouse_wheel(event):

            try:

                amount = int(
                    event.delta / 120
                )

                if amount == 0:
                    amount = 1

                canvas.yview_scroll(
                    operator.neg(amount),
                    "units"
                )

            except Exception:
                pass

        self.bind_all(
            "<MouseWheel>",
            mouse_wheel
        )

        self.bind_all(
            "<Button-4>",
            lambda event: canvas.yview_scroll(-1, "units")
        )

        self.bind_all(
            "<Button-5>",
            lambda event: canvas.yview_scroll(1, "units")
        )

        return content

    # =========================================================
    # CLOSE
    # =========================================================

    def close_application(self):

        self.animation_running = False

        try:
            self.share_manager.stop()
        except Exception:
            pass

        self.destroy()


# =========================================================
# APPLICATION ENTRY
# =========================================================

if __name__ == "__main__":

    app = SecureVault()

    app.mainloop()