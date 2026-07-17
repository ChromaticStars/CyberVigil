import tkinter as tk
from tkinter import ttk
from datetime import datetime


# ---- Modern color palette ----
BG_DARK      = "#0F172A"   # main background (slate-900)
BG_PANEL     = "#111827"   # panel/content background
BG_CARD      = "#1E293B"   # card background (slate-800)
BG_HEADER    = "#0B1120"   # header bar
ACCENT       = "#3B82F6"   # blue accent
ACCENT_SOFT  = "#1D4ED8"
TEXT_PRIMARY = "#F1F5F9"
TEXT_MUTED   = "#94A3B8"
GREEN        = "#22C55E"
RED          = "#EF4444"
YELLOW       = "#FACC15"
ORANGE       = "#F97316"

FONT_FAMILY = "Segoe UI"


class IDS_GUI:

    def __init__(self, root):

        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("1366x580")
        self.root.configure(bg=BG_DARK)
        self.root.minsize(1200, 540)

        self.total_packets = tk.StringVar(value="0")
        self.tcp_packets = tk.StringVar(value="0")
        self.udp_packets = tk.StringVar(value="0")
        self.icmp_packets = tk.StringVar(value="0")
        self.alerts = tk.StringVar(value="0")

        self.status = tk.StringVar(value="Stopped")
        self.runtime = tk.StringVar(value="00:00:00")

        self._setup_styles()

        # ---------------- Header ----------------
        header = tk.Frame(self.root, bg=BG_HEADER, height=58)
        header.pack(fill="x")
        header.pack_propagate(False)

        title = tk.Label(
            header,
            text="🛡  CYBERVIGIL",
            bg=BG_HEADER,
            fg=TEXT_PRIMARY,
            font=(FONT_FAMILY, 18, "bold")
        )
        title.pack(side="left", padx=20, pady=(12, 0))


        # ---------------- Status bar ----------------
        status_frame = tk.Frame(self.root, bg=BG_PANEL)
        status_frame.pack(fill="x")

        status_inner = tk.Frame(status_frame, bg=BG_PANEL)
        status_inner.pack(fill="x", padx=15, pady=6)

        tk.Label(
            status_inner,
            text="Status:",
            font=(FONT_FAMILY, 11, "bold"),
            bg=BG_PANEL,
            fg=TEXT_MUTED
        ).pack(side="left", padx=(0, 6))

        self.status_dot = tk.Label(
            status_inner,
            text="●",
            font=(FONT_FAMILY, 12),
            bg=BG_PANEL,
            fg=RED
        )
        self.status_dot.pack(side="left")

        self.status_label = tk.Label(
            status_inner,
            textvariable=self.status,
            fg=RED,
            bg=BG_PANEL,
            font=(FONT_FAMILY, 11, "bold")
        )
        self.status_label.pack(side="left", padx=(4, 0))

        self.runtime_label = tk.Label(
            status_inner,
            textvariable=self.runtime,
            bg=BG_PANEL,
            fg=TEXT_PRIMARY,
            font=(FONT_FAMILY, 11, "bold")
        )
        self.runtime_label.pack(side="right")

        tk.Label(
            status_inner,
            text="Runtime:",
            font=(FONT_FAMILY, 11, "bold"),
            bg=BG_PANEL,
            fg=TEXT_MUTED
        ).pack(side="right", padx=(0, 5))

        # ---------------- Stat cards ----------------
        stats_frame = tk.Frame(self.root, bg=BG_DARK)
        stats_frame.pack(fill="x", padx=15, pady=(8, 4))

        for i in range(5):
            stats_frame.grid_columnconfigure(i, weight=1)

        self.create_card(stats_frame, "TOTAL PACKETS", self.total_packets, 0, ACCENT)
        self.create_card(stats_frame, "TCP", self.tcp_packets, 1, "#38BDF8")
        self.create_card(stats_frame, "UDP", self.udp_packets, 2, "#A78BFA")
        self.create_card(stats_frame, "ICMP", self.icmp_packets, 3, ORANGE)
        self.create_card(stats_frame, "ALERTS", self.alerts, 4, RED)

        # ---------------- Content (tables) ----------------
        content = tk.Frame(self.root, bg=BG_DARK)
        content.pack(fill="both", expand=True, padx=15, pady=8)

        # -- Packet capture panel --
        packet_frame = tk.Frame(content, bg=BG_CARD, highlightbackground="#334155",
                                 highlightthickness=1)
        packet_frame.pack(side="left", fill="both", expand=False, padx=(0, 8))
        packet_frame.config(width=470)
        packet_frame.pack_propagate(False)

        tk.Label(
            packet_frame,
            text="LIVE PACKET CAPTURE",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            anchor="w"
        ).pack(fill="x", padx=12, pady=(10, 5))

        packet_table_wrap = tk.Frame(packet_frame, bg=BG_CARD)
        packet_table_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        packet_scroll = ttk.Scrollbar(packet_table_wrap)
        packet_scroll.pack(side="right", fill="y")

        self.packet_table = ttk.Treeview(
            packet_table_wrap,
            columns=("Time", "Protocol", "Source", "Destination", "Port"),
            show="headings",
            yscrollcommand=packet_scroll.set,
            height=7,
            style="Dark.Treeview"
        )
        packet_scroll.config(command=self.packet_table.yview)

        self.packet_table.heading("Time", text="Time")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Source", text="Source IP")
        self.packet_table.heading("Destination", text="Destination IP")
        self.packet_table.heading("Port", text="Port")

        self.packet_table.column("Time", width=55, anchor="center")
        self.packet_table.column("Protocol", width=55, anchor="center")
        self.packet_table.column("Source", width=90, anchor="center")
        self.packet_table.column("Destination", width=110, anchor="center")
        self.packet_table.column("Port", width=50, anchor="center")

        self.packet_table.pack(fill="both", expand=True)

        # -- Threat Intelligence panel (alert types / top sources / top ports) --
        intel_frame = tk.Frame(content, bg=BG_CARD, highlightbackground="#334155",
                                highlightthickness=1)
        intel_frame.pack(side="right", fill="y", expand=False, padx=(8, 0))
        intel_frame.config(width=300)
        intel_frame.pack_propagate(False)

        self.alert_types_table = self._build_intel_table(
            intel_frame, "Alert Types", ("Attack", "Count"), (170, 60)
        )
        self.top_ips_table = self._build_intel_table(
            intel_frame, "Top Source IPs", ("Source IP", "Count"), (170, 60)
        )
        self.top_ports_table = self._build_intel_table(
            intel_frame, "Top Source Ports", ("Port", "Count"), (170, 60)
        )

        # -- Alerts panel --
        alert_frame = tk.Frame(content, bg=BG_CARD, highlightbackground="#334155",
                                highlightthickness=1)
        alert_frame.pack(side="left", fill="both", expand=True, padx=(8, 0))

        tk.Label(
            alert_frame,
            text="IDS ALERTS",
            font=(FONT_FAMILY, 10, "bold"),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            anchor="w"
        ).pack(fill="x", padx=12, pady=(10, 5))

        alert_table_wrap = tk.Frame(alert_frame, bg=BG_CARD)
        alert_table_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        alert_scroll = ttk.Scrollbar(alert_table_wrap)
        alert_scroll.pack(side="right", fill="y")

        self.alert_table = ttk.Treeview(
            alert_table_wrap,
            columns=("Time", "Severity", "Attack", "Source"),
            show="headings",
            yscrollcommand=alert_scroll.set,
            height=7,
            style="Dark.Treeview"
        )
        alert_scroll.config(command=self.alert_table.yview)

        self.alert_table.heading("Time", text="Time")
        self.alert_table.heading("Severity", text="Severity")
        self.alert_table.heading("Attack", text="Attack")
        self.alert_table.heading("Source", text="Source IP")

        self.alert_table.column("Time", width=60, anchor="center")
        self.alert_table.column("Severity", width=70, anchor="center")
        self.alert_table.column("Attack", width=100, anchor="center")
        self.alert_table.column("Source", width=90, anchor="center")
        self.alert_table.pack(fill="both", expand=True)

        # Severity color tags (kept as originally used: HIGH / MEDIUM / CRITICAL)
        self.alert_table.tag_configure("HIGH", background="#4C1D1D", foreground="#FCA5A5")
        self.alert_table.tag_configure("MEDIUM", background="#4A3B0F", foreground="#FDE68A")
        self.alert_table.tag_configure("CRITICAL", background="#5B1010", foreground="#FECACA")

        # ---------------- Buttons ----------------
        button_frame = tk.Frame(self.root, bg=BG_DARK)
        button_frame.pack(fill="x", padx=15, pady=(0, 10))

        self.start_button = tk.Button(
            button_frame,
            text="▶  Start IDS",
            width=15,
            bg=GREEN,
            fg="white",
            activebackground="#16A34A",
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=(FONT_FAMILY, 10, "bold")
        )
        self.start_button.pack(side="left", padx=(0, 8), ipady=6)

        self.stop_button = tk.Button(
            button_frame,
            text="■  Stop IDS",
            width=15,
            bg=RED,
            fg="white",
            activebackground="#DC2626",
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=(FONT_FAMILY, 10, "bold")
        )
        self.stop_button.pack(side="left", padx=8, ipady=6)

        self.report_button = tk.Button(
            button_frame,
            text="📄  Generate Report",
            width=18,
            bg=ACCENT,
            fg="white",
            activebackground=ACCENT_SOFT,
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=(FONT_FAMILY, 10, "bold")
        )
        self.report_button.pack(side="left", padx=8, ipady=6)

        self.clear_button = tk.Button(
            button_frame,
            text="Clear Alerts",
            width=15,
            bg="#334155",
            fg=TEXT_PRIMARY,
            activebackground="#475569",
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=(FONT_FAMILY, 10, "bold")
        )
        self.clear_button.pack(side="left", padx=8, ipady=6)

        self.exit_button = tk.Button(
            button_frame,
            text="Exit",
            width=12,
            command=self.root.destroy,
            bg="#1E293B",
            fg=TEXT_MUTED,
            activebackground="#334155",
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=(FONT_FAMILY, 10, "bold")
        )
        self.exit_button.pack(side="right", ipady=6)

        # simple hover effects
        self._add_hover(self.start_button, GREEN, "#16A34A")
        self._add_hover(self.stop_button, RED, "#DC2626")
        self._add_hover(self.report_button, ACCENT, ACCENT_SOFT)
        self._add_hover(self.clear_button, "#334155", "#475569")
        self._add_hover(self.exit_button, "#1E293B", "#334155")

        # ---------------- Footer ----------------
        self.footer = tk.Label(
            self.root,
            text="Ready",
            anchor="w",
            bg=BG_HEADER,
            fg=TEXT_MUTED,
            font=(FONT_FAMILY, 9),
            padx=10,
            pady=4
        )
        self.footer.pack(fill="x", side="bottom")

    # ---------------- Styling helpers ----------------

    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Dark.Treeview",
            background=BG_CARD,
            fieldbackground=BG_CARD,
            foreground=TEXT_PRIMARY,
            rowheight=26,
            borderwidth=0,
            font=(FONT_FAMILY, 9)
        )
        style.configure(
            "Dark.Treeview.Heading",
            background="#0F172A",
            foreground=TEXT_MUTED,
            font=(FONT_FAMILY, 9, "bold"),
            relief="flat",
            borderwidth=0
        )
        style.map(
            "Dark.Treeview.Heading",
            background=[("active", "#1E293B")]
        )
        style.map(
            "Dark.Treeview",
            background=[("selected", ACCENT_SOFT)],
            foreground=[("selected", "white")]
        )

        # Compact variant used for the Threat Intelligence mini-tables
        style.configure(
            "Mini.Treeview",
            background=BG_CARD,
            fieldbackground=BG_CARD,
            foreground=TEXT_PRIMARY,
            rowheight=20,
            borderwidth=0,
            font=(FONT_FAMILY, 8)
        )
        style.configure(
            "Mini.Treeview.Heading",
            background="#0F172A",
            foreground=TEXT_MUTED,
            font=(FONT_FAMILY, 8, "bold"),
            relief="flat",
            borderwidth=0
        )
        style.map(
            "Mini.Treeview",
            background=[("selected", ACCENT_SOFT)],
            foreground=[("selected", "white")]
        )

    def _add_hover(self, button, normal_color, hover_color):
        button.bind("<Enter>", lambda e: button.config(bg=hover_color))
        button.bind("<Leave>", lambda e: button.config(bg=normal_color))

    def _build_intel_table(self, parent, title, columns, widths):
        """Builds a small labeled table (used for alert types / top IPs / top ports)."""

        wrap = tk.Frame(parent, bg=BG_CARD)
        wrap.pack(fill="x", padx=10, pady=(0, 6))

        tk.Label(
            wrap,
            text=title.upper(),
            font=(FONT_FAMILY, 8, "bold"),
            bg=BG_CARD,
            fg=ACCENT if "Alert" in title else TEXT_MUTED,
            anchor="w"
        ).pack(fill="x", pady=(3, 2))

        table = ttk.Treeview(
            wrap,
            columns=columns,
            show="headings",
            height=2,
            style="Mini.Treeview"
        )
        for col, width in zip(columns, widths):
            table.heading(col, text=col)
            table.column(col, width=width, anchor="w" if col == columns[0] else "center")
        table.pack(fill="x")

        table.tag_configure("empty", foreground=TEXT_MUTED)

        return table

    def show_info_dialog(self, title, message, kind="success"):
        """Themed replacement for tkinter.messagebox.showinfo/showerror.
        kind: 'success', 'error', or 'info' - controls icon/accent color.
        """
        icon_map = {
            "success": ("✔", GREEN),
            "error": ("✖", RED),
            "info": ("ℹ", ACCENT),
        }
        symbol, color = icon_map.get(kind, ("ℹ", ACCENT))

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg=BG_CARD)
        dialog.resizable(False, False)
        dialog.transient(self.root)

        width, height = 360, 170
        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (width // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (height // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

        top_bar = tk.Frame(dialog, bg=color, height=4)
        top_bar.pack(fill="x", side="top")

        tk.Label(
            dialog,
            text=symbol,
            font=(FONT_FAMILY, 26, "bold"),
            bg=BG_CARD,
            fg=color
        ).pack(pady=(16, 6))

        tk.Label(
            dialog,
            text=message,
            font=(FONT_FAMILY, 10),
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            wraplength=300,
            justify="center"
        ).pack(pady=(0, 14), padx=20)

        ok_button = tk.Button(
            dialog,
            text="OK",
            width=10,
            bg=ACCENT,
            fg="white",
            activebackground=ACCENT_SOFT,
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=(FONT_FAMILY, 10, "bold"),
            command=dialog.destroy
        )
        ok_button.pack(pady=(0, 16), ipady=4)
        self._add_hover(ok_button, ACCENT, ACCENT_SOFT)

        dialog.bind("<Return>", lambda e: dialog.destroy())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

        dialog.grab_set()
        ok_button.focus_set()
        dialog.wait_window()

    def create_card(self, parent, title, variable, column, accent_color):

        frame = tk.Frame(
            parent,
            bg=BG_CARD,
            highlightbackground="#334155",
            highlightthickness=1,
            width=170,
            height=72
        )
        frame.grid(row=0, column=column, padx=5, sticky="nsew")
        frame.grid_propagate(False)

        accent_bar = tk.Frame(frame, bg=accent_color, height=2)
        accent_bar.pack(fill="x", side="top")

        tk.Label(
            frame,
            text=title,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            font=(FONT_FAMILY, 9, "bold")
        ).pack(pady=(12, 2))

        tk.Label(
            frame,
            textvariable=variable,
            bg=BG_CARD,
            fg=TEXT_PRIMARY,
            font=(FONT_FAMILY, 18, "bold")
        ).pack()

    # ---------------- Functional methods (unchanged behavior) ----------------

    def add_packet(self, data):

        port = data.get("dst_port", "-")

        self.packet_table.insert(
            "",
            tk.END,
            values=(
                datetime.now().strftime("%H:%M:%S"),
                data["protocol"],
                data["src_ip"],
                data["dst_ip"],
                port
            )
        )

        # Keep only the latest 300 packets
        if len(self.packet_table.get_children()) > 300:
            first = self.packet_table.get_children()[0]
            self.packet_table.delete(first)

        self.packet_table.yview_moveto(1)

    def add_alert(self, alert):
        severity = alert["severity"]

        self.alert_table.insert(
            "",
            tk.END,
            values=(
                datetime.now().strftime("%H:%M:%S"),
                severity,
                alert["attack"],
                alert["source"]
            ),
            tags=(severity,)
        )
        self.alert_table.yview_moveto(1)

    def clear_packets(self):
        for row in self.packet_table.get_children():
            self.packet_table.delete(row)

    def clear_alerts(self):
        for row in self.alert_table.get_children():
            self.alert_table.delete(row)

    def update_runtime(self, seconds):
        hrs = seconds // 3600
        mins = (seconds % 3600) // 60
        secs = seconds % 60
        self.runtime.set(f"{hrs:02}:{mins:02}:{secs:02}")

    def set_status(self, running):
        if running:
            self.status.set("Running")
            self.status_label.config(fg=GREEN)
            self.status_dot.config(fg=GREEN)
        else:
            self.status.set("Stopped")
            self.status_label.config(fg=RED)
            self.status_dot.config(fg=RED)

    def update_statistics(self, stats):
        self.total_packets.set(stats["TOTAL"])
        self.tcp_packets.set(stats["TCP"])
        self.udp_packets.set(stats["UDP"])
        self.icmp_packets.set(stats["ICMP"])
        self.alerts.set(stats["ALERTS"])

    # ---------------- Threat Intelligence panel ----------------

    def _refresh_mini_table(self, table, items, top_n=5, label_fmt=None, empty_text="No data yet"):
        for row in table.get_children():
            table.delete(row)

        items = sorted(items, key=lambda pair: pair[1], reverse=True)[:top_n]

        if not items:
            table.insert("", tk.END, values=(empty_text, ""), tags=("empty",))
            return

        for key, count in items:
            label = label_fmt(key) if label_fmt else str(key)
            table.insert("", tk.END, values=(label, count))

    def update_alert_types(self, alert_stats):
        """attack_type -> count"""
        self._refresh_mini_table(
            self.alert_types_table,
            alert_stats.items(),
            empty_text="No alerts yet"
        )

    def update_top_sources(self, source_ip_stats):
        """Counter of source IPs"""
        self._refresh_mini_table(
            self.top_ips_table,
            source_ip_stats.items(),
            empty_text="No packets yet"
        )

    def update_top_ports(self, source_port_stats):
        """Counter of source ports"""
        self._refresh_mini_table(
            self.top_ports_table,
            source_port_stats.items(),
            label_fmt=lambda p: f"Port {p}",
            empty_text="No data yet"
        )

    def clear_intel(self):
        for table in (self.alert_types_table, self.top_ips_table, self.top_ports_table):
            for row in table.get_children():
                table.delete(row)


if __name__ == "__main__":

    root = tk.Tk()

    app = IDS_GUI(root)

    root.mainloop()
