import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
from datetime import datetime
from typing import Optional, Dict, List
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import Database
from core.scanners import DNSCacheScanner, CommonSitesScanner, CustomDomainScanner, ScanResult
from core.export_manager import ExportManager


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ModernCard(ctk.CTkFrame):
    """Reusable modern card component with hover effect"""
    
    def __init__(self, parent, title, value, icon="📊", color="#6366f1", **kwargs):
        super().__init__(parent, corner_radius=15, **kwargs)
        
        self.color = color
        self.configure(fg_color="gray20")
        
        # Icon and title section
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        
        icon_label = ctk.CTkLabel(
            header,
            text=icon,
            font=ctk.CTkFont(size=32)
        )
        icon_label.pack(side="left")
        
        title_label = ctk.CTkLabel(
            header,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="gray70"
        )
        title_label.pack(side="left", padx=10)
        
        # Value section
        self.value_label = ctk.CTkLabel(
            self,
            text=str(value),
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color=color
        )
        self.value_label.pack(pady=(10, 20))
        
        # Hover effect
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        for child in self.winfo_children():
            child.bind("<Enter>", self._on_enter)
            child.bind("<Leave>", self._on_leave)
    
    def _on_enter(self, event):
        self.configure(fg_color="gray25")
    
    def _on_leave(self, event):
        self.configure(fg_color="gray20")
    
    def update_value(self, new_value):
        self.value_label.configure(text=str(new_value))


class SearchBar(ctk.CTkFrame):
    """Modern search bar with icon"""
    
    def __init__(self, parent, placeholder="Search...", callback=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        
        self.callback = callback
        
        # Search icon
        icon = ctk.CTkLabel(
            self,
            text="🔍",
            font=ctk.CTkFont(size=18)
        )
        icon.pack(side="left", padx=(10, 5))
        
        # Entry field
        self.entry = ctk.CTkEntry(
            self,
            placeholder_text=placeholder,
            border_width=0,
            height=40,
            font=ctk.CTkFont(size=13)
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # Bind key release for live search
        if callback:
            self.entry.bind("<KeyRelease>", lambda e: callback(self.get()))
        
        # Configure frame background
        self.configure(
            fg_color="gray20",
            corner_radius=10,
            height=45
        )
    
    def get(self):
        return self.entry.get()
    
    def clear(self):
        self.entry.delete(0, 'end')


class ProgressCard(ctk.CTkFrame):
    """Animated progress card for scanning"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, corner_radius=15, **kwargs)
        
        # Title
        self.title = ctk.CTkLabel(
            self,
            text="Scanning in Progress",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.title.pack(pady=(30, 10))
        
        # Current domain
        self.domain_label = ctk.CTkLabel(
            self,
            text="Initializing...",
            font=ctk.CTkFont(size=13),
            text_color="gray60"
        )
        self.domain_label.pack(pady=5)
        
        # Progress bar
        self.progress = ctk.CTkProgressBar(
            self,
            mode="determinate",
            height=20,
            corner_radius=10
        )
        self.progress.pack(pady=20, padx=40, fill="x")
        self.progress.set(0)
        
        # Stats row
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(pady=10, fill="x", padx=40)
        
        self.count_label = ctk.CTkLabel(
            stats_frame,
            text="0 / 0",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.count_label.pack(side="left")
        
        # Metrics grid
        metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        metrics_frame.pack(pady=20, fill="x", padx=40)
        
        # Permitted count
        permitted_frame = ctk.CTkFrame(metrics_frame, fg_color="transparent")
        permitted_frame.pack(side="left", expand=True)
        
        ctk.CTkLabel(
            permitted_frame,
            text="✅ Permitted",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        ).pack()
        
        self.permitted_label = ctk.CTkLabel(
            permitted_frame,
            text="0",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#10b981"
        )
        self.permitted_label.pack()
        
        # Lowest latency
        latency_frame = ctk.CTkFrame(metrics_frame, fg_color="transparent")
        latency_frame.pack(side="left", expand=True)
        
        ctk.CTkLabel(
            latency_frame,
            text="⚡ Lowest Latency",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        ).pack()
        
        self.latency_label = ctk.CTkLabel(
            latency_frame,
            text="-- ms",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#06b6d4"
        )
        self.latency_label.pack()
    
    def update_progress(self, current, total, domain, permitted=0, lowest_latency=None, speed=0):
        """Update all progress indicators"""
        progress = current / total if total > 0 else 0
        self.progress.set(progress)
        self.domain_label.configure(text=f"Testing: {domain}")
        self.count_label.configure(text=f"{current} / {total}")
        self.permitted_label.configure(text=f"{permitted}")
        
        if lowest_latency is not None:
            self.latency_label.configure(text=f"{lowest_latency:.0f} ms")
        else:
            self.latency_label.configure(text="-- ms")


class SNIReconApp(ctk.CTk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Window configuration
        self.title("SNI Reconnaissance Tool")
        self.geometry("1000x650")
        self.minsize(900, 600)
        
        # Initialize managers
        self.db = Database()
        self.export_manager = ExportManager()
        
        # Settings file path
        self.settings_file = "settings.json"
        self.settings = self._load_settings()
        
        # Apply settings to scanners module
        self._apply_scanner_settings()
        
        # Application state
        self.current_scan_results: Optional[List[ScanResult]] = None
        self.current_scan_type: Optional[str] = None
        self.is_scanning = False
        self.scan_thread: Optional[threading.Thread] = None
        self.scan_start_time: Optional[datetime] = None
        self.filtered_results: Optional[List[ScanResult]] = None
        self.has_unsaved_changes = False
        
        # Statistics cache
        self.stats_cache = {
            'total_scans': 0,
            'lowest_latency': 0
        }
        
        # Configure grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        # Create UI
        self.create_sidebar()
        self.create_main_container()
        
        # Load initial stats
        self._update_stats_cache()
        
        # Show dashboard
        self.show_dashboard()
        
        # Bind keyboard shortcuts
        self.bind("<Control-n>", lambda e: self._check_unsaved_before_action(self.show_scan_selection))
        self.bind("<Control-h>", lambda e: self._check_unsaved_before_action(self.show_history))
        self.bind("<Control-s>", lambda e: self._quick_save())
        self.bind("<Escape>", lambda e: self._check_unsaved_before_action(self.show_dashboard))
    
    def create_sidebar(self):
        """Create modern sidebar navigation"""
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(7, weight=1)
        
        # Logo/Title
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=30)
        
        ctk.CTkLabel(
            logo_frame,
            text="🔍",
            font=ctk.CTkFont(size=36)
        ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="SNI Reconnaissance",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="Tool",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack()
        
        # Navigation buttons
        self.nav_buttons = {}
        nav_items = [
            ("📊", "Dashboard", self.show_dashboard, 1),
            ("🔍", "New Scan", self.show_scan_selection, 2),
            ("📝", "History", self.show_history, 3),
            ("⚙️", "Settings", self.show_settings, 4),
        ]
        
        for icon, text, command, row in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=f"{icon}  {text}",
                command=lambda cmd=command: self._check_unsaved_before_action(cmd),
                anchor="w",
                fg_color="transparent",
                hover_color="gray25",
                height=45,
                font=ctk.CTkFont(size=13)
            )
            btn.grid(row=row, column=0, padx=10, pady=5, sticky="ew")
            self.nav_buttons[text] = btn
        
        # Help button
        help_btn = ctk.CTkButton(
            self.sidebar,
            text="❓  Help",
            command=self.show_help,
            anchor="w",
            fg_color="transparent",
            hover_color="gray25",
            height=40,
            font=ctk.CTkFont(size=12)
        )
        help_btn.grid(row=8, column=0, padx=10, pady=10, sticky="ew")
    
    def create_main_container(self):
        """Create main content container"""
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
    
    def clear_main(self):
        """Clear main container"""
        for widget in self.main_container.winfo_children():
            widget.destroy()
    
    def _check_unsaved_before_action(self, action):
        """Check for unsaved changes before performing action"""
        if self.has_unsaved_changes and self.current_scan_results:
            dialog = SaveDiscardDialog(self, self._save_scan_dialog, lambda: self._discard_and_continue(action))
        else:
            action()
    
    def _discard_and_continue(self, action):
        """Discard changes and continue with action"""
        self.has_unsaved_changes = False
        self.current_scan_results = None
        action()
    
    def _update_stats_cache(self):
        """Update statistics cache from database"""
        scans = self.db.get_all_scans()
        self.stats_cache['total_scans'] = len(scans)
        
        # Reset lowest latency
        self.stats_cache['lowest_latency'] = 0
        
        # Calculate lowest latency from recent scans
        if scans:
            recent_scan = scans[0]  # Most recent
            results = self.db.load_scan_results(recent_scan['id'])
            if results:
                latencies = [r.latency for r in results if r.latency]
                if latencies:
                    self.stats_cache['lowest_latency'] = min(latencies)
    
    def _load_settings(self) -> dict:
        """Load settings from file or return defaults"""
        default_settings = {
            'timeout': 3.0,
            'max_workers': 20
        }
        
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults to handle new settings
                    default_settings.update(loaded)
                    return default_settings
        except Exception as e:
            print(f"Error loading settings: {e}")
        
        return default_settings
    
    def _save_settings(self):
        """Save settings to file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def _apply_scanner_settings(self):
        """Apply settings to scanner module"""
        try:
            from core import scanners
            # Directly modify the module-level constants
            scanners.TIMEOUT = self.settings['timeout']
            scanners.MAX_WORKERS = self.settings['max_workers']
            print(f"Settings applied: TIMEOUT={scanners.TIMEOUT}, MAX_WORKERS={scanners.MAX_WORKERS}")
        except Exception as e:
            print(f"Error applying settings: {e}")
    
    def show_dashboard(self):
        """Display modern dashboard"""
        self.clear_main()
        self._update_stats_cache()
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            header,
            text="Dashboard",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(side="left")
        
        # Quick action button
        quick_scan_btn = ctk.CTkButton(
            header,
            text="➕  New Scan",
            command=self.show_scan_selection,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#6366f1",
            hover_color="#4f46e5"
        )
        quick_scan_btn.pack(side="right")
        
        # Stats cards
        cards_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        cards_frame.pack(fill="x", pady=10)
        
        # Create stat cards
        self.total_scans_card = ModernCard(
            cards_frame,
            title="Total Scans",
            value=self.stats_cache['total_scans'],
            icon="📊",
            color="#6366f1"
        )
        self.total_scans_card.pack(side="left", fill="both", expand=True, padx=5)
        
        self.lowest_latency_card = ModernCard(
            cards_frame,
            title="Lowest Latency",
            value=f"{self.stats_cache['lowest_latency']:.0f}ms" if self.stats_cache['lowest_latency'] > 0 else "--",
            icon="⚡",
            color="#06b6d4"
        )
        self.lowest_latency_card.pack(side="left", fill="both", expand=True, padx=5)
        
        # Recent scans section
        recent_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        recent_frame.pack(fill="both", expand=True, pady=(20, 0))
        
        # Section header
        section_header = ctk.CTkFrame(recent_frame, fg_color="transparent")
        section_header.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(
            section_header,
            text="Recent Scans",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(side="left")
        
        # View all button
        view_all_btn = ctk.CTkButton(
            section_header,
            text="View All →",
            command=self.show_history,
            fg_color="transparent",
            hover_color="gray25",
            width=100,
            height=32,
            font=ctk.CTkFont(size=12)
        )
        view_all_btn.pack(side="right")
        
        # Recent scans list
        scans_scroll = ctk.CTkScrollableFrame(
            recent_frame,
            fg_color="transparent"
        )
        scans_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Load recent scans
        scans = self.db.get_all_scans()[:5]  # Last 5 scans
        
        if not scans:
            no_scans = ctk.CTkLabel(
                scans_scroll,
                text="No scans yet. Create your first scan!",
                font=ctk.CTkFont(size=14),
                text_color="gray60"
            )
            no_scans.pack(pady=40)
        else:
            for scan in scans:
                self._create_scan_card(scans_scroll, scan)
    
    def _create_scan_card(self, parent, scan):
        """Create a scan card for dashboard/history"""
        card = ctk.CTkFrame(parent, fg_color="gray17", corner_radius=10)
        card.pack(fill="x", pady=5)
        
        # Load scan results to get stats
        results = self.db.load_scan_results(scan['id'])
        permitted = sum(1 for r in results if r.status == "Valid SNI") if results else 0
        total = len(results) if results else 0
        
        # Content
        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(side="left", fill="x", expand=True, padx=20, pady=15)
        
        # Name
        name_label = ctk.CTkLabel(
            content,
            text=scan['name'],
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w"
        )
        name_label.pack(anchor="w")
        
        # Details
        scan_type_display = scan['scan_type'].replace('_', ' ').title()
        details = f"{scan_type_display} • {scan['timestamp']} • {permitted}/{total} accessible"
        details_label = ctk.CTkLabel(
            content,
            text=details,
            font=ctk.CTkFont(size=11),
            text_color="gray60",
            anchor="w"
        )
        details_label.pack(anchor="w")
        
        # Actions
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=10)
        
        open_btn = ctk.CTkButton(
            btn_frame,
            text="Open",
            command=lambda: self._load_scan(scan['id']),
            width=70,
            height=32,
            font=ctk.CTkFont(size=12)
        )
        open_btn.pack(side="left", padx=3)
        
        delete_btn = ctk.CTkButton(
            btn_frame,
            text="🗑",
            command=lambda: self._delete_scan_with_confirm(scan['id']),
            width=35,
            height=32,
            fg_color="transparent",
            hover_color="gray25",
            font=ctk.CTkFont(size=12)
        )
        delete_btn.pack(side="left", padx=3)

    def show_scan_selection(self):
        """Display scan type selection screen"""
        self.clear_main()
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            header,
            text="New Scan",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(side="left")
        
        # Scan type selection
        scan_types = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")
        scan_types.pack(fill="both", expand=True, pady=20)
        
        # DNS Cache Scan
        dns_card = ctk.CTkFrame(scan_types, corner_radius=15)
        dns_card.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            dns_card,
            text="🔍 DNS Cache Analysis",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", padx=25, pady=(25, 5))
        
        ctk.CTkLabel(
            dns_card,
            text="Extract and scan domains from your system's DNS cache (Windows only)",
            font=ctk.CTkFont(size=13),
            text_color="gray60",
            wraplength=700,
            justify="left"
        ).pack(anchor="w", padx=25, pady=(0, 15))
        
        dns_btn = ctk.CTkButton(
            dns_card,
            text="Start DNS Cache Scan",
            command=lambda: self.start_scan("dns_cache"),
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#6366f1",
            hover_color="#4f46e5"
        )
        dns_btn.pack(anchor="w", padx=25, pady=(0, 25))
        
        # Common Sites Scan
        sites_card = ctk.CTkFrame(scan_types, corner_radius=15)
        sites_card.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            sites_card,
            text="🌐 Common Sites Scan",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", padx=25, pady=(25, 5))
        
        ctk.CTkLabel(
            sites_card,
            text="Test connectivity to popular websites and services from a predefined list",
            font=ctk.CTkFont(size=13),
            text_color="gray60",
            wraplength=700,
            justify="left"
        ).pack(anchor="w", padx=25, pady=(0, 15))
        
        sites_btn = ctk.CTkButton(
            sites_card,
            text="Start Common Sites Scan",
            command=lambda: self.start_scan("common_sites"),
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669"
        )
        sites_btn.pack(anchor="w", padx=25, pady=(0, 25))
        
        # Custom Domain Scan
        custom_card = ctk.CTkFrame(scan_types, corner_radius=15)
        custom_card.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            custom_card,
            text="📝 Custom Domain Scan",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", padx=25, pady=(25, 5))
        
        ctk.CTkLabel(
            custom_card,
            text="Scan your own list of domains - enter manually, paste, or import from file",
            font=ctk.CTkFont(size=13),
            text_color="gray60",
            wraplength=700,
            justify="left"
        ).pack(anchor="w", padx=25, pady=(0, 15))
        
        custom_btn = ctk.CTkButton(
            custom_card,
            text="Create Custom Scan",
            command=self.show_custom_domain_input,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#06b6d4",
            hover_color="#0891b2"
        )
        custom_btn.pack(anchor="w", padx=25, pady=(0, 25))
    
    def show_custom_domain_input(self):
        """Show custom domain input screen"""
        self.clear_main()
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        back_btn = ctk.CTkButton(
            header,
            text="← Back",
            command=self.show_scan_selection,
            width=80,
            fg_color="transparent",
            hover_color="gray25",
            font=ctk.CTkFont(size=13)
        )
        back_btn.pack(side="left")
        
        ctk.CTkLabel(
            header,
            text="Custom Domain Scan",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(side="left", padx=20)
        
        # Input area
        input_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        input_frame.pack(fill="both", expand=True, pady=10)
        
        # Instructions
        instructions = ctk.CTkLabel(
            input_frame,
            text="Enter domains (one per line):",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        instructions.pack(anchor="w", padx=25, pady=(25, 10))
        
        # Text input
        self.custom_domain_text = ctk.CTkTextbox(
            input_frame,
            font=ctk.CTkFont(size=13),
            wrap="word"
        )
        self.custom_domain_text.pack(fill="both", expand=True, padx=25, pady=10)
        self.custom_domain_text.insert("1.0", "google.com\nfacebook.com\nyoutube.com")
        
        # Action buttons
        button_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=25, pady=(10, 25))
        
        import_btn = ctk.CTkButton(
            button_frame,
            text="📁  Import File",
            command=self._import_domains_from_file,
            width=120,
            height=40,
            fg_color="transparent",
            border_width=2,
            border_color="gray40"
        )
        import_btn.pack(side="left", padx=5)
        
        clear_btn = ctk.CTkButton(
            button_frame,
            text="🗑  Clear",
            command=lambda: self.custom_domain_text.delete("1.0", "end"),
            width=100,
            height=40,
            fg_color="transparent",
            border_width=2,
            border_color="gray40"
        )
        clear_btn.pack(side="left", padx=5)
        
        # Domain count
        self.domain_count_label = ctk.CTkLabel(
            button_frame,
            text="3 domains",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        )
        self.domain_count_label.pack(side="left", padx=15)
        
        # Update count on key release
        self.custom_domain_text.bind("<KeyRelease>", self._update_domain_count)
        
        # Start scan button
        start_btn = ctk.CTkButton(
            button_frame,
            text="Start Scan",
            command=lambda: self.start_scan("custom"),
            width=140,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#06b6d4",
            hover_color="#0891b2"
        )
        start_btn.pack(side="right", padx=5)
    
    def _import_domains_from_file(self):
        """Import domains from a file"""
        filename = filedialog.askopenfilename(
            title="Import Domains",
            filetypes=[
                ("Text Files", "*.txt"),
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Clear current content and insert
                self.custom_domain_text.delete("1.0", "end")
                self.custom_domain_text.insert("1.0", content)
                self._update_domain_count()
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import file:\n{str(e)}")
    
    def _update_domain_count(self, event=None):
        """Update domain count label"""
        content = self.custom_domain_text.get("1.0", "end").strip()
        domains = [line.strip() for line in content.split('\n') if line.strip()]
        count = len(domains)
        self.domain_count_label.configure(text=f"{count} domain{'s' if count != 1 else ''}")
    
    def start_scan(self, scan_type: str):
        """Initialize and start scanning process"""
        # Get domains for custom scan
        if scan_type == "custom":
            content = self.custom_domain_text.get("1.0", "end").strip()
            domains = [line.strip() for line in content.split('\n') if line.strip()]
            
            if not domains:
                messagebox.showwarning("No Domains", "Please enter at least one domain to scan.")
                return
            
            # Store domains for the scanner
            self.custom_domains = domains
        
        self.current_scan_type = scan_type
        self.current_scan_results = []
        self.is_scanning = True
        self.scan_start_time = datetime.now()
        self.has_unsaved_changes = True
        
        # Show scanning screen
        self.show_scanning_screen()
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_type,),
            daemon=True
        )
        self.scan_thread.start()
    
    def show_scanning_screen(self):
        """Display scanning progress screen"""
        self.clear_main()
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            header,
            text="Scanning",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(side="left")
        
        # Progress card
        self.progress_card = ProgressCard(self.main_container)
        self.progress_card.pack(fill="both", expand=True, pady=20)
    
    def _run_scan(self, scan_type: str):
        """Execute scan in background thread"""
        try:
            # IMPORTANT: Re-apply settings before each scan to ensure they're used
            self._apply_scanner_settings()
            
            # Verify settings are applied
            from core import scanners
            print(f"Starting scan with TIMEOUT={scanners.TIMEOUT}, MAX_WORKERS={scanners.MAX_WORKERS}")
            
            if scan_type == "dns_cache":
                scanner = DNSCacheScanner()
            elif scan_type == "common_sites":
                scanner = CommonSitesScanner()
            else:  # custom
                scanner = CustomDomainScanner(self.custom_domains)
            
            # Verify scanner instance has correct settings
            print(f"Scanner instance: timeout={scanner.timeout}, max_workers={scanner.max_workers}")
            
            # Statistics tracking
            self.scan_stats = {
                'permitted': 0,
                'lowest_latency': None
            }
            
            # Run scan with callback for progress updates
            results = scanner.scan(progress_callback=self._scan_progress_callback)
            
            # Update results
            self.current_scan_results = results
            self.is_scanning = False
            
            # Update UI on main thread
            self.after(0, self._scan_complete)
            
        except Exception as e:
            self.is_scanning = False
            self.after(0, lambda: self._scan_error(str(e)))
    
    def _scan_progress_callback(self, current: int, total: int, domain: str, result: ScanResult = None):
        """Callback for scan progress updates"""
        # Update statistics
        if result:
            if result.status == "Valid SNI":
                self.scan_stats['permitted'] += 1
                if result.latency:
                    if self.scan_stats['lowest_latency'] is None or result.latency < self.scan_stats['lowest_latency']:
                        self.scan_stats['lowest_latency'] = result.latency
        
        # Calculate speed
        if self.scan_start_time and current > 0:
            elapsed = (datetime.now() - self.scan_start_time).total_seconds()
            speed = current / elapsed if elapsed > 0 else 0
        else:
            speed = 0
        
        self.after(0, lambda: self._update_scan_progress(
            current, total, domain, 
            self.scan_stats['permitted'], 
            self.scan_stats['lowest_latency'], 
            speed
        ))
    
    def _update_scan_progress(self, current: int, total: int, domain: str, permitted: int, lowest_latency: float, speed: float):
        """Update scanning UI with progress"""
        if hasattr(self, 'progress_card'):
            self.progress_card.update_progress(current, total, domain, permitted, lowest_latency, speed)
    
    def _scan_complete(self):
        """Handle scan completion"""
        self.show_results_screen()
    
    def _scan_error(self, error_msg: str):
        """Handle scan error"""
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
        self.show_scan_selection()
    
    def show_results_screen(self, saved_results: List[ScanResult] = None, scan_info: Dict = None):
        """Display scan results """
        self.clear_main()
        
        # Use saved results if provided, otherwise use current scan results
        results = saved_results if saved_results else self.current_scan_results
        self.filtered_results = results
        is_saved_scan = saved_results is not None
        
        if not results:
            messagebox.showerror("Error", "No results to display")
            self.show_dashboard()
            return
        
        # Calculate statistics
        total = len(results)
        permitted = sum(1 for r in results if r.status == "Valid SNI")
        restricted = total - permitted
        
        latencies = [r.latency for r in results if r.latency]
        lowest_latency = min(latencies) if latencies else 0
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        back_btn = ctk.CTkButton(
            header,
            text="← Back",
            command=lambda: self.show_dashboard() if is_saved_scan else self._check_unsaved_before_action(self.show_dashboard),
            width=80,
            fg_color="transparent",
            hover_color="gray25",
            font=ctk.CTkFont(size=13)
        )
        back_btn.pack(side="left")
        
        title_text = scan_info['name'] if scan_info else "Scan Results"
        ctk.CTkLabel(
            header,
            text=title_text,
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(side="left", padx=20)
        
        # Action buttons
        if not is_saved_scan:
            save_btn = ctk.CTkButton(
                header,
                text="💾  Save",
                command=self._save_scan_dialog,
                width=100,
                height=38,
                font=ctk.CTkFont(size=13),
                fg_color="#10b981",
                hover_color="#059669"
            )
            save_btn.pack(side="right", padx=5)
        
        export_btn = ctk.CTkButton(
            header,
            text="📤  Export",
            command=self._show_export_dialog,
            width=100,
            height=38,
            font=ctk.CTkFont(size=13)
        )
        export_btn.pack(side="right", padx=5)
        
        # Stats summary
        stats_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        stats_frame.pack(fill="x", pady=10)
        
        # Summary cards
        summary_card1 = ctk.CTkFrame(stats_frame, corner_radius=10, fg_color="gray20")
        summary_card1.pack(side="left", fill="x", expand=True, padx=5)
        
        ctk.CTkLabel(
            summary_card1,
            text=f"{permitted}",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#10b981"
        ).pack(pady=(15, 5))
        
        ctk.CTkLabel(
            summary_card1,
            text="Valid SNI",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        ).pack(pady=(0, 15))
        
        summary_card2 = ctk.CTkFrame(stats_frame, corner_radius=10, fg_color="gray20")
        summary_card2.pack(side="left", fill="x", expand=True, padx=5)
        
        ctk.CTkLabel(
            summary_card2,
            text=f"{restricted}",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#ef4444"
        ).pack(pady=(15, 5))
        
        ctk.CTkLabel(
            summary_card2,
            text="🚫 Blocked",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        ).pack(pady=(0, 15))
        
        summary_card3 = ctk.CTkFrame(stats_frame, corner_radius=10, fg_color="gray20")
        summary_card3.pack(side="left", fill="x", expand=True, padx=5)
        
        ctk.CTkLabel(
            summary_card3,
            text=f"{lowest_latency:.0f}ms" if lowest_latency > 0 else "--",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="#06b6d4"
        ).pack(pady=(15, 5))
        
        ctk.CTkLabel(
            summary_card3,
            text="Lowest Latency",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        ).pack(pady=(0, 15))
        
        # Results section
        results_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        results_frame.pack(fill="both", expand=True, pady=(20, 0))
        
        # Toolbar
        toolbar = ctk.CTkFrame(results_frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(
            toolbar,
            text="Detailed Results",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")
        
        # Search and filter
        filter_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        filter_frame.pack(side="right")
        
        # Status filter
        self.status_filter = ctk.CTkOptionMenu(
            filter_frame,
            values=["All", "Valid SNI", "Blocked"],
            command=self._filter_results,
            width=120,
            height=32,
            font=ctk.CTkFont(size=12)
        )
        self.status_filter.pack(side="right", padx=5)
        self.status_filter.set("All")
        
        # Search bar
        self.results_search = SearchBar(
            filter_frame,
            placeholder="Search domains...",
            callback=self._filter_results,
            width=200
        )
        self.results_search.pack(side="right", padx=5)
        
        # Results list (scrollable)
        self.results_scroll = ctk.CTkScrollableFrame(
            results_frame,
            fg_color="transparent"
        )
        self.results_scroll.pack(fill="both", expand=True, padx=20, pady=(10, 20))
        
        # Display results
        self._display_grouped_results()
    
    def _filter_results(self, *args):
        """Filter results based on search and status"""
        if not self.current_scan_results and not self.filtered_results:
            return
        
        results = self.current_scan_results if self.current_scan_results else self.filtered_results
        search_term = self.results_search.get().lower() if hasattr(self, 'results_search') else ""
        status_filter = self.status_filter.get() if hasattr(self, 'status_filter') else "All"
        
        # Apply filters
        filtered = results
        
        if status_filter != "All":
            filtered = [r for r in filtered if r.status == status_filter]
        
        if search_term:
            filtered = [r for r in filtered if search_term in r.domain.lower()]
        
        self.filtered_results = filtered
        self._display_grouped_results()
    
    def _display_grouped_results(self):
        """Display all results as a simple list"""
        # Clear existing results
        for widget in self.results_scroll.winfo_children():
            widget.destroy()
        
        if not self.filtered_results:
            no_results = ctk.CTkLabel(
                self.results_scroll,
                text="No results match your filters",
                font=ctk.CTkFont(size=14),
                text_color="gray60"
            )
            no_results.pack(pady=40)
            return
        
        # Display all results as simple list
        for result in self.filtered_results:
            self._create_single_result_row(self.results_scroll, result)
    
    def _create_single_result_row(self, parent, result):
        """Create a single result row"""
        row = ctk.CTkFrame(parent, fg_color="gray17", corner_radius=8)
        row.pack(fill="x", pady=3)
        
        main_row = ctk.CTkFrame(row, fg_color="transparent")
        main_row.pack(fill="x", padx=15, pady=10)
        
        # Status indicator
        status_color = "#10b981" if result.status == "Valid SNI" else "#ef4444"
        status_indicator = ctk.CTkLabel(
            main_row,
            text="●",
            font=ctk.CTkFont(size=20),
            text_color=status_color,
            width=30
        )
        status_indicator.pack(side="left")
        
        # Domain name
        domain_label = ctk.CTkLabel(
            main_row,
            text=result.domain,
            font=ctk.CTkFont(size=13),
            anchor="w"
        )
        domain_label.pack(side="left", fill="x", expand=True, padx=10)
        
        # Latency badge
        if result.latency:
            latency_text = f"{result.latency:.0f}ms"
            if result.latency < 100:
                badge_color = "#10b981"
            elif result.latency < 300:
                badge_color = "#f59e0b"
            else:
                badge_color = "#ef4444"
            
            latency_badge = ctk.CTkLabel(
                main_row,
                text=latency_text,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="white",
                fg_color=badge_color,
                corner_radius=5,
                width=60,
                height=24
            )
            latency_badge.pack(side="right", padx=5)
        
        # Status label
        status_label = ctk.CTkLabel(
            main_row,
            text=result.status,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=status_color,
            width=100
        )
        status_label.pack(side="right", padx=5)
        
        # Copy button
        copy_btn = ctk.CTkButton(
            main_row,
            text="📋",
            width=35,
            height=25,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            hover_color="gray25",
            command=lambda: self._copy_domain(result.domain)
        )
        copy_btn.pack(side="right", padx=2)
        
        # Hover effect
        row.bind("<Enter>", lambda e: row.configure(fg_color="gray20"))
        row.bind("<Leave>", lambda e: row.configure(fg_color="gray17"))
    
    def _copy_domain(self, domain):
        """Copy domain to clipboard"""
        self.clipboard_clear()
        self.clipboard_append(domain)
    
    def _save_scan_dialog(self):
        """Show dialog to save scan"""
        if not self.current_scan_results:
            messagebox.showwarning("No Results", "No scan results to save.")
            return
        
        dialog = ctk.CTkInputDialog(
            text="Enter a name for this scan:",
            title="Save Scan"
        )
        scan_name = dialog.get_input()
        
        if scan_name:
            try:
                scan_id = self.db.save_scan(
                    scan_name,
                    self.current_scan_type,
                    self.current_scan_results
                )
                self.has_unsaved_changes = False
                messagebox.showinfo("Success", f"Scan '{scan_name}' saved successfully!")
                self._update_stats_cache()
                self.show_dashboard()
            except ValueError as e:
                messagebox.showerror("Error", str(e))
    
    def _quick_save(self):
        """Quick save with keyboard shortcut"""
        if self.current_scan_results and self.has_unsaved_changes:
            self._save_scan_dialog()
    
    def _show_export_dialog(self):
        """Show export options dialog"""
        if not self.current_scan_results and not self.filtered_results:
            messagebox.showwarning("No Results", "No results to export.")
            return
        
        results = self.filtered_results if self.filtered_results else self.current_scan_results
        
        # Create export dialog
        export_dialog = ctk.CTkToplevel(self)
        export_dialog.title("Export Results")
        export_dialog.geometry("400x300")
        export_dialog.resizable(False, False)
        
        # Center dialog
        export_dialog.transient(self)
        export_dialog.grab_set()
        
        # Content
        ctk.CTkLabel(
            export_dialog,
            text="Export Results",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)
        
        # Format selection
        format_frame = ctk.CTkFrame(export_dialog, fg_color="transparent")
        format_frame.pack(pady=10, padx=40, fill="x")
        
        ctk.CTkLabel(
            format_frame,
            text="Select format:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=5)
        
        format_var = ctk.StringVar(value="csv")
        
        ctk.CTkRadioButton(
            format_frame,
            text="CSV (Excel Compatible)",
            variable=format_var,
            value="csv"
        ).pack(anchor="w", pady=3)
        
        ctk.CTkRadioButton(
            format_frame,
            text="JSON (API Integration)",
            variable=format_var,
            value="json"
        ).pack(anchor="w", pady=3)
        
        ctk.CTkRadioButton(
            format_frame,
            text="TXT (Plain Text)",
            variable=format_var,
            value="txt"
        ).pack(anchor="w", pady=3)
        
        # Export button
        def do_export():
            format_type = format_var.get()
            self._export_results(results, format_type)
            export_dialog.destroy()
        
        export_btn = ctk.CTkButton(
            export_dialog,
            text="Export",
            command=do_export,
            width=200,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        export_btn.pack(pady=20)
    
    def _export_results(self, results: List[ScanResult], format_type: str):
        """Export results to file"""
        # Get save location
        extensions = {
            'csv': '.csv',
            'json': '.json',
            'txt': '.txt'
        }
        
        filename = filedialog.asksaveasfilename(
            defaultextension=extensions[format_type],
            filetypes=[
                (f"{format_type.upper()} Files", f"*{extensions[format_type]}"),
                ("All Files", "*.*")
            ]
        )
        
        if not filename:
            return
        
        try:
            if format_type == 'csv':
                self.export_manager.export_to_csv(results, filename)
            elif format_type == 'json':
                self.export_manager.export_to_json(results, filename)
            else:  # txt
                self.export_manager.export_to_txt(results, filename)
            
            messagebox.showinfo("Success", f"Results exported successfully to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def show_history(self):
        """Display scan history"""
        self.clear_main()
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            header,
            text="Scan History",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(side="left")
        
        # Clear all button
        clear_all_btn = ctk.CTkButton(
            header,
            text="🗑  Clear All",
            command=self._clear_all_scans,
            width=120,
            height=38,
            fg_color="#ef4444",
            hover_color="#dc2626",
            font=ctk.CTkFont(size=13)
        )
        clear_all_btn.pack(side="right")
        
        # Scans list
        scans_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        scans_frame.pack(fill="both", expand=True, pady=10)
        
        # Search bar
        search_toolbar = ctk.CTkFrame(scans_frame, fg_color="transparent")
        search_toolbar.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(
            search_toolbar,
            text="All Scans",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")
        
        history_search = SearchBar(
            search_toolbar,
            placeholder="Search scans...",
            width=250
        )
        history_search.pack(side="right")
        
        scans_scroll = ctk.CTkScrollableFrame(
            scans_frame,
            fg_color="transparent"
        )
        scans_scroll.pack(fill="both", expand=True, padx=20, pady=(10, 20))
        
        scans = self.db.get_all_scans()
        
        if not scans:
            no_scans = ctk.CTkLabel(
                scans_scroll,
                text="No saved scans yet",
                font=ctk.CTkFont(size=14),
                text_color="gray60"
            )
            no_scans.pack(pady=40)
        else:
            for scan in scans:
                self._create_scan_card(scans_scroll, scan)
    
    def _load_scan(self, scan_id: int):
        """Load and display a saved scan"""
        # Check for unsaved changes first
        if self.has_unsaved_changes and self.current_scan_results:
            def load_after_check():
                self.has_unsaved_changes = False
                self.current_scan_results = None
                self._do_load_scan(scan_id)
            
            dialog = SaveDiscardDialog(self, self._save_scan_dialog, load_after_check)
        else:
            self._do_load_scan(scan_id)
    
    def _do_load_scan(self, scan_id: int):
        """Actually load the scan after checking for unsaved changes"""
        results = self.db.load_scan_results(scan_id)
        scan_info = self.db.get_scan_info(scan_id)
        
        if results and scan_info:
            self.has_unsaved_changes = False
            self.show_results_screen(saved_results=results, scan_info=scan_info)
        else:
            messagebox.showerror("Error", "Failed to load scan results")
    
    def _delete_scan_with_confirm(self, scan_id: int):
        """Delete a scan with confirmation"""
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this scan?"):
            self.db.delete_scan(scan_id)
            self._update_stats_cache()
            # Refresh current view
            if hasattr(self, 'main_container'):
                self.show_history()
    
    def _clear_all_scans(self):
        """Clear all scan history"""
        scans = self.db.get_all_scans()
        if not scans:
            messagebox.showinfo("No Scans", "No scans to clear.")
            return
        
        if messagebox.askyesno(
            "Confirm Clear All",
            f"Are you sure you want to delete all {len(scans)} scans?\nThis action cannot be undone."
        ):
            for scan in scans:
                self.db.delete_scan(scan['id'])
            self._update_stats_cache()
            self.show_history()
    
    def show_settings(self):
        """Show settings screen"""
        self.clear_main()
        
        # Header
        header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            header,
            text="Settings",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(side="left")
        
        # Settings content
        settings_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        settings_frame.pack(fill="both", expand=True, pady=10)
        
        settings_scroll = ctk.CTkScrollableFrame(settings_frame, fg_color="transparent")
        settings_scroll.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Scan Settings
        ctk.CTkLabel(
            settings_scroll,
            text="Scan Settings",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(10, 15))
        
        # Timeout setting
        timeout_frame = ctk.CTkFrame(settings_scroll, fg_color="transparent")
        timeout_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            timeout_frame,
            text="Connection Timeout (seconds):",
            font=ctk.CTkFont(size=14)
        ).pack(side="left")
        
        timeout_slider = ctk.CTkSlider(
            timeout_frame,
            from_=0.3,
            to=10.0,
            number_of_steps=97,
            width=200
        )
        timeout_slider.pack(side="right", padx=10)
        timeout_slider.set(self.settings['timeout'])  # Load saved value
        
        timeout_value = ctk.CTkLabel(
            timeout_frame,
            text=f"{self.settings['timeout']:.1f}s",  # Show saved value
            font=ctk.CTkFont(size=13),
            text_color="gray60",
            width=50
        )
        timeout_value.pack(side="right")
        
        def update_timeout(value):
            timeout_value.configure(text=f"{value:.1f}s")
        
        timeout_slider.configure(command=update_timeout)
        
        # Explanation for timeout
        ctk.CTkLabel(
            settings_scroll,
            text="How long to wait for each domain response (0.3s - 10s)",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        ).pack(anchor="w", padx=20, pady=(0, 10))
        
        # Max workers
        workers_frame = ctk.CTkFrame(settings_scroll, fg_color="transparent")
        workers_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            workers_frame,
            text="Concurrent Threads:",
            font=ctk.CTkFont(size=14)
        ).pack(side="left")
        
        workers_slider = ctk.CTkSlider(
            workers_frame,
            from_=5,
            to=50,
            number_of_steps=45,
            width=200
        )
        workers_slider.pack(side="right", padx=10)
        workers_slider.set(self.settings['max_workers'])  # Load saved value
        
        workers_value = ctk.CTkLabel(
            workers_frame,
            text=str(self.settings['max_workers']),  # Show saved value
            font=ctk.CTkFont(size=13),
            text_color="gray60",
            width=50
        )
        workers_value.pack(side="right")
        
        def update_workers(value):
            workers_value.configure(text=f"{int(value)}")
        
        workers_slider.configure(command=update_workers)
        
        # Explanation for threads
        ctk.CTkLabel(
            settings_scroll,
            text="How many domains to scan simultaneously (5-50)",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        ).pack(anchor="w", padx=20, pady=(0, 20))
        
        # Save button
        save_frame = ctk.CTkFrame(settings_scroll, fg_color="transparent")
        save_frame.pack(fill="x", pady=20)
        
        def save_settings_clicked():
            # Get current slider values
            new_timeout = timeout_slider.get()
            new_workers = int(workers_slider.get())
            
            # Update settings
            self.settings['timeout'] = new_timeout
            self.settings['max_workers'] = new_workers
            
            # Save to file
            self._save_settings()
            
            # Apply to scanners
            self._apply_scanner_settings()
            
            # Show success message
            messagebox.showinfo(
                "Settings Saved", 
                f"Settings saved successfully!\n\n"
                f"Timeout: {new_timeout:.1f}s\n"
                f"Threads: {new_workers}\n\n"
                f"✅ Settings applied immediately!"
            )
        
        save_button = ctk.CTkButton(
            save_frame,
            text="💾 Save Settings",
            command=save_settings_clicked,
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669"
        )
        save_button.pack(pady=10)
        
        # Reset to defaults button
        def reset_to_defaults():
            if messagebox.askyesno("Reset Settings", "Reset all settings to default values?"):
                self.settings = {
                    'timeout': 3.0,
                    'max_workers': 20
                }
                self._save_settings()
                self._apply_scanner_settings()
                # Reload settings screen to show new values
                self.show_settings()
        
        reset_button = ctk.CTkButton(
            save_frame,
            text="🔄 Reset to Defaults",
            command=reset_to_defaults,
            height=35,
            font=ctk.CTkFont(size=14),
            fg_color="gray30",
            hover_color="gray40"
        )
        reset_button.pack(pady=5)
        
        # Current settings info
        info_frame = ctk.CTkFrame(settings_scroll, corner_radius=10, fg_color="gray20")
        info_frame.pack(fill="x", pady=20)
        
        ctk.CTkLabel(
            info_frame,
            text="ℹ️ Current Active Settings",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 10))
        
        ctk.CTkLabel(
            info_frame,
            text=f"Timeout: {self.settings['timeout']:.1f}s | Threads: {self.settings['max_workers']}",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        ).pack(pady=(0, 15))
        
        # About Section
        ctk.CTkLabel(
            settings_scroll,
            text="About",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(30, 15))
        
        about_text = """SNI Reconnaissance Tool

A TLS-based network reachability analyzer for restricted environments.

Features:
• DNS Cache scanning
• Common sites testing
• Custom domain scanning
• Export to multiple formats
• Scan history management
• Modern dark mode UI
• Persistent settings

Version: 2.0"""
        
        ctk.CTkLabel(
            settings_scroll,
            text=about_text,
            font=ctk.CTkFont(size=12),
            text_color="gray60",
            justify="left"
        ).pack(anchor="w", pady=10)
    
    def show_help(self):
        """Show help dialog"""
        help_dialog = ctk.CTkToplevel(self)
        help_dialog.title("Help")
        help_dialog.geometry("600x500")
        
        # Center dialog
        help_dialog.transient(self)
        help_dialog.grab_set()
        
        # Header
        ctk.CTkLabel(
            help_dialog,
            text="❓ Help & Documentation",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Help content
        help_scroll = ctk.CTkScrollableFrame(help_dialog)
        help_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        help_text = """
KEYBOARD SHORTCUTS:
• Ctrl+N - New Scan
• Ctrl+H - View History
• Ctrl+S - Quick Save
• Esc - Return to Dashboard

HOW TO USE:
1. Select a scan type (DNS Cache, Common Sites, or Custom)
2. For custom scans, enter domains manually or import from file
3. View results with real-time statistics
4. Save scans for later reference
5. Export results in CSV, JSON, or TXT format

DNS CACHE SCAN:
Extracts domains from your system's DNS cache (Windows only).
Requires administrator privileges on some systems.

COMMON SITES SCAN:
Tests connectivity to popular websites from a predefined list.
Edit data/common_sites.txt to customize the list.

CUSTOM DOMAIN SCAN:
Scan your own list of domains. Enter one domain per line.
Supports importing from TXT or CSV files.

RESULTS:
• Green: Fast connection (<100ms)
• Yellow: Medium connection (100-300ms)  
• Red: Slow connection (>300ms)
• Valid SNI: Successfully connected - Use in V2Ray
• Blocked: Connection failed or blocked - Don't use

EXPORT OPTIONS:
• CSV: For Excel or data analysis
• JSON: For API integration or programming
• TXT: Simple plain text format

TIPS:
• Use search to filter large result sets
• Filter by status (Valid SNI/Blocked)
• Copy domains to clipboard with the copy button
• Sort results by clicking column headers
        """
        
        ctk.CTkLabel(
            help_scroll,
            text=help_text,
            font=ctk.CTkFont(size=12),
            justify="left",
            anchor="w"
        ).pack(fill="x", padx=10, pady=10)


class SaveDiscardDialog(ctk.CTkToplevel):
    """Modal dialog for save/discard/cancel"""
    
    def __init__(self, parent, save_callback, discard_callback):
        super().__init__(parent)
        
        self.save_callback = save_callback
        self.discard_callback = discard_callback
        
        # Configure window
        self.title("Unsaved Scan")
        self.geometry("450x220")
        self.resizable(False, False)
        
        # Make modal
        self.transient(parent)
        self.grab_set()
        
        # Center on parent
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - 450) // 2
        y = parent.winfo_y() + (parent.winfo_height() - 220) // 2
        self.geometry(f"+{x}+{y}")
        
        # Icon
        ctk.CTkLabel(
            self,
            text="💾",
            font=ctk.CTkFont(size=48)
        ).pack(pady=20)
        
        # Message
        message = ctk.CTkLabel(
            self,
            text="You have unsaved scan results.\nWhat would you like to do?",
            font=ctk.CTkFont(size=14),
            justify="center"
        )
        message.pack(pady=10)
        
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        save_btn = ctk.CTkButton(
            btn_frame,
            text="💾  Save",
            command=self._save,
            width=120,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669"
        )
        save_btn.pack(side="left", padx=5)
        
        discard_btn = ctk.CTkButton(
            btn_frame,
            text="🗑  Discard",
            command=self._discard,
            width=120,
            height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#ef4444",
            hover_color="#dc2626"
        )
        discard_btn.pack(side="left", padx=5)
        
        cancel_btn = ctk.CTkButton(
            btn_frame,
            text="Cancel",
            command=self.destroy,
            width=120,
            height=40,
            font=ctk.CTkFont(size=13),
            fg_color="transparent",
            border_width=2,
            border_color="gray40"
        )
        cancel_btn.pack(side="left", padx=5)
    
    def _save(self):
        """Save and close"""
        self.destroy()
        self.save_callback()
    
    def _discard(self):
        """Discard and close"""
        self.destroy()
        self.discard_callback()


def main():
    """Application entry point"""
    app = SNIReconApp()
    app.mainloop()


if __name__ == "__main__":
    main()
