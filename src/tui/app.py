#!/usr/bin/env python3
"""
Full-screen Terminal User Interface for audit_tools.
Built with Textual framework for modern terminal applications.
"""

import sys
from pathlib import Path
from typing import List, Dict, Optional
from enum import Enum
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Header, Footer, Static, DataTable, Button, Label, Switch, TabbedContent, TabPane, Input, LoadingIndicator
from textual.screen import Screen, ModalScreen
from textual.binding import Binding
from textual import events
from textual.css.query import NoMatches

from audit_manifest import parse_manifest, triage, Finding
from utils.colors import Colors, STYLES, EMOJIS


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ManifestResult:
    """Results from scanning a single manifest."""
    path: str
    package: str
    findings: List[Finding]
    status: str = 'pending'  # pending, success, error

    @property
    def has_high(self) -> bool:
        return any(f.severity == 'HIGH' for f in self.findings)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'HIGH')

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'MEDIUM')

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'LOW')

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'INFO')

    @property
    def total_count(self) -> int:
        return len(self.findings)


class Severity(Enum):
    """Severity filter options."""
    ALL = 'INFO'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'


# ─────────────────────────────────────────────────────────────────────────────
# Widgets
# ─────────────────────────────────────────────────────────────────────────────
class SeverityBadge(Static):
    """Colored badge displaying severity level."""
    
    def __init__(self, severity: str, count: int, **kwargs):
        super().__init__(**kwargs)
        self.severity = severity
        self.count = count
    
    def compose(self) -> ComposeResult:
        emoji = EMOJIS.get(self.severity, '⚪')
        count_str = f"{self.count}" if self.count > 0 else "✓"
        
        if self.severity == 'HIGH':
            self.styles.background = "#dc3545"
            self.styles.color = "white"
        elif self.severity == 'MEDIUM':
            self.styles.background = "#ffc107"
            self.styles.color = "#333"
        elif self.severity == 'LOW':
            self.styles.background = "#007bff"
            self.styles.color = "white"
        else:
            self.styles.background = "#28a745"
            self.styles.color = "white"
        
        self.styles.padding = (0, 1)
        self.styles.border = ("solid", self.styles.background)
        self.styles.width = "auto"
        
        yield Static(f"{emoji} {count_str} {self.severity}")


class StatusBar(Static):
    """Status bar showing current operation status."""
    
    DEFAULT_CLASSES = "status-bar"


class FindingTable(DataTable):
    """DataTable for displaying audit findings with sorting and filtering."""
    
    DEFAULT_CSS = """
    FindingTable {
        height: 1fr;
        width: 100%;
        border: solid cyan;
    }
    FindingTable > .datatable--header {
        background: $accent-dark;
        color: white;
        text-style: bold;
    }
    FindingTable > .datatable--cursor {
        background: $accent;
    }
    """


# ─────────────────────────────────────────────────────────────────────────────
# Screens
# ─────────────────────────────────────────────────────────────────────────────
class FilterModal(ModalScreen):
    """Modal screen for filtering findings by severity."""
    
    BINDINGS = [
        Binding('escape', 'dismiss_modal', 'Close'),
        Binding('enter', 'select_severity', 'Select'),
    ]
    
    def __init__(self, on_select: callable):
        super().__init__()
        self.on_select = on_select
        self.current_selection = Severity.ALL
    
    def compose(self) -> ComposeResult:
        yield Static("[bold cyan]Filter Findings By Severity[/]", classes="modal-header")
        
        with Vertical(classes="filter-options"):
            for severity in ['ALL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                btn = Button(severity, variant="default")
                btn.set_class(True, f"severity-{severity.lower()}")
                btn.on_click(self.on_button_click, severity=severity)
                yield btn
    
    def on_button_click(self, event: Button.Pressed, severity: str):
        self.current_selection = Severity[severity]
        self.dismiss(severity.upper() if severity != 'ALL' else 'INFO')
    
    def action_dismiss_modal(self):
        self.dismiss(None)
    
    def action_select_severity(self):
        self.dismiss(self.current_selection.value)


class HelpModal(ModalScreen):
    """Help modal showing keyboard shortcuts and controls."""
    
    BINDINGS = [
        Binding('escape', 'dismiss', 'Close'),
    ]
    
    def compose(self) -> ComposeResult:
        help_text = """
        ╭─ Keyboard Shortcuts ──────────────────────────────╮
        │ q / escape  Quit application                      │
        │ ?           Show this help                        │
        │ /           Focus filter input                    │
        │ f           Open severity filter modal            │
        │ t           Toggle table sort                     │
        │ r           Refresh scan results                  │
        │ e           Export report                         │
        │ c           Clear all results                     │
        │ ↑ ↓         Navigate table                        │
        │ Enter       View details of finding               │
        │ 1-4         Jump to severity count badge          │
        ╰───────────────────────────────────────────────────╯
        """
        yield Static(help_text, id="help-content")
    
    def action_dismiss(self):
        self.dismiss()


class DetailScreen(ModalScreen):
    """Screen showing detailed view of a single finding."""
    
    BINDINGS = [
        Binding('escape', 'dismiss', 'Close'),
        Binding('n', 'next_finding', 'Next'),
        Binding('p', 'prev_finding', 'Previous'),
    ]
    
    def __init__(self, finding: Finding, all_findings: List[Finding]):
        super().__init__()
        self.finding = finding
        self.all_findings = all_findings
        self.index = all_findings.index(finding) if finding in all_findings else 0
    
    def compose(self) -> ComposeResult:
        f = self.finding
        emoji = EMOJIS.get(f.severity, '⚪')
        
        yield Static(
            f"{emoji} Finding Details",
            id="detail-header"
        )
        
        with Vertical(classes="detail-body"):
            yield Static(f"[bold]Severity:[/] {f.severity}", id="detail-severity")
            yield Static(f"[bold]Location:[/] {f.location}", id="detail-location")
            yield Static(f"[bold]Issue:[/] {f.issue}", id="detail-issue")
    
    def action_next_finding(self):
        next_idx = (self.index + 1) % len(self.all_findings)
        self.dismiss(self.all_findings[next_idx])
    
    def action_prev_finding(self):
        prev_idx = (self.index - 1) % len(self.all_findings)
        self.dismiss(self.all_findings[prev_idx])


# ─────────────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────────────
class AuditApp(App):
    """Main full-screen TUI application for audit_tools."""
    
    # ─────────────────────────────────────────────────────────────────────
    # App Configuration
    # ─────────────────────────────────────────────────────────────────────
    TITLE = "🛡️ audit_tools TUI"
    SUB_TITLE = "Android Manifest Security Scanner"
    
    CSS_PATH = None  # Inline CSS below
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    /* Header Styling */
    Header {
        background: $primary;
        color: $text;
    }
    
    /* Footer Styling */
    Footer {
        background: $surface-darken-3;
        key-display: block;
        key-hover-highlight: true;
    }
    
    /* Container Layouts */
    Container {
        background: transparent;
    }
    
    Horizontal {
        align-horizontal: center;
    }
    
    Vertical {
        align-vertical: middle;
    }
    
    Grid {
        grid-size: 4;
        grid-gutter: 1 2;
    }
    
    /* Badge Styling */
    SeverityBadge {
        height: 3;
        width: auto;
        align: center middle;
        text-align: center;
        content-align: center middle;
    }
    
    /* Status Bar */
    StatusBar {
        dock: bottom;
        height: 2;
        background: $accent-darken-2;
        color: $text-muted;
    }
    
    /* Tables */
    FindingTable {
        height: 1fr;
        width: 100%;
        border: solid $accent;
    }
    
    /* Tabbed Content */
    TabbedContent {
        height: 100%;
    }
    
    TabPane {
        padding: 1;
    }
    
    /* Buttons */
    Button {
        margin: 0 1;
        width: auto;
    }
    
    /* Input Fields */
    Input {
        margin: 1 0;
        width: 1fr;
    }
    
    /* Modal Styles */
    ModalScreen {
        background: rgba(0, 0, 0, 0.5);
    }
    
    #help-content {
        padding: 1 2;
        background: $surface;
        border: double $accent;
        margin: 1;
    }
    
    /* Severity Colors for Buttons */
    Button.severity-high {
        background: #dc3545;
        color: white;
    }
    
    Button.severity-medium {
        background: #ffc107;
        color: black;
    }
    
    Button.severity-low {
        background: #007bff;
        color: white;
    }
    
    Button.severity-info {
        background: #28a745;
        color: white;
    }
    """
    
    # ─────────────────────────────────────────────────────────────────────
    # Key Bindings
    # ─────────────────────────────────────────────────────────────────────
    BINDINGS = [
        Binding('q', 'quit', 'Quit', show=True, priority=True),
        Binding('?', 'show_help', 'Help', show=True),
        Binding('/', 'focus_filter', 'Search', show=True),
        Binding('f', 'open_filter', 'Filter', show=True),
        Binding('r', 'refresh_scan', 'Refresh', show=True),
        Binding('e', 'export_report', 'Export', show=True),
        Binding('c', 'clear_results', 'Clear', show=True),
        Binding('t', 'toggle_sort', 'Sort', show=True),
        Binding('1', 'jump_to_highest_severity', 'HIGH', show=False),
        Binding('2', 'jump_to_medium_severity', 'MEDIUM', show=False),
        Binding('3', 'jump_to_low_severity', 'LOW', show=False),
        Binding('4', 'jump_to_info_severity', 'INFO', show=False),
    ]
    
    # ─────────────────────────────────────────────────────────────────────
    # Lifecycle Methods
    # ─────────────────────────────────────────────────────────────────────
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.results: List[ManifestResult] = []
        self.all_findings: List[Finding] = []
        self.current_severity_filter = 'INFO'
        self.sort_reverse = False
        
        # Load manifests passed as arguments
        self.initial_manifests = args or []
    
    def compose(self) -> ComposeResult:
        """Compose the main UI layout."""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            with TabbedContent(id="tabs"):
                # Dashboard Tab
                with TabPane("Dashboard", id="dashboard"):
                    yield self._compose_dashboard()
                
                # Findings Tab
                with TabPane("Findings", id="findings"):
                    yield self._compose_findings_tab()
                
                # Settings Tab
                with TabPane("Settings", id="settings"):
                    yield self._compose_settings_tab()
        
        yield StatusBar(id="status-bar")
        yield Footer()
    
    def _compose_dashboard(self) -> ComposeResult:
        """Compose dashboard tab content."""
        with Container(id="dashboard"):
            yield Static("📊 Security Overview", classes="tab-title")
            
            # Severity badges row
            with Horizontal(id="badge-row"):
                yield SeverityBadge('HIGH', 0, id="badge-high")
                yield SeverityBadge('MEDIUM', 0, id="badge-medium")
                yield SeverityBadge('LOW', 0, id="badge-low")
                yield SeverityBadge('INFO', 0, id="badge-info")
            
            # Quick stats
            with Grid(id="stats-grid"):
                yield Static("Total Scanned", classes="stat-label")
                yield Static("0", classes="stat-value", id="stat-total")
                yield Static("Packages", classes="stat-label")
                yield Static("0", classes="stat-value", id="stat-packages")
                yield Static("Error Rate", classes="stat-label")
                yield Static("0%", classes="stat-value", id="stat-errors")
                yield Static("Health Score", classes="stat-label")
                yield Static("100", classes="stat-value", id="stat-health")
            
            # Recent scans list
            yield Static("📋 Recent Scans", classes="section-title")
            
            with Vertical(id="scans-list"):
                yield Static("No scans yet. Press R to refresh.", id="no-scans-msg")
        
        yield Static("", id="dashboard-footer")
    
    def _compose_findings_tab(self) -> ComposeResult:
        """Compose findings tab content."""
        with Container(id="findings-tab"):
            # Toolbar
            with Horizontal(id="toolbar"):
                yield Input(placeholder="Search findings...", id="search-input")
                yield Button("Filter", id="filter-btn")
                yield Button("Export", id="export-btn")
                yield Button("Clear", id="clear-btn")
            
            # Severity filter toggles
            with Horizontal(id="severity-toggles"):
                yield Switch(id="toggle-high", label="HIGH")
                yield Switch(id="toggle-medium", label="MEDIUM")
                yield Switch(id="toggle-low", label="LOW")
                yield Switch(id="toggle-info", label="INFO")
            
            # Findings table
            yield FindingTable(id="findings-table")
    
    def _compose_settings_tab(self) -> ComposeResult:
        """Compose settings tab content."""
        with Container(id="settings"):
            yield Static("⚙️  Application Settings", classes="tab-title")
            
            yield Static("\nGeneral:", classes="section-title")
            yield Static("  Theme: Dark (default)")
            yield Static("  Verbosity: Normal")
            
            yield Static("\nScanner:", classes="section-title")
            yield Static("  Default severity: INFO")
            yield Static("  Parallel workers: 1")
            
            yield Static("\nExport:", classes="section-title")
            yield Static("  Formats: text, json, html")
            yield Static("  Output directory: artifacts/")
    
    # ─────────────────────────────────────────────────────────────────────
    # Action Handlers
    # ─────────────────────────────────────────────────────────────────────
    def on_mount(self) -> None:
        """Called when app mounts."""
        self.update_status("Ready. Press R to scan.")
        
        # Apply initial severity switches
        self.query_one("#toggle-high", Switch).value = True
        self.query_one("#toggle-medium", Switch).value = True
        self.query_one("#toggle-low", Switch).value = True
        self.query_one("#toggle-info", Switch).value = True
        
        # If manifests passed, start scan
        if self.initial_manifests:
            self.call_later(self.refresh_scan)
    
    def action_quit(self):
        """Quit the application."""
        self.exit()
    
    def action_show_help(self):
        """Show help modal."""
        self.push_screen(HelpModal())
    
    def action_focus_filter(self):
        """Focus search input."""
        self.query_one("#search-input", Input).focus()
    
    def action_open_filter(self):
        """Open severity filter modal."""
        def handler(value):
            if value:
                self.current_severity_filter = value
                self.filter_findings()
        self.push_screen(FilterModal(handler))
    
    def action_refresh_scan(self):
        """Trigger new scan."""
        self.scan_manifests()
    
    def action_export_report(self):
        """Export current findings to file."""
        from rich.prompt import Prompt
        # In real implementation, this would open a dialog
        self.notify("Export feature coming soon!", title="Export")
    
    def action_clear_results(self):
        """Clear all scan results."""
        self.results.clear()
        self.all_findings.clear()
        self.update_dashboard()
        self.update_table([])
        self.update_status("Results cleared")
    
    def action_toggle_sort(self):
        """Toggle table sort order."""
        self.sort_reverse = not self.sort_reverse
        self.update_table(self.all_findings)
    
    def action_jump_to_highest_severity(self):
        """Jump to HIGH findings."""
        self.filter_by_severity('HIGH')
    
    def action_jump_to_medium_severity(self):
        """Jump to MEDIUM findings."""
        self.filter_by_severity('MEDIUM')
    
    def action_jump_to_low_severity(self):
        """Jump to LOW findings."""
        self.filter_by_severity('LOW')
    
    def action_jump_to_info_severity(self):
        """Jump to INFO findings."""
        self.filter_by_severity('INFO')
    
    # ─────────────────────────────────────────────────────────────────────
    # Scan Logic
    # ─────────────────────────────────────────────────────────────────────
    def scan_manifests(self, manifests: List[str] = None):
        """Scan manifest files and update UI."""
        targets = manifests or self.initial_manifests or ['.']
        self.update_status(f"Scanning {len(targets)} manifest(s)...")
        
        from glob import glob
        expanded = []
        for pattern in targets:
            matches = glob(pattern)
            if matches:
                expanded.extend(matches)
            else:
                expanded.append(pattern)
        
        self.results.clear()
        self.all_findings.clear()
        
        for manifest_path in expanded:
            try:
                root = parse_manifest(manifest_path)
                package = root.get('package') or 'unknown'
                findings = triage(root)
                
                result = ManifestResult(
                    path=manifest_path,
                    package=package,
                    findings=findings,
                    status='success'
                )
                self.results.append(result)
                self.all_findings.extend(findings)
                
            except Exception as e:
                self.results.append(
                    ManifestResult(
                        path=manifest_path,
                        package='unknown',
                        findings=[],
                        status='error'
                    )
                )
        
        # Update UI
        self.update_dashboard()
        self.update_table(self.all_findings)
        self.update_status(f"Scan complete. {len(self.all_findings)} findings.")
    
    def update_dashboard(self):
        """Update dashboard with current stats."""
        # Update badges
        counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.all_findings:
            counts[f.severity] += 1
        
        for sev in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
            badge = self.query_one(f"#badge-{sev.lower()}", SeverityBadge)
            badge.count = counts[sev]
            badge.refresh()
        
        # Update stats grid
        total_scans = len(self.results)
        total_packages = len(set(r.package for r in self.results))
        error_count = sum(1 for r in self.results if r.status == 'error')
        health_score = max(0, 100 - (counts['HIGH'] * 10 + counts['MEDIUM'] * 5))
        
        self.query_one("#stat-total", Static).update(str(total_scans))
        self.query_one("#stat-packages", Static).update(str(total_packages))
        self.query_one("#stat-errors", Static).update(f"{error_count}/{total_scans}")
        self.query_one("#stat-health", Static).update(str(health_score))
        
        # Hide empty state message
        no_scans = self.query_one("#no-scans-msg", Static)
        no_scans.display = total_scans == 0
        
        # Add recent scans to list
        if total_scans > 0:
            scans_list = self.query_one("#scans-list", Vertical)
            for i, result in enumerate(self.results[-5:]):  # Last 5
                stat_item = Static(f"[dim]{result.path}[/] • {result.total_count} findings")
                stat_item.id = f"scan-{i}"
                scans_list.mount(stat_item)
    
    def update_table(self, findings: List[Finding]):
        """Update the findings table."""
        table = self.query_one("#findings-table", FindingTable)
        
        if not table.thead:
            # Initialize table columns
            table.add_columns("Severity", "Package", "Component", "Issue")
        
        # Clear and populate
        table.clear()
        
        filtered = self._filter_findings(findings)
        sorted_findings = sorted(filtered, key=lambda f: f.severity, reverse=self.sort_reverse)
        
        for f in sorted_findings:
            package = 'N/A'  # Would need to track mapping
            table.add_row(
                f.severity,
                package,
                f.location.split()[0] if f.location else '?',
                f.issue
            )
    
    def filter_findings(self):
        """Apply current filters to table."""
        self.update_table(self.all_findings)
    
    def _filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings based on severity switches."""
        result = []
        for f in findings:
            switch = self.query_one(f"#toggle-{f.severity.lower()}", Switch)
            if switch.value:
                result.append(f)
        return result
    
    def filter_by_severity(self, severity: str):
        """Filter to show only one severity level."""
        # Turn off all switches, turn on selected
        for sev in ['high', 'medium', 'low', 'info']:
            self.query_one(f"#toggle-{sev}", Switch).value = (sev == severity.lower())
        
        self.filter_findings()
        self.update_status(f"Showing {severity} findings only")
    
    def update_status(self, message: str):
        """Update status bar message."""
        status = self.query_one("#status-bar", StatusBar)
        status.update(message)
    
    # ─────────────────────────────────────────────────────────────────────
    # Event Handlers
    # ─────────────────────────────────────────────────────────────────────
    def on_button_pressed(self, event: Button.Pressed):
        """Handle button clicks."""
        if event.button.id == 'filter-btn':
            self.action_open_filter()
        elif event.button.id == 'export-btn':
            self.action_export_report()
        elif event.button.id == 'clear-btn':
            self.action_clear_results()
    
    def on_switch_changed(self, event: Switch.Changed):
        """Handle switch toggles."""
        if event.switch.id.startswith('toggle-'):
            self.filter_findings()
    
    def on_input_changed(self, event: Input.Changed):
        """Handle search input changes."""
        # TODO: Implement real-time filtering
        pass
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        """Handle table row selection."""
        # Show details modal for selected finding
        if self.all_findings:
            idx = event.row_key.value
            finding = self.all_findings[idx]
            self.push_screen(DetailScreen(finding, self.all_findings))
    
    def on_key(self, event: events.Key):
        """Handle global keyboard events."""
        if event.key == 'enter':
            # Trigger detail view for currently selected row
            table = self.query_one("#findings-table", FindingTable)
            if table.cursor_row is not None:
                idx = table.cursor_row
                finding = self.all_findings[idx] if idx < len(self.all_findings) else None
                if finding:
                    self.push_screen(DetailScreen(finding, self.all_findings))


def run(*manifests):
    """Run the TUI application."""
    app = AuditApp(*manifests)
    app.run()


if __name__ == '__main__':
    from sys import argv
    run(*argv[1:])
