# Modern Clean UI Components for MetaShield
# Sophisticated and minimal component library

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

class Card(QFrame):
    """Modern card component with clean shadows and rounded corners"""
    
    def __init__(self, title="", padding=24, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        
        # Modern card styling
        self.setStyleSheet("""
            Card {
                background-color: white;
                border: 1px solid #f0f0f0;
                border-radius: 12px;
                padding: 0px;
            }
        """)
        
        # Subtle shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(24)
        shadow.setColor(QColor(0, 0, 0, 8))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)
        
        # Layout with proper padding
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(padding, padding, padding, padding)
        self.main_layout.setSpacing(16)
        
        # Add title if provided
        if title:
            self.title_label = QLabel(title)
            self.title_label.setProperty("class", "title")
            self.title_label.setStyleSheet("""
                QLabel {
                    color: #262626;
                    font-size: 18px;
                    font-weight: 600;
                    margin-bottom: 8px;
                    padding: 0;
                }
            """)
            self.main_layout.addWidget(self.title_label)
        
        self.setLayout(self.main_layout)
    
    def add_widget(self, widget):
        """Add a widget to the card"""
        self.main_layout.addWidget(widget)
    
    def add_layout(self, layout):
        """Add a layout to the card"""
        self.main_layout.addLayout(layout)
        
    def layout(self):
        """Return the main layout for backwards compatibility"""
        return self.main_layout

class PrimaryButton(QPushButton):
    """Primary action button with modern styling"""
    
    def __init__(self, text, icon=None, size="normal", parent=None):
        super().__init__(text, parent)
        if icon:
            self.setIcon(icon)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("class", "primary")
        
        # Size variants
        if size == "small":
            self.setFixedSize(60, 28)
            self.setStyleSheet("""
                PrimaryButton {
                    background-color: #1890ff;
                    border: none;
                    border-radius: 4px;
                    color: white;
                    font-size: 11px;
                    font-weight: 500;
                    padding: 0px;
                }
                PrimaryButton:hover {
                    background-color: #40a9ff;
                }
                PrimaryButton:pressed {
                    background-color: #096dd9;
                }
            """)
        elif size == "compact":
            self.setFixedSize(70, 32)
            self.setStyleSheet("""
                PrimaryButton {
                    background-color: #1890ff;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 12px;
                    font-weight: 500;
                    padding: 0px;
                }
                PrimaryButton:hover {
                    background-color: #40a9ff;
                }
                PrimaryButton:pressed {
                    background-color: #096dd9;
                }
            """)
        else:  # normal size
            self.setMinimumSize(80, 36)
            self.setStyleSheet("""
                PrimaryButton {
                    background-color: #1890ff;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 14px;
                    font-weight: 500;
                    padding: 8px 16px;
                }
                PrimaryButton:hover {
                    background-color: #40a9ff;
                }
                PrimaryButton:pressed {
                    background-color: #096dd9;
                }
            """)

class SecondaryButton(QPushButton):
    """Secondary button with outline style"""
    
    def __init__(self, text, icon=None, size="normal", parent=None):
        super().__init__(text, parent)
        if icon:
            self.setIcon(icon)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("class", "secondary")
        
        # Size variants
        if size == "small":
            self.setFixedSize(60, 28)
            self.setStyleSheet("""
                SecondaryButton {
                    background-color: white;
                    border: 1px solid #d9d9d9;
                    border-radius: 4px;
                    color: #595959;
                    font-size: 11px;
                    font-weight: 500;
                    padding: 0px;
                }
                SecondaryButton:hover {
                    border-color: #40a9ff;
                    color: #40a9ff;
                }
                SecondaryButton:pressed {
                    border-color: #096dd9;
                    color: #096dd9;
                }
            """)
        elif size == "compact":
            self.setFixedSize(80, 32)
            self.setStyleSheet("""
                SecondaryButton {
                    background-color: white;
                    border: 1px solid #d9d9d9;
                    border-radius: 6px;
                    color: #595959;
                    font-size: 12px;
                    font-weight: 500;
                    padding: 0px;
                }
                SecondaryButton:hover {
                    border-color: #40a9ff;
                    color: #40a9ff;
                }
                SecondaryButton:pressed {
                    border-color: #096dd9;
                    color: #096dd9;
                }
            """)
        else:  # normal size
            self.setMinimumSize(80, 36)
            self.setStyleSheet("""
                SecondaryButton {
                    background-color: white;
                    border: 1px solid #d9d9d9;
                    border-radius: 6px;
                    color: #595959;
                    font-size: 14px;
                    font-weight: 500;
                    padding: 8px 16px;
                }
                SecondaryButton:hover {
                    border-color: #40a9ff;
                    color: #40a9ff;
                }
                SecondaryButton:pressed {
                    border-color: #096dd9;
                    color: #096dd9;
                }
            """)

class DangerButton(QPushButton):
    """Danger/delete button with red styling"""
    
    def __init__(self, text, icon=None, size="normal", parent=None):
        super().__init__(text, parent)
        if icon:
            self.setIcon(icon)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("class", "danger")
        
        # Size variants  
        if size == "small":
            self.setFixedSize(60, 28)
            self.setStyleSheet("""
                DangerButton {
                    background-color: #ff4d4f;
                    border: none;
                    border-radius: 4px;
                    color: white;
                    font-size: 11px;
                    font-weight: 500;
                    padding: 0px;
                }
                DangerButton:hover {
                    background-color: #ff7875;
                }
                DangerButton:pressed {
                    background-color: #d32f2f;
                }
            """)
        elif size == "compact":
            self.setFixedSize(70, 32)
            self.setStyleSheet("""
                DangerButton {
                    background-color: #ff4d4f;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 12px;
                    font-weight: 500;
                    padding: 0px;
                }
                DangerButton:hover {
                    background-color: #ff7875;
                }
                DangerButton:pressed {
                    background-color: #d32f2f;
                }
            """)
        else:  # normal size
            self.setMinimumSize(80, 36)
            self.setStyleSheet("""
                DangerButton {
                    background-color: #ff4d4f;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 14px;
                    font-weight: 500;
                    padding: 8px 16px;
                }
                DangerButton:hover {
                    background-color: #ff7875;
                }
                DangerButton:pressed {
                    background-color: #d32f2f;
                }
            """)

class ActionButton(QPushButton):
    """Compact action button for toolbars and action groups"""
    
    def __init__(self, text, button_type="primary", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # Set appropriate size for action buttons
        self.setFixedHeight(32)
        self.setMinimumWidth(70)
        
        # Style based on button type - PyQt6 compatible CSS only
        if button_type == "primary":
            self.setStyleSheet('''
                ActionButton {
                    background-color: #1890ff;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 12px;
                }
                ActionButton:hover {
                    background-color: #40a9ff;
                }
                ActionButton:pressed {
                    background-color: #096dd9;
                }
            ''')
        elif button_type == "secondary":
            self.setStyleSheet('''
                ActionButton {
                    background-color: white;
                    border: 2px solid #d9d9d9;
                    border-radius: 6px;
                    color: #595959;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 12px;
                }
                ActionButton:hover {
                    border-color: #40a9ff;
                    color: #40a9ff;
                    background-color: #f0f8ff;
                }
                ActionButton:pressed {
                    border-color: #096dd9;
                    color: #096dd9;
                    background-color: #e6f7ff;
                }
            ''')
        elif button_type == "danger":
            self.setStyleSheet('''
                ActionButton {
                    background-color: #ff4d4f;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 12px;
                }
                ActionButton:hover {
                    background-color: #ff7875;
                }
                ActionButton:pressed {
                    background-color: #d32f2f;
                }
            ''')
        elif button_type == "success":
            self.setStyleSheet('''
                ActionButton {
                    background-color: #52c41a;
                    border: none;
                    border-radius: 6px;
                    color: white;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 6px 12px;
                }
                ActionButton:hover {
                    background-color: #73d13d;
                }
                ActionButton:pressed {
                    background-color: #389e0d;
                }
            ''')

class IconButton(QPushButton):
    """Icon-only button for toolbars"""
    
    def __init__(self, icon, tooltip="", parent=None):
        super().__init__(parent)
        self.setIcon(icon)
        self.setToolTip(tooltip)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(36, 36)
        self.setStyleSheet("""
            IconButton {
                background-color: transparent;
                border: none;
                border-radius: 6px;
                padding: 8px;
            }
            IconButton:hover {
                background-color: #f5f5f5;
            }
            IconButton:pressed {
                background-color: #e6f7ff;
            }
        """)

class SearchInput(QLineEdit):
    """Enhanced search input with search icon"""
    
    searchChanged = pyqtSignal(str)
    
    def __init__(self, placeholder="Search...", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        
        # Search action
        self.search_action = QAction("🔍", self)
        self.addAction(self.search_action, QLineEdit.ActionPosition.LeadingPosition)
        
        # Connect signals
        self.textChanged.connect(self.searchChanged.emit)
        
        # Styling
        self.setStyleSheet("""
            SearchInput {
                padding-left: 32px;
                font-size: 14px;
                min-height: 36px;
                border-radius: 8px;
            }
        """)

class ModernTable(QTableWidget):
    """Clean table with modern styling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_table()
    
    def setup_table(self):
        """Configure table for modern appearance"""
        # Remove selection behavior on rows
        pass  # self.setSelectionBehavior(1)
        pass  # self.setSelectionMode(1)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        
        # Header styling
        self.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.horizontalHeader().setHighlightSections(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        
        # Row height
        self.verticalHeader().setDefaultSectionSize(48)
        
        # Enable sorting
        self.setSortingEnabled(True)
    
    def setColumns(self, headers):
        """Set column headers"""
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)

class SidebarList(QListWidget):
    """Sidebar navigation list"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(280)
        self.setMaximumWidth(320)
        self.setSpacing(4)
        
        # Custom styling for sidebar
        self.setStyleSheet("""
            SidebarList {
                background-color: white;
                border: 1px solid #f0f0f0;
                border-radius: 8px;
                padding: 8px;
            }
            SidebarList::item {
                border-radius: 6px;
                padding: 10px 12px;
                margin: 2px 0;
                color: #595959;
                font-weight: 400;
            }
            SidebarList::item:selected {
                background-color: #e6f7ff;
                color: #1890ff;
                font-weight: 500;
            }
            SidebarList::item:hover {
                background-color: #f5f5f5;
            }
        """)

class StatusBadge(QLabel):
    """Status indicator badge"""
    
    def __init__(self, text, status_type="default", parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_type = status_type
        self.update_style()
    
    def update_style(self):
        """Update badge styling based on status type"""
        styles = {
            "success": "background-color: #f6ffed; color: #52c41a; border: 1px solid #b7eb8f;",
            "warning": "background-color: #fffbe6; color: #faad14; border: 1px solid #ffe58f;",
            "error": "background-color: #fff2f0; color: #ff4d4f; border: 1px solid #ffb3b3;",
            "info": "background-color: #e6f7ff; color: #1890ff; border: 1px solid #91d5ff;",
            "default": "background-color: #fafafa; color: #595959; border: 1px solid #f0f0f0;"
        }
        
        style = styles.get(self.status_type, styles["default"])
        self.setStyleSheet(f"""
            StatusBadge {{
                {style}
                border-radius: 12px;
                font-size: 12px;
                font-weight: 500;
                padding: 4px 8px;
                min-width: 40px;
                max-height: 24px;
            }}
        """)
    
    def set_status(self, status_type):
        """Change the badge status"""
        self.status_type = status_type
        self.update_style()

class ProgressCard(Card):
    """Card with progress indicator"""
    
    def __init__(self, title, current=0, total=100, parent=None):
        super().__init__(title, parent=parent)
        
        self.current = current
        self.total = total
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        
        # Progress text
        self.progress_label = QLabel(f"{current}/{total}")
        self.progress_label.setProperty("class", "caption")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Add to layout
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        
        self.add_layout(progress_layout)
    
    def update_progress(self, current):
        """Update progress value"""
        self.current = current
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"{current}/{self.total}")

class MetricCard(Card):
    """Card for displaying metrics/statistics"""
    
    def __init__(self, title, value, change=None, icon=None, parent=None):
        super().__init__(padding=20, parent=parent)
        
        # Main layout
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)
        
        # Icon
        if icon:
            icon_label = QLabel()
            icon_label.setPixmap(icon.pixmap(24, 24))
            header_layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel(title)
        title_label.setProperty("class", "subtitle")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Value
        value_label = QLabel(str(value))
        value_label.setStyleSheet("""
            QLabel {
                color: #262626;
                font-size: 28px;
                font-weight: 600;
                margin: 8px 0;
            }
        """)
        
        # Change indicator
        if change is not None:
            change_label = QLabel(f"{'+' if change >= 0 else ''}{change}%")
            change_color = "#52c41a" if change >= 0 else "#ff4d4f"
            change_label.setStyleSheet(f"""
                QLabel {{
                    color: {change_color};
                    font-size: 12px;
                    font-weight: 500;
                }}
            """)
            
            self.add_layout(header_layout)
            self.add_widget(value_label)
            self.add_widget(change_label)
        else:
            self.add_layout(header_layout)
            self.add_widget(value_label)

class EmptyState(QWidget):
    """Empty state component"""
    
    def __init__(self, title, description="", action_text="", parent=None):
        super().__init__(parent)
        
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)
        
        # Empty icon (you can replace with actual icon)
        icon_label = QLabel("📭")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("""
            QLabel {
                font-size: 48px;
                color: #bfbfbf;
                margin: 24px 0;
            }
        """)
        
        # Title
        title_label = QLabel(title)
        title_label.setProperty("class", "title")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                color: #8c8c8c;
                font-size: 16px;
                font-weight: 500;
            }
        """)
        
        # Description
        if description:
            desc_label = QLabel(description)
            desc_label.setProperty("class", "subtitle")
            desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("""
                QLabel {
                    color: #bfbfbf;
                    font-size: 14px;
                    margin-bottom: 16px;
                }
            """)
        
        # Action button
        if action_text:
            action_btn = PrimaryButton(action_text)
            layout.addWidget(icon_label)
            layout.addWidget(title_label)
            if description:
                layout.addWidget(desc_label)
            layout.addWidget(action_btn, 0, Qt.AlignmentFlag.AlignCenter)
        else:
            layout.addWidget(icon_label)
            layout.addWidget(title_label)
            if description:
                layout.addWidget(desc_label)
        
        self.setLayout(layout)

class LoadingSpinner(QLabel):
    """Loading spinner animation"""
    
    def __init__(self, size=24, parent=None):
        super().__init__(parent)
        self.size = size
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Simple loading text (you can implement actual spinner later)
        self.setText("⟳")
        self.setStyleSheet(f"""
            QLabel {{
                font-size: {size-4}px;
                color: #1890ff;
            }}
        """)
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.rotate)
        self.rotation = 0
    
    def start(self):
        """Start the loading animation"""
        self.timer.start(100)
        self.show()
    
    def stop(self):
        """Stop the loading animation"""
        self.timer.stop()
        self.hide()
    
    def rotate(self):
        """Rotate the spinner"""
        self.rotation = (self.rotation + 30) % 360
        transform = QTransform()
        transform.rotate(self.rotation)
        # Note: For a real implementation, you'd apply the transform to a pixmap

class Divider(QFrame):
    """Horizontal divider line"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.HLine)
        self.setFixedHeight(1)
        self.setStyleSheet("""
            Divider {
                border: none;
                background-color: #f0f0f0;
                margin: 16px 0;
            }
        """)