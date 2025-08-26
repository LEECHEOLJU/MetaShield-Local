# Modern Clean UI Style for MetaShield
# Inspired by modern design systems like Ant Design, Material Design 3, and Fluent Design

MODERN_STYLE = """
/* ===== Global Base Styles ===== */
* {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Malgun Gothic', '맑은 고딕', 'Roboto', sans-serif;
    outline: none;
}

QWidget {
    background-color: #fafafa;
    color: #262626;
    font-size: 14px;
    selection-background-color: #1890ff;
    selection-color: white;
}

QMainWindow {
    background-color: #fafafa;
    border: none;
}

/* ===== Card-like Container ===== */
QFrame {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
}

/* ===== Buttons - Clean Modern Style ===== */
QPushButton {
    background-color: #1890ff;
    border: none;
    border-radius: 6px;
    color: white;
    font-size: 14px;
    font-weight: 500;
    padding: 8px 16px;
    min-height: 32px;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #40a9ff;
}

QPushButton:pressed {
    background-color: #096dd9;
}

QPushButton:disabled {
    background-color: #f5f5f5;
    color: #bfbfbf;
}

/* Secondary Button */
QPushButton[class="secondary"] {
    background-color: white;
    border: 1px solid #d9d9d9;
    color: #595959;
}

QPushButton[class="secondary"]:hover {
    border-color: #40a9ff;
    color: #40a9ff;
}

/* Danger Button */
QPushButton[class="danger"] {
    background-color: #ff4d4f;
}

QPushButton[class="danger"]:hover {
    background-color: #ff7875;
}

/* ===== Input Fields - Clean and Minimal ===== */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: white;
    border: 1px solid #d9d9d9;
    border-radius: 6px;
    color: #262626;
    font-size: 14px;
    padding: 8px 12px;
    selection-background-color: #1890ff;
    selection-color: white;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #40a9ff;
}

QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {
    background-color: #f5f5f5;
    color: #bfbfbf;
    border-color: #f0f0f0;
}

QTextEdit, QPlainTextEdit {
    min-height: 100px;
    min-width: 200px;
    line-height: 1.5;
}

/* ===== Tables - Clean Data Display ===== */
QTableWidget {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    gridline-color: #f0f0f0;
    font-size: 14px;
    selection-background-color: #e6f7ff;
    min-height: 300px;
    min-width: 400px;
}

QTableWidget::item {
    border: none;
    padding: 12px 16px;
    border-bottom: 1px solid #f0f0f0;
}

QTableWidget::item:selected {
    background-color: #e6f7ff;
    color: #262626;
}

QTableWidget::item:hover {
    background-color: #f5f5f5;
}

QHeaderView::section {
    background-color: #fafafa;
    border: none;
    border-bottom: 2px solid #f0f0f0;
    color: #8c8c8c;
    font-size: 12px;
    font-weight: 600;
    padding: 12px 16px;
    font-weight: bold;
    letter-spacing: 0.5px;
}

QHeaderView::section:hover {
    background-color: #f0f0f0;
}

/* ===== Lists - Sidebar Navigation Style ===== */
QListWidget {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    min-width: 250px;
    min-height: 150px;
    outline: none;
}

QListWidget::item {
    border: none;
    border-radius: 4px;
    color: #595959;
    margin: 2px 8px;
    padding: 10px 12px;
}

QListWidget::item:selected {
    background-color: #e6f7ff;
    color: #1890ff;
    font-weight: 500;
}

QListWidget::item:hover {
    background-color: #f5f5f5;
}

/* ===== Tabs - Modern Tab Design ===== */
QTabWidget {
    background-color: transparent;
    border: none;
}

QTabWidget::pane {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    border-top-left-radius: 0;
    margin-top: -1px;
    padding: 16px;
}

QTabWidget::tab-bar {
    alignment: left;
}

QTabBar::tab {
    background-color: transparent;
    border: 1px solid #f0f0f0;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    color: #8c8c8c;
    font-size: 14px;
    font-weight: 500;
    margin-right: 4px;
    padding: 12px 20px;
    min-width: 80px;
}

QTabBar::tab:selected {
    background-color: white;
    color: #1890ff;
    border-color: #f0f0f0;
    border-bottom: 1px solid white;
    margin-bottom: -1px;
}

QTabBar::tab:hover:!selected {
    background-color: #f5f5f5;
    color: #595959;
}

/* ===== Group Boxes - Clean Sections ===== */
QGroupBox {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    font-weight: 500;
    margin-top: 16px;
    padding-top: 24px;
    min-width: 220px;
}

QGroupBox::title {
    color: #262626;
    font-size: 16px;
    font-weight: 600;
    left: 16px;
    padding: 0 8px;
    subcontrol-origin: margin;
    subcontrol-position: top left;
}

/* ===== Labels - Typography ===== */
QLabel {
    color: #595959;
    font-size: 14px;
    padding: 2px 0;
}

QLabel[class="title"] {
    color: #262626;
    font-size: 20px;
    font-weight: 600;
}

QLabel[class="subtitle"] {
    color: #8c8c8c;
    font-size: 14px;
    font-weight: 400;
}

QLabel[class="caption"] {
    color: #bfbfbf;
    font-size: 12px;
}

/* ===== Text Browser - Content Display ===== */
QTextBrowser {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    color: #262626;
    font-size: 14px;
    line-height: 1.6;
    padding: 16px;
    selection-background-color: #1890ff;
    selection-color: white;
}

/* ===== Checkboxes - Modern Toggle Style ===== */
QCheckBox {
    color: #595959;
    font-size: 14px;
    spacing: 8px;
}

QCheckBox::indicator {
    background-color: white;
    border: 1px solid #d9d9d9;
    border-radius: 4px;
    height: 16px;
    width: 16px;
}

QCheckBox::indicator:checked {
    background-color: #1890ff;
    border-color: #1890ff;
    image: none;
}

/* Qt doesn't support :after with content, using background approach instead */

QCheckBox::indicator:hover {
    border-color: #40a9ff;
}

/* ===== Combo Box - Dropdown Style ===== */
QComboBox {
    background-color: white;
    border: 1px solid #d9d9d9;
    border-radius: 6px;
    color: #262626;
    font-size: 14px;
    min-width: 120px;
    padding: 6px 12px;
}

QComboBox:hover {
    border-color: #40a9ff;
}

QComboBox:focus {
    border-color: #40a9ff;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border: 2px solid #8c8c8c;
    border-top: none;
    border-left: none;
    height: 4px;
    width: 4px;
    margin-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 6px;
    color: #262626;
    selection-background-color: #e6f7ff;
    outline: none;
}

/* ===== Scrollbars - Minimal Design ===== */
QScrollBar:vertical {
    background-color: transparent;
    width: 8px;
}

QScrollBar::handle:vertical {
    background-color: #d9d9d9;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #bfbfbf;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background: none;
    border: none;
    height: 0;
}

QScrollBar:horizontal {
    background-color: transparent;
    height: 8px;
}

QScrollBar::handle:horizontal {
    background-color: #d9d9d9;
    border-radius: 4px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #bfbfbf;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    background: none;
    border: none;
    width: 0;
}

/* ===== Splitter - Resizable Dividers ===== */
QSplitter::handle {
    background-color: #f0f0f0;
    border-radius: 2px;
}

QSplitter::handle:horizontal {
    width: 4px;
}

QSplitter::handle:vertical {
    height: 4px;
}

QSplitter::handle:hover {
    background-color: #1890ff;
}

/* ===== Status Bar ===== */
QStatusBar {
    background-color: white;
    border-top: 1px solid #f0f0f0;
    color: #8c8c8c;
    font-size: 12px;
    padding: 4px 16px;
}

/* ===== Menu Bar ===== */
QMenuBar {
    background-color: white;
    border-bottom: 1px solid #f0f0f0;
    color: #595959;
    font-size: 14px;
    padding: 4px;
}

QMenuBar::item {
    background-color: transparent;
    border-radius: 4px;
    padding: 8px 12px;
}

QMenuBar::item:selected {
    background-color: #f5f5f5;
}

QMenu {
    background-color: white;
    border: 1px solid #f0f0f0;
    border-radius: 8px;
    color: #595959;
    padding: 8px;
}

QMenu::item {
    background-color: transparent;
    border-radius: 4px;
    padding: 8px 16px;
}

QMenu::item:selected {
    background-color: #e6f7ff;
    color: #1890ff;
}

/* ===== Progress Bar ===== */
QProgressBar {
    background-color: #f5f5f5;
    border: none;
    border-radius: 6px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #1890ff;
    border-radius: 6px;
}

/* ===== Tooltips ===== */
QToolTip {
    background-color: #262626;
    border: none;
    border-radius: 6px;
    color: white;
    font-size: 12px;
    padding: 8px 12px;
}

/* ===== Window Controls ===== */
QWidget:window {
    background-color: #fafafa;
}

/* ===== Focus Styles ===== */
*:focus {
    outline: none;
}

/* ===== Disabled States ===== */
*:disabled {
    color: #bfbfbf;
}

/* ===== Basic Responsive Settings ===== */
/* Safe responsive adjustments without layout breaking */
QListWidget {
    min-width: 280px;
}

QTableWidget {
    min-height: 300px;
}

QTextEdit, QPlainTextEdit {
    min-height: 80px;
}

/* Keep original button styling */
QPushButton {
    min-width: 80px;
    padding: 8px 16px;
}
"""

# Dark Theme Variant
DARK_THEME = """
QWidget {
    background-color: #141414;
    color: #f0f0f0;
}

QMainWindow {
    background-color: #141414;
}

QFrame, QGroupBox, QListWidget, QTableWidget, QTextBrowser {
    background-color: #1f1f1f;
    border-color: #333333;
}

QPushButton {
    background-color: #1890ff;
    border: none;
}

QPushButton:hover {
    background-color: #40a9ff;
}

QPushButton[class="secondary"] {
    background-color: #1f1f1f;
    border: 1px solid #434343;
    color: #f0f0f0;
}

QPushButton[class="secondary"]:hover {
    border-color: #40a9ff;
    color: #40a9ff;
}

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
    background-color: #1f1f1f;
    border: 1px solid #434343;
    color: #f0f0f0;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border-color: #40a9ff;
}

QTableWidget::item:selected {
    background-color: #1f1f1f;
    color: #40a9ff;
}

QHeaderView::section {
    background-color: #1f1f1f;
    border-bottom-color: #434343;
    color: #8c8c8c;
}

QListWidget::item:selected {
    background-color: #1f1f1f;
    color: #40a9ff;
}

QTabBar::tab {
    border-color: #434343;
    color: #8c8c8c;
}

QTabBar::tab:selected {
    background-color: #1f1f1f;
    color: #40a9ff;
}

QLabel {
    color: #f0f0f0;
}

QLabel[class="subtitle"], QLabel[class="caption"] {
    color: #8c8c8c;
}

QCheckBox {
    color: #f0f0f0;
}

QCheckBox::indicator {
    background-color: #1f1f1f;
    border-color: #434343;
}

QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background-color: #434343;
}

QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
    background-color: #595959;
}

QStatusBar, QMenuBar {
    background-color: #1f1f1f;
    border-color: #434343;
    color: #f0f0f0;
}
"""