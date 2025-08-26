# -*- coding: utf-8 -*-
"""
PyQt6 호환 간단한 UI 컴포넌트들
"""

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

class Card(QFrame):
    """간단한 카드 컴포넌트"""
    def __init__(self, title="", padding=24, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            Card {
                background-color: white;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
                margin: 4px;
            }
        """)
        
        self.layout = QVBoxLayout(self)
        if title:
            title_label = QLabel(title)
            title_label.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 8px;")
            self.layout.addWidget(title_label)
    
    def add_widget(self, widget):
        """위젯 추가"""
        self.layout.addWidget(widget)
    
    def add_layout(self, layout):
        """레이아웃 추가"""
        self.layout.addLayout(layout)

class PrimaryButton(QPushButton):
    """기본 버튼"""
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QPushButton {
                background-color: #1890ff;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #40a9ff;
            }
        """)

class SecondaryButton(QPushButton):
    """보조 버튼"""
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QPushButton {
                background-color: #f5f5f5;
                color: #595959;
                border: 1px solid #d9d9d9;
                border-radius: 6px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #fafafa;
            }
        """)

class SearchInput(QLineEdit):
    """검색 입력창"""
    searchChanged = pyqtSignal(str)
    
    def __init__(self, placeholder="검색...", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setStyleSheet("""
            QLineEdit {
                border: 1px solid #d9d9d9;
                border-radius: 6px;
                padding: 8px 12px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #1890ff;
            }
        """)
        self.textChanged.connect(self.searchChanged.emit)

class ModernTable(QTableWidget):
    """현대적 테이블"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QTableWidget {
                gridline-color: #f0f0f0;
                background-color: white;
                selection-background-color: #e6f7ff;
            }
            QHeaderView::section {
                background-color: #fafafa;
                border: 1px solid #f0f0f0;
                padding: 8px;
                font-weight: 500;
            }
        """)

class StatusBadge(QLabel):
    """상태 뱃지"""
    def __init__(self, text="", status="default", parent=None):
        super().__init__(text, parent)
        colors = {
            "success": "#52c41a",
            "warning": "#faad14", 
            "error": "#ff4d4f",
            "default": "#d9d9d9"
        }
        color = colors.get(status, colors["default"])
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {color};
                color: white;
                border-radius: 4px;
                padding: 2px 8px;
                font-size: 12px;
            }}
        """)

class SidebarList(QListWidget):
    """사이드바 리스트"""
    def __init__(self, parent=None):
        super().__init__(parent)

class Divider(QFrame):
    """구분선"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: #f0f0f0; max-height: 1px;")

class MetricCard(Card):
    """메트릭 카드"""
    def __init__(self, title="", value="", parent=None):
        super().__init__(parent=parent)

class EmptyState(QWidget):
    """빈 상태"""
    def __init__(self, parent=None):
        super().__init__(parent)

class LoadingSpinner(QLabel):
    """로딩 스피너"""
    def __init__(self, parent=None):
        super().__init__("로딩 중...", parent)

class ProgressCard(Card):
    """진행률 카드"""
    def __init__(self, parent=None):
        super().__init__(parent=parent)
