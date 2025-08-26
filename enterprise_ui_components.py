# Enterprise UI Components for MetaShield
# FortiOS/PaloAlto style navigation system

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

class TopNavigationBar(QWidget):
    """상단 대분류 탭 네비게이션 바 - FortiOS 스타일"""
    
    # 탭 변경 시그널
    tabChanged = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_tab = "보안분석"  # 기본 선택 탭
        self.tabs = {
            "보안분석": "🛡️ 보안분석",
            "실험실": "🧪 실험실",
            "관제 고객사": "🏢 관제 고객사", 
            "사용가이드": "📚 사용가이드"
        }
        self.tab_buttons = {}
        self.setup_ui()
        
    def setup_ui(self):
        """상단 네비게이션 바 UI 구성"""
        self.setFixedHeight(60)
        self.setStyleSheet('''
            TopNavigationBar {
                background-color: #ffffff;
                border-bottom: 2px solid #f0f0f0;
            }
        ''')
        
        # 메인 레이아웃
        layout = QHBoxLayout()
        layout.setContentsMargins(20, 8, 20, 8)
        layout.setSpacing(0)
        
        # MetaShield 로고 및 타이틀
        title_layout = QHBoxLayout()
        title_layout.setSpacing(12)
        
        # 로고 아이콘
        logo_label = QLabel("🛡️")
        logo_label.setStyleSheet('''
            QLabel {
                font-size: 24px;
                color: #1890ff;
            }
        ''')
        title_layout.addWidget(logo_label)
        
        # 타이틀
        title_label = QLabel("MetaShield")
        title_label.setStyleSheet('''
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #262626;
                padding: 0px 8px;
            }
        ''')
        title_layout.addWidget(title_label)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        # 탭 버튼들
        tab_layout = QHBoxLayout()
        tab_layout.setSpacing(4)
        
        for tab_key, tab_text in self.tabs.items():
            btn = self.create_tab_button(tab_key, tab_text)
            self.tab_buttons[tab_key] = btn
            tab_layout.addWidget(btn)
            
        layout.addLayout(tab_layout)
        layout.addStretch()
        
        # 우측 상태 정보 (나중에 추가 가능)
        status_layout = QHBoxLayout()
        
        # 현재 시간 표시
        time_label = QLabel()
        timer = QTimer()
        timer.timeout.connect(lambda: time_label.setText(
            QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm")
        ))
        timer.start(1000)  # 1초마다 업데이트
        time_label.setText(QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm"))
        time_label.setStyleSheet('''
            QLabel {
                color: #8c8c8c;
                font-size: 11px;
                padding: 4px 8px;
            }
        ''')
        status_layout.addWidget(time_label)
        
        layout.addLayout(status_layout)
        self.setLayout(layout)
        
        # 기본 탭 활성화
        self.set_active_tab("보안분석")
    
    def create_tab_button(self, tab_key, tab_text):
        """탭 버튼 생성"""
        btn = QPushButton(tab_text)
        btn.setMinimumSize(120, 44)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # 기본 스타일
        btn.setStyleSheet('''
            QPushButton {
                background-color: transparent;
                border: none;
                border-radius: 8px;
                color: #595959;
                font-size: 14px;
                font-weight: 500;
                padding: 8px 16px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #f5f5f5;
                color: #1890ff;
            }
        ''')
        
        btn.clicked.connect(lambda: self.on_tab_clicked(tab_key))
        return btn
    
    def on_tab_clicked(self, tab_key):
        """탭 클릭 이벤트 처리"""
        self.set_active_tab(tab_key)
        self.tabChanged.emit(tab_key)
    
    def set_active_tab(self, tab_key):
        """활성 탭 설정"""
        self.current_tab = tab_key
        
        # 모든 버튼 스타일 초기화
        for key, btn in self.tab_buttons.items():
            if key == tab_key:
                # 활성 탭 스타일
                btn.setStyleSheet('''
                    QPushButton {
                        background-color: #e6f7ff;
                        border: 2px solid #1890ff;
                        border-radius: 8px;
                        color: #1890ff;
                        font-size: 14px;
                        font-weight: bold;
                        padding: 8px 16px;
                        text-align: center;
                    }
                    QPushButton:hover {
                        background-color: #bae7ff;
                        border-color: #40a9ff;
                    }
                ''')
            else:
                # 비활성 탭 스타일
                btn.setStyleSheet('''
                    QPushButton {
                        background-color: transparent;
                        border: none;
                        border-radius: 8px;
                        color: #595959;
                        font-size: 14px;
                        font-weight: 500;
                        padding: 8px 16px;
                        text-align: center;
                    }
                    QPushButton:hover {
                        background-color: #f5f5f5;
                        color: #1890ff;
                    }
                ''')

class SideNavigationPanel(QWidget):
    """좌측 세부 탭 사이드 네비게이션 패널"""
    
    # 서브탭 변경 시그널  
    subTabChanged = pyqtSignal(str, str)  # (main_tab, sub_tab)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_main_tab = "보안분석"
        self.current_sub_tab = ""
        self.sub_tabs = {
            "보안분석": [
                ("ai_analysis", "🧠 AI 보안 분석"),
                ("vulnerability_search", "🔍 취약점 검색"),
                ("pattern_repository", "📚 패턴 저장소")
            ],
            "실험실": [
                ("advanced_ioc", "🧬 고급 IOC 분석"),
                ("yara_generator", "🎯 YARA 룰 생성"),
                ("malware_analysis", "🔍 멀웨어 정적분석"),
                ("threat_hunting", "🕵️ 위협헌팅 쿼리")
            ],
            "관제 고객사": [
                ("dashboard", "📊 통합 대시보드"),
                ("goodrich", "🏭 굿리치"),
                ("kurly", "🛒 컬리"),
                ("finda", "💳 핀다"),
                ("gln", "🚛 GLN"),
                ("hanwha", "🛡️ 한화시스템")
            ],
            "사용가이드": [
                ("guide", "📋 사용자 가이드")
            ]
        }
        self.sub_buttons = {}
        self.setup_ui()
        
    def setup_ui(self):
        """사이드 네비게이션 UI 구성"""
        self.setMinimumWidth(250)
        self.setMaximumWidth(320)
        self.setStyleSheet('''
            SideNavigationPanel {
                background-color: #fafafa;
                border-right: 1px solid #f0f0f0;
            }
        ''')
        
        # 메인 레이아웃
        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(16, 20, 16, 20)
        self.main_layout.setSpacing(8)
        
        # 현재 대분류 제목
        self.category_title = QLabel()
        self.category_title.setStyleSheet('''
            QLabel {
                color: #262626;
                font-size: 16px;
                font-weight: bold;
                padding: 12px 16px;
                background-color: white;
                border-radius: 8px;
                border: 1px solid #f0f0f0;
            }
        ''')
        self.main_layout.addWidget(self.category_title)
        
        # 구분선
        divider = QFrame()
        divider.setFrameStyle(QFrame.Shape.HLine)
        divider.setStyleSheet('''
            QFrame {
                border: none;
                background-color: #f0f0f0;
                max-height: 1px;
                margin: 8px 0;
            }
        ''')
        self.main_layout.addWidget(divider)
        
        # 서브탭 버튼 컨테이너
        self.button_container = QWidget()
        self.button_layout = QVBoxLayout(self.button_container)
        self.button_layout.setContentsMargins(0, 0, 0, 0)
        self.button_layout.setSpacing(4)
        
        self.main_layout.addWidget(self.button_container)
        self.main_layout.addStretch()
        
        self.setLayout(self.main_layout)
        
    def update_sub_tabs(self, main_tab):
        """메인 탭에 따라 서브탭 업데이트"""
        self.current_main_tab = main_tab
        
        # 기존 버튼들 제거
        for i in reversed(range(self.button_layout.count())):
            self.button_layout.itemAt(i).widget().setParent(None)
        self.sub_buttons.clear()
        
        # 카테고리 제목 업데이트  
        category_icons = {
            "보안분석": "🛡️",
            "실험실": "🧪",
            "관제 고객사": "🏢", 
            "사용가이드": "📚"
        }
        self.category_title.setText(f"{category_icons.get(main_tab, '📋')} {main_tab}")
        
        # 새로운 서브탭 버튼들 생성
        if main_tab in self.sub_tabs:
            for sub_key, sub_text in self.sub_tabs[main_tab]:
                btn = self.create_sub_button(sub_key, sub_text)
                self.sub_buttons[sub_key] = btn
                self.button_layout.addWidget(btn)
                
            # 첫 번째 서브탭을 기본으로 활성화
            if self.sub_tabs[main_tab]:
                first_sub_key = self.sub_tabs[main_tab][0][0]
                self.set_active_sub_tab(first_sub_key)
                
    def create_sub_button(self, sub_key, sub_text):
        """서브탭 버튼 생성"""
        btn = QPushButton(sub_text)
        btn.setMinimumHeight(40)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        
        btn.setStyleSheet('''
            QPushButton {
                background-color: white;
                border: 1px solid #f0f0f0;
                border-radius: 6px;
                color: #595959;
                font-size: 13px;
                font-weight: 500;
                padding: 8px 12px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #f0f8ff;
                border-color: #40a9ff;
                color: #1890ff;
            }
        ''')
        
        btn.clicked.connect(lambda: self.on_sub_tab_clicked(sub_key))
        return btn
    
    def on_sub_tab_clicked(self, sub_key):
        """서브탭 클릭 이벤트 처리"""
        self.set_active_sub_tab(sub_key)
        self.subTabChanged.emit(self.current_main_tab, sub_key)
        
    def set_active_sub_tab(self, sub_key):
        """활성 서브탭 설정"""
        self.current_sub_tab = sub_key
        
        # 모든 서브탭 버튼 스타일 업데이트
        for key, btn in self.sub_buttons.items():
            if key == sub_key:
                # 활성 서브탭 스타일
                btn.setStyleSheet('''
                    QPushButton {
                        background-color: #e6f7ff;
                        border: 2px solid #1890ff;
                        border-radius: 6px;
                        color: #1890ff;
                        font-size: 13px;
                        font-weight: bold;
                        padding: 8px 12px;
                        text-align: left;
                    }
                    QPushButton:hover {
                        background-color: #bae7ff;
                        border-color: #40a9ff;
                    }
                ''')
            else:
                # 비활성 서브탭 스타일
                btn.setStyleSheet('''
                    QPushButton {
                        background-color: white;
                        border: 1px solid #f0f0f0;
                        border-radius: 6px;
                        color: #595959;
                        font-size: 13px;
                        font-weight: 500;
                        padding: 8px 12px;
                        text-align: left;
                    }
                    QPushButton:hover {
                        background-color: #f0f8ff;
                        border-color: #40a9ff;
                        color: #1890ff;
                    }
                ''')

class EnterpriseDashboard(QWidget):
    """관제 고객사용 대시보드 템플릿"""
    
    def __init__(self, company_name="", parent=None):
        super().__init__(parent)
        self.company_name = company_name
        self.setup_ui()
        
    def setup_ui(self):
        """대시보드 UI 구성"""
        layout = QVBoxLayout()
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)
        
        # 헤더
        header_layout = QHBoxLayout()
        
        # 회사 아이콘과 제목
        if self.company_name == "dashboard":
            icon = "📊"
            title = "통합 대시보드"
        elif self.company_name == "goodrich":
            icon = "🏭"
            title = "굿리치 관제"
        elif self.company_name == "kurly":
            icon = "🛒"
            title = "컬리 관제"
        elif self.company_name == "finda":
            icon = "💳"  
            title = "핀다 관제"
        elif self.company_name == "gln":
            icon = "🚛"
            title = "GLN 관제"
        elif self.company_name == "hanwha":
            icon = "🛡️"
            title = "한화시스템 관제"
        else:
            icon = "🏢"
            title = "관제 대시보드"
            
        title_label = QLabel(f"{icon} {title}")
        title_label.setStyleSheet('''
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #262626;
                padding: 16px 0;
            }
        ''')
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        # 상태 표시
        status_label = QLabel("🟢 운영중")
        status_label.setStyleSheet('''
            QLabel {
                background-color: #f6ffed;
                color: #52c41a;
                font-size: 12px;
                font-weight: bold;
                padding: 6px 12px;
                border-radius: 12px;
                border: 1px solid #b7eb8f;
            }
        ''')
        header_layout.addWidget(status_label)
        
        layout.addLayout(header_layout)
        
        # 플레이스홀더 콘텐츠
        content_widget = QWidget()
        content_widget.setStyleSheet('''
            QWidget {
                background-color: white;
                border: 2px dashed #d9d9d9;
                border-radius: 12px;
            }
        ''')
        
        content_layout = QVBoxLayout(content_widget)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # 플레이스홀더 아이콘
        placeholder_icon = QLabel("🚧")
        placeholder_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_icon.setStyleSheet('''
            QLabel {
                font-size: 48px;
                margin: 40px 0 20px 0;
                color: #bfbfbf;
            }
        ''')
        content_layout.addWidget(placeholder_icon)
        
        # 플레이스홀더 텍스트
        placeholder_text = QLabel(f"{title} 기능 개발 예정")
        placeholder_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_text.setStyleSheet('''
            QLabel {
                font-size: 18px;
                color: #8c8c8c;
                margin-bottom: 12px;
            }
        ''')
        content_layout.addWidget(placeholder_text)
        
        placeholder_desc = QLabel("이 영역에 관제 대시보드, 모니터링 차트,\n알람 현황 등이 표시될 예정입니다.")
        placeholder_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_desc.setStyleSheet('''
            QLabel {
                font-size: 14px;
                color: #bfbfbf;
                line-height: 1.6;
            }
        ''')
        content_layout.addWidget(placeholder_desc)
        
        layout.addWidget(content_widget, 1)
        self.setLayout(layout)