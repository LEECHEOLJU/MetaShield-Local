import os
import sys
from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, pyqtSlot, QMetaObject, Q_ARG
from PyQt6.QtGui import QFont, QPalette

from modern_ui_style import MODERN_STYLE, DARK_THEME
from advanced_ui_components import Card, ActionButton, SearchInput, ModernTable, SidebarList, Divider, PrimaryButton, SecondaryButton
from enterprise_ui_components import TopNavigationBar, SideNavigationPanel, EnterpriseDashboard

from nvd_cve_checker_Pro import CVEApp 
from pattern_dict_tab import PatternDictTab
from guide_tab import GuideTab
from comprehensive_report import ComprehensiveReportGenerator, ComprehensiveReportDialog
from advanced_ioc_analyzer import AdvancedIOCTab
from yara_rule_generator import YaraGeneratorTab
from malware_static_analyzer import MalwareAnalysisTab
from threat_hunting_query_generator import ThreatHuntingTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ MetaShield | 엔터프라이즈 보안 플랫폼")
        self.resize(1600, 900)
        
        # PyQt6 자동 다크모드 감지 및 적용
        self.apply_adaptive_theme()
        
        # Apply modern clean styling
        self.setStyleSheet(MODERN_STYLE)
        
        # Set modern window properties
        self.setMinimumSize(1400, 900)
        self.setWindowFlags(Qt.WindowType.Window)
        
        # ⭐ 새로운 엔터프라이즈 UI 구조
        self.setup_enterprise_ui()
        
        # 기존 위젯들 초기화
        self.init_content_widgets()
        
        # 기본 탭 설정
        self.show_content("보안분석", "ai_analysis")
        
    def setup_enterprise_ui(self):
        """엔터프라이즈급 3단 네비게이션 UI 구성"""
        # 중앙 위젯
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 메인 레이아웃 - 세로 배치
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 1. 상단 네비게이션 바
        self.top_nav = TopNavigationBar()
        self.top_nav.tabChanged.connect(self.on_main_tab_changed)
        main_layout.addWidget(self.top_nav)
        
        # 2. 콘텐츠 영역 - 수평 분할
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        content_splitter.setHandleWidth(1)  # 옆은 구분선
        
        # 2-1. 좌측 사이드 네비게이션
        self.side_nav = SideNavigationPanel()
        self.side_nav.subTabChanged.connect(self.on_sub_tab_changed)
        content_splitter.addWidget(self.side_nav)
        
        # 2-2. 메인 콘텐츠 영역
        self.content_area = QStackedWidget()
        self.content_area.setStyleSheet("""
            QStackedWidget {
                background-color: white;
                border: none;
            }
        """)
        content_splitter.addWidget(self.content_area)
        
        # 초기 비율 설정 - 좌측 최소화, 메인 최대화
        content_splitter.setSizes([280, 1320])
        content_splitter.setCollapsible(0, False)  # 좌측 패널 접기 방지
        
        main_layout.addWidget(content_splitter)
        
        # 초기 사이드 내비게이션 설정
        self.side_nav.update_sub_tabs("보안분석")
    
    def init_content_widgets(self):
        """콘텐츠 위젯들 초기화"""
        self.content_widgets = {}
        
        # 보안분석 콘텐츠들
        self.content_widgets["ai_analysis"] = self.create_styled_analysis_tab()
        self.content_widgets["vulnerability_search"] = CVEApp()
        self.content_widgets["pattern_repository"] = PatternDictTab()
        
        # 실험실 콘텐츠들
        self.content_widgets["advanced_ioc"] = AdvancedIOCTab()
        self.content_widgets["yara_generator"] = YaraGeneratorTab()
        self.content_widgets["malware_analysis"] = MalwareAnalysisTab()
        self.content_widgets["threat_hunting"] = ThreatHuntingTab()
        
        # 사용가이드 콘텐츠
        self.content_widgets["guide"] = GuideTab("", "사용자 가이드")
        
        # 관제 고객사 콘텐츠들 - 빈 대시보드
        for company in ["dashboard", "goodrich", "kurly", "finda", "gln", "hanwha"]:
            self.content_widgets[company] = EnterpriseDashboard(company)
        
        # 모든 위젯들을 스택 위젯에 추가
        for widget in self.content_widgets.values():
            self.content_area.addWidget(widget)
    
    def on_main_tab_changed(self, main_tab):
        """대분류 탭 변경 이벤트"""
        # 사이드 내비게이션 업데이트
        self.side_nav.update_sub_tabs(main_tab)
        
        # 매칭되는 콘텐츠 표시
        if main_tab == "보안분석":
            self.show_content(main_tab, "ai_analysis")
        elif main_tab == "실험실":
            self.show_content(main_tab, "advanced_ioc")
        elif main_tab == "관제 고객사":
            self.show_content(main_tab, "dashboard")
        elif main_tab == "사용가이드":
            self.show_content(main_tab, "guide")
    
    def on_sub_tab_changed(self, main_tab, sub_tab):
        """세부 탭 변경 이벤트"""
        self.show_content(main_tab, sub_tab)
    
    def show_content(self, main_tab, sub_tab):
        """지정된 콘텐츠 표시"""
        if sub_tab in self.content_widgets:
            widget = self.content_widgets[sub_tab]
            self.content_area.setCurrentWidget(widget)
            
            # 디버깅 정보
            print(f"[UI] Switched to: {main_tab} > {sub_tab}")
    
    def create_modern_header(self):
        """Create modern clean header"""
        header = QFrame()
        header.setFixedHeight(64)
        header.setStyleSheet("""
            QFrame {
                background-color: white;
                border-bottom: 1px solid #f0f0f0;
            }
        """)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(16)
        
        # App logo/icon and title
        title_layout = QHBoxLayout()
        title_layout.setSpacing(12)
        
        # Logo (you can replace with actual logo)
        logo = QLabel("🛡️")
        logo.setStyleSheet("font-size: 24px;")
        title_layout.addWidget(logo)
        
        # Title
        title = QLabel("MetaShield")
        title.setProperty("class", "title")
        title.setStyleSheet("""
            QLabel {
                color: #262626;
                font-size: 22px;
                font-weight: 700;
            }
        """)
        title_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("보안 분석 플랫폼")
        subtitle.setProperty("class", "subtitle")
        subtitle.setStyleSheet("""
            QLabel {
                color: #8c8c8c;
                font-size: 14px;
                font-weight: 400;
            }
        """)
        title_layout.addWidget(subtitle)
        
        layout.addLayout(title_layout)
        layout.addStretch()
        
        return header
    
    def apply_adaptive_theme(self):
        """PyQt6 자동 다크모드 감지 및 테마 적용"""
        palette = self.palette()
        is_dark_mode = palette.color(QPalette.ColorRole.Window).lightness() < 128
        
        if is_dark_mode:
            # 다크모드 감지 시 DARK_THEME 적용
            self.setStyleSheet(DARK_THEME)
            # 상태바에 다크모드 표시
            if hasattr(self, 'statusBar'):
                self.statusBar().showMessage("🌙 다크모드 자동 적용됨")
        else:
            # 라이트모드는 기본 MODERN_STYLE 사용
            if hasattr(self, 'statusBar'):
                self.statusBar().showMessage("☀️ 라이트모드 적용됨")
    
    def create_styled_analysis_tab(self):
        """Create modern analysis tab"""
        return ModernAnalysisTab()


class ModernAnalysisTab(QWidget):
    """Modern clean analysis tab with card-based layout"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the modern UI layout with optimized spacing - 요구사항: 상단 탭형식 옵션 추가"""
        from config import get_ui_config
        ui_config = get_ui_config()
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(ui_config.tab_margin, ui_config.tab_margin, ui_config.tab_margin, ui_config.tab_margin)
        main_layout.setSpacing(ui_config.section_spacing)
        
        # 메인 콘텐츠 영역 - 가로 반반 분할 (요구사항)
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        content_splitter.setHandleWidth(8)
        
        # Left panel - Input and controls
        left_panel = self.create_input_panel()
        content_splitter.addWidget(left_panel)
        
        # Right panel - Results and analysis
        right_panel = self.create_results_panel()
        content_splitter.addWidget(right_panel)
        
        # 화면 가로를 반반으로 나눔 (요구사항)
        content_splitter.setSizes([700, 700])  # 반반 분할
        
        main_layout.addWidget(content_splitter)
        self.setLayout(main_layout)
    
    def create_input_panel(self):
        """Create the input panel with payload input and controls"""
        from config import get_ui_config
        ui_config = get_ui_config()
        
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, ui_config.card_padding, 0)
        layout.setSpacing(ui_config.section_spacing)
        
        # Input card
        input_card = Card("페이로드 입력")
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("여기에 페이로드 또는 보안 이벤트 데이터를 입력하세요...\n\n지원되는 형식:\n• HTTP 요청\n• 로그 항목\n• 네트워크 트래픽\n• 파일 해시")
        self.input_text.setMinimumHeight(500)  # 페이로드 입력칸 크게 (요구사항)
        input_card.add_widget(self.input_text)
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(ui_config.button_spacing)
        
        self.analyze_btn = PrimaryButton("🧠 분석")
        self.analyze_btn.clicked.connect(self.run_analysis)
        
        self.clear_btn = SecondaryButton("지우기")
        self.clear_btn.clicked.connect(self.clear_input)
        
        button_layout.addWidget(self.analyze_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addStretch()
        
        input_card.add_layout(button_layout)
        
        # Analysis options card
        options_card = Card("분석 옵션")
        
        # Checkboxes for analysis options
        self.threat_intel_cb = QCheckBox("위협 인텔리전스 조회")
        self.threat_intel_cb.setChecked(True)
        
        self.ioc_extract_cb = QCheckBox("IOC 추출")
        self.ioc_extract_cb.setChecked(True)
        
        self.cve_lookup_cb = QCheckBox("CVE 데이터베이스 조회")
        self.cve_lookup_cb.setChecked(True)
        
        options_card.add_widget(self.threat_intel_cb)
        options_card.add_widget(self.ioc_extract_cb)
        options_card.add_widget(self.cve_lookup_cb)
        
        # Add divider
        divider = Divider()
        
        # Generate report button
        self.report_btn = SecondaryButton("📊 보고서 생성")
        self.report_btn.clicked.connect(self.generate_comprehensive_report)
        self.report_btn.setEnabled(False)  # Enable after analysis
        
        layout.addWidget(input_card)
        layout.addWidget(options_card)
        layout.addWidget(divider)
        layout.addWidget(self.report_btn)
        layout.addStretch()
        
        return panel
    
    def create_results_panel(self):
        """Create the results panel with tabbed analysis results"""
        from config import get_ui_config
        ui_config = get_ui_config()
        
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(ui_config.card_padding, 0, 0, 0)
        layout.setSpacing(ui_config.section_spacing)
        
        # Results card with tabs
        results_card = Card("분석 결과")
        
        # Create tab widget for different result types
        self.results_tabs = QTabWidget()
        
        # AI 분석 결과 탭 - 크게 (요구사항)
        self.ai_results = QTextBrowser()
        self.ai_results.setPlaceholderText("AI 분석 결과가 여기에 표시됩니다...")
        self.ai_results.setMinimumHeight(500)  # 분석결과 크게
        self.results_tabs.addTab(self.ai_results, "AI 분석")
        
        # IOC 결과 탭 - 크게 (요구사항)
        self.ioc_results = QTextBrowser()
        self.ioc_results.setPlaceholderText("추출된 IOC가 여기에 표시됩니다...")
        self.ioc_results.setMinimumHeight(500)
        self.results_tabs.addTab(self.ioc_results, "IOCs")
        
        # 위협 인텔리전스 탭 - 크게 (요구사항)
        self.threat_results = QTextBrowser()
        self.threat_results.setPlaceholderText("위협 인텔리전스 데이터가 여기에 표시됩니다...")
        self.threat_results.setMinimumHeight(500)
        self.results_tabs.addTab(self.threat_results, "위협 인텔리전스")
        
        results_card.add_widget(self.results_tabs)
        
        layout.addWidget(results_card)
        
        return panel
    
    def clear_input(self):
        """Clear the input field"""
        self.input_text.clear()
        self.ai_results.clear()
        self.ioc_results.clear()
        self.threat_results.clear()
        self.report_btn.setEnabled(False)
    
    def run_analysis(self):
        """Run the security analysis - simplified version"""
        payload = self.input_text.toPlainText().strip()
        if not payload:
            QMessageBox.warning(self, "입력 필요", "분석할 페이로드 데이터를 입력해주세요.")
            return
        
        # 간단한 진행 표시
        progress = QProgressDialog("AI 분석을 진행하고 있습니다...", "취소", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(500)
        progress.show()
        
        try:
            # IOC 추출
            progress.setLabelText("IOC 추출 중...")
            progress.setValue(20)
            QApplication.processEvents()
            
            ioc_data = {}
            if self.ioc_extract_cb.isChecked():
                ioc_data = self.extract_iocs_from_text(payload)
                self.display_ioc_results(ioc_data)
            
            # AI 분석
            progress.setLabelText("AI 분석 중...")
            progress.setValue(50)
            QApplication.processEvents()
            
            ai_result = self.perform_ai_analysis(payload)
            self.ai_results.setPlainText(ai_result)
            
            # 위협 인텔리전스
            if self.threat_intel_cb.isChecked():
                progress.setLabelText("위협 인텔리전스 조회 중...")
                progress.setValue(80)
                QApplication.processEvents()
                
                threat_data = self.query_threat_feeds(ioc_data)
                self.threat_results.setHtml(threat_data)
            
            # 완료
            progress.setValue(100)
            self.report_btn.setEnabled(True)
            
        except Exception as e:
            QMessageBox.critical(self, "분석 오류", f"분석 중 오류가 발생했습니다:\n{str(e)}")
            
        finally:
            progress.close()
    
    
    def perform_ai_analysis(self, payload):
        """통합된 AI 분석 실행 - config와 prompts 모듈 사용"""
        from config import get_ai_config
        from prompts import SecurityPrompts, PromptConfig, get_prompt_by_input_type
        
        # 설정 로드
        ai_config = get_ai_config()
        if not ai_config.is_valid():
            return "❌ AI 설정이 유효하지 않습니다. config.py를 확인해주세요."
        
        # 입력 타입에 따른 적절한 프롬프트 선택
        input_type, prompt = get_prompt_by_input_type(payload)
        
        try:
            from openai import AzureOpenAI
            client = AzureOpenAI(
                api_key=ai_config.api_key,
                api_version=ai_config.api_version,
                azure_endpoint=ai_config.endpoint,
            )
            response = client.chat.completions.create(
                model=ai_config.deployment,
                messages=[
                    {"role": "system", "content": SecurityPrompts.get_system_message()},
                    {"role": "user", "content": prompt}
                ],
                temperature=PromptConfig.TEMPERATURE,
                max_completion_tokens=PromptConfig.MAX_COMPLETION_TOKENS,
                top_p=PromptConfig.TOP_P,
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI 분석 오류: {str(e)}"
    
    def extract_iocs_from_text(self, text):
        """텍스트에서 IOC 추출 - 고도화된 정규식 사용"""
        import re
        import ipaddress
        
        iocs = {
            "ips": [],
            "domains": [], 
            "urls": [],
            "hashes": [],
            "emails": []
        }
        
        # 개선된 IP 주소 추출 (유효한 공인 IP만)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        
        for ip in potential_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                # 공인 IP만 추출 (사설IP, 루프백, 멀티캐스트 제외)
                if not (ip_obj.is_private or ip_obj.is_loopback or 
                    ip_obj.is_multicast or ip_obj.is_reserved):
                    if ip not in iocs["ips"]:
                        iocs["ips"].append(ip)
            except ValueError:
                continue  # 유효하지 않은 IP 제외
        
        # 개선된 도메인 추출 (실제 도메인만)
        domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)\b'
        potential_domains = re.findall(domain_pattern, text.lower())
        
        # 제외할 확장자/패턴
        exclude_patterns = [r'\.exe$', r'\.dll$', r'\.pdf$', r'\.doc$', r'\.zip$', 
                        r'\.jpg$', r'\.png$', r'\.txt$', r'\.log$', r'^\d+\.\d+$']
        
        for domain in potential_domains:
            if len(domain.split('.')[0]) > 1:  # 첫 번째 부분이 2글자 이상
                if not any(re.search(pattern, domain) for pattern in exclude_patterns):
                    if domain not in iocs["domains"]:
                        iocs["domains"].append(domain)
        
        # 개선된 URL 추출
        url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        potential_urls = re.findall(url_pattern, text)
        
        for url in potential_urls:
            if len(url) > 10 and url not in iocs["urls"]:  # 너무 짧은 URL 제외
                iocs["urls"].append(url)
        
        # 개선된 해시값 추출 (16진수 검증)
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b', 
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        
        for hash_type, pattern in hash_patterns.items():
            potential_hashes = re.findall(pattern, text)
            for hash_val in potential_hashes:
                # 실제 16진수인지 검증
                try:
                    int(hash_val, 16)
                    if hash_val.lower() not in [h.lower() for h in iocs["hashes"]]:
                        iocs["hashes"].append(hash_val.lower())
                except ValueError:
                    continue
        
        # 개선된 이메일 추출
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        potential_emails = re.findall(email_pattern, text)
        
        # 일반적인 테스트/예시 이메일 제외
        exclude_emails = ['test@test.com', 'user@example.com', 'admin@localhost']
        
        for email in potential_emails:
            if email.lower() not in exclude_emails and email not in iocs["emails"]:
                iocs["emails"].append(email.lower())
        
        return iocs
    
    def display_ioc_results(self, ioc_data):
        """Display IOC extraction results in a clean format"""
        if not any(ioc_data.values()):
            self.ioc_results.setPlainText("🔍 페이로드에서 IOC를 찾을 수 없습니다.")
            return
        
        result_text = "🎯 **추출된 침해 지표(IOCs)**\n\n"
        
        if ioc_data.get('ips'):
            result_text += f"🌐 **IP 주소 ({len(ioc_data['ips'])}):**\n"
            for ip in ioc_data['ips'][:10]:  # Limit display
                result_text += f"  • {ip}\n"
            result_text += "\n"
        
        if ioc_data.get('domains'):
            result_text += f"🔗 **도메인 ({len(ioc_data['domains'])}):**\n"
            for domain in ioc_data['domains'][:10]:
                result_text += f"  • {domain}\n"
            result_text += "\n"
        
        if ioc_data.get('urls'):
            result_text += f"🔗 **URL ({len(ioc_data['urls'])}):**\n"
            for url in ioc_data['urls'][:5]:
                result_text += f"  • {url}\n"
            result_text += "\n"
        
        if ioc_data.get('hashes'):
            result_text += f"🔐 **파일 해시 ({len(ioc_data['hashes'])}):**\n"
            for hash_val in ioc_data['hashes']:
                result_text += f"  • {hash_val}\n"
            result_text += "\n"
        
        if ioc_data.get('emails'):
            result_text += f"📧 **이메일 ({len(ioc_data['emails'])}):**\n"
            for email in ioc_data['emails']:
                result_text += f"  • {email}\n"
            result_text += "\n"
        
        self.ioc_results.setPlainText(result_text)
    
    def query_threat_feeds(self, iocs):
        """위협 피드 조회 - 고도화된 결과 분석"""
        
        results_html = "<h3>🔍 위협 인텔리전스 조회 결과</h3>"
        
        # IOC 통계
        total_iocs = sum(len(v) for v in iocs.values())
        if total_iocs == 0:
            return "<div>❌ 추출된 IOC가 없습니다.</div>"
        
        # VirusTotal API 조회 
        vt_results = self.query_virustotal(iocs)
        
        # AbuseIPDB 조회 
        abuse_results = self.query_abuseipdb(iocs)
        
        # 개선된 결과 통합
        results_html += f"""
        <h4>📊 탐지된 IOC 현황</h4>
        <div style='background:#f8f9fa;padding:10px;border-left:4px solid #007bff;'>
            <ul style='margin:0;'>
                <li>🌐 <b>IP 주소:</b> {len(iocs['ips'])}개 (공인 IP만)</li>
                <li>🔗 <b>도메인:</b> {len(iocs['domains'])}개 (유효한 도메인만)</li>
                <li>📎 <b>URL:</b> {len(iocs['urls'])}개</li>
                <li>🔐 <b>해시값:</b> {len(iocs['hashes'])}개 (MD5/SHA1/SHA256)</li>
                <li>📧 <b>이메일:</b> {len(iocs['emails'])}개</li>
            </ul>
        </div>
        
        <h4>🚨 위험도 평가</h4>
        {vt_results}
        {abuse_results}
        
        <h4>💡 권고사항</h4>
        <div style='background:#e8f5e8;padding:10px;border-left:4px solid #28a745;'>
            <b>즉시 조치:</b><br>
            ✅ 위험도가 높은 IOC에 대한 방화벽/프록시 차단 정책 적용<br>
            ✅ 엔드포인트 보안 솔루션 IOC 업데이트<br>
            ✅ SIEM/로그 분석 시스템에서 해당 IOC 검색<br><br>
            
            <b>추가 분석:</b><br>
            🔍 관련 네트워크 트래픽 패턴 분석<br>
            🔍 동일 출발지에서 발생한 다른 보안 이벤트 검색<br>
            🔍 조직 내부 감염 여부 확인
        </div>
        """
        
        return results_html

    def query_virustotal(self, iocs):
        """VirusTotal API v3 사용 - config에서 설정 로드"""
        from config import get_threat_intel_config
        
        try:
            threat_config = get_threat_intel_config()
            vt_api_key = threat_config.virustotal_api_key
            
            if not vt_api_key or len(vt_api_key) < 20:
                return "<div style='color:#dc3545;'>⚠️ VirusTotal API 키가 올바르지 않습니다.</div>"
            
            import requests
            import time
            
            results = "<h5>🦠 VirusTotal 분석 결과</h5><div style='margin-left:20px;'>"
            
            # IP 주소 조회 (API v3 사용)
            for i, ip in enumerate(iocs["ips"][:5]):  # 무료 계정 제한
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": vt_api_key}
                
                try:
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        attributes = data.get("data", {}).get("attributes", {})
                        
                        # 악성 판정 통계
                        stats = attributes.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        total_engines = sum(stats.values()) if stats else 0
                        
                        # 위험도 분류
                        if malicious > 0:
                            risk_icon = "🔴"
                            risk_text = f"위험 ({malicious}개 엔진 탐지)"
                        elif suspicious > 0:
                            risk_icon = "🟡"  
                            risk_text = f"의심 ({suspicious}개 엔진 의심)"
                        else:
                            risk_icon = "🟢"
                            risk_text = "정상"
                        
                        # 추가 정보
                        country = attributes.get("country", "알 수 없음")
                        asn = attributes.get("as_owner", "알 수 없음")
                        
                        results += f"""
                        <div style='border:1px solid #ddd;padding:8px;margin:4px 0;'>
                            <b>{risk_icon} {ip}</b> - {risk_text}<br>
                            <small>국가: {country} | ASN: {asn[:50]}...</small><br>
                            <small>분석 엔진: {malicious + suspicious}/{total_engines}개 탐지</small>
                        </div>
                        """
                        
                    elif response.status_code == 404:
                        results += f"<div>🔵 {ip}: 정보 없음</div>"
                    else:
                        results += f"<div>❌ {ip}: 조회 실패 (코드: {response.status_code})</div>"
                        
                except requests.RequestException as e:
                    results += f"<div>❌ {ip}: 네트워크 오류</div>"
                
                # API 제한 준수 (무료: 4 requests/min)
                if i < len(iocs["ips"][:5]) - 1:
                    time.sleep(15)
            
            results += "</div>"
            return results
            
        except Exception as e:
            return f"<div style='color:#dc3545;'>VirusTotal 조회 오류: {str(e)}</div>"

    def query_abuseipdb(self, iocs):
        """AbuseIPDB API 조회 - config에서 설정 로드"""
        from config import get_threat_intel_config
        
        try:
            threat_config = get_threat_intel_config()
            abuse_api_key = threat_config.abuseipdb_api_key
            
            if not abuse_api_key or len(abuse_api_key) < 20:
                return "<div style='color:#dc3545;'>⚠️ AbuseIPDB API 키가 올바르지 않습니다.</div>"
            
            import requests
            
            results = "<h5>🚫 AbuseIPDB 분석 결과</h5><div style='margin-left:20px;'>"
            
            for ip in iocs["ips"][:10]:  # 무료 계정 제한
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": abuse_api_key,
                    "Accept": "application/json"
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": ""
                }
                
                try:
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json().get("data", {})
                        confidence = data.get("abuseConfidencePercentage", 0)
                        usage_type = data.get("usageType", "알 수 없음")
                        country = data.get("countryCode", "알 수 없음")
                        isp = data.get("isp", "알 수 없음")
                        total_reports = data.get("totalReports", 0)
                        
                        # 정확한 위험도 분류
                        if confidence >= 75:
                            risk_icon = "🔴"
                            risk_text = f"고위험 (신뢰도: {confidence}%)"
                        elif confidence >= 25:
                            risk_icon = "🟡"
                            risk_text = f"중위험 (신뢰도: {confidence}%)"  
                        else:
                            risk_icon = "🟢"
                            risk_text = f"저위험 (신뢰도: {confidence}%)"
                        
                        results += f"""
                        <div style='border:1px solid #ddd;padding:8px;margin:4px 0;'>
                            <b>{risk_icon} {ip}</b> - {risk_text}<br>
                            <small>국가: {country} | ISP: {isp[:30]}...</small><br>
                            <small>용도: {usage_type} | 신고 횟수: {total_reports}건</small>
                        </div>
                        """
                        
                    else:
                        results += f"<div>❌ {ip}: 조회 실패 (코드: {response.status_code})</div>"
                        
                except requests.RequestException:
                    results += f"<div>❌ {ip}: 네트워크 오류</div>"
            
            results += "</div>"
            return results
            
        except Exception as e:
            return f"<div style='color:#dc3545;'>AbuseIPDB 조회 오류: {str(e)}</div>"
    
    def generate_comprehensive_report(self):
        """Generate comprehensive analysis report"""
        try:
            from comprehensive_report import ComprehensiveReportGenerator, ComprehensiveReportDialog
            
            payload = self.input_text.toPlainText().strip()
            if not payload:
                QMessageBox.warning(self, "입력 필요", "먼저 분석을 실행해주세요.")
                return
            
            # Collect all analysis results
            ai_analysis = self.ai_results.toPlainText()
            ioc_data = self.extract_iocs_from_text(payload)
            threat_intel = self.threat_results.toHtml()
            
            # Generate report
            report_generator = ComprehensiveReportGenerator()
            final_report = report_generator.generate_comprehensive_report(
                payload=payload,
                ai_analysis=ai_analysis,
                ioc_data=ioc_data,
                threat_intel_data=threat_intel
            )
            
            # Show report dialog
            dialog = ComprehensiveReportDialog(final_report, self)
            dialog.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "보고서 오류", f"보고서 생성에 실패했습니다:\n{str(e)}")

    def create_yara_generator_tab(self):
        """YARA 룰 생성 탭 (플레이스홀더)"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # 제목
        title = QLabel("🎯 YARA 룰 자동 생성")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #1890ff;
                padding: 12px 0;
            }
        """)
        layout.addWidget(title)
        
        # 설명
        description = QLabel("""
        <h3>🚧 개발 예정 기능</h3>
        <p>다음 기능들을 구현할 예정입니다:</p>
        <ul>
        <li>🧬 멀웨어 샘플 기반 YARA 룰 자동 생성</li>
        <li>🎯 AI 기반 패턴 식별 및 룰 최적화</li>
        <li>🧪 YARA 룰 테스트 및 검증 환경</li>
        <li>📊 룰 성능 및 오탐률 평가</li>
        <li>📚 룰 라이브러리 관리</li>
        </ul>
        """)
        description.setStyleSheet("QLabel { font-size: 14px; }")
        layout.addWidget(description)
        
        layout.addStretch()
        return tab

    def create_malware_analysis_tab(self):
        """멀웨어 정적 분석 탭 (플레이스홀더)"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # 제목
        title = QLabel("🔍 멀웨어 정적 분석")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #1890ff;
                padding: 12px 0;
            }
        """)
        layout.addWidget(title)
        
        # 설명
        description = QLabel("""
        <h3>🚧 개발 예정 기능</h3>
        <p>다음 기능들을 구현할 예정입니다:</p>
        <ul>
        <li>📁 PE/ELF 파일 헤더 분석</li>
        <li>📋 Import/Export Table 분석</li>
        <li>🔤 문자열 추출 및 의심 패턴 탐지</li>
        <li>🔒 패킹/난독화 탐지</li>
        <li>🧬 엔트로피 분석</li>
        <li>📊 API 호출 패턴 분석</li>
        <li>🔗 라이브러리 의존성 분석</li>
        </ul>
        """)
        description.setStyleSheet("QLabel { font-size: 14px; }")
        layout.addWidget(description)
        
        layout.addStretch()
        return tab

    def create_threat_hunting_tab(self):
        """위협 헌팅 쿼리 생성 탭 (플레이스홀더)"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # 제목
        title = QLabel("🕵️ 위협 헌팅 쿼리 생성")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #1890ff;
                padding: 12px 0;
            }
        """)
        layout.addWidget(title)
        
        # 설명
        description = QLabel("""
        <h3>🚧 개발 예정 기능</h3>
        <p>다음 기능들을 구현할 예정입니다:</p>
        <ul>
        <li>🔍 IOC 기반 Splunk/ELK 쿼리 자동 생성</li>
        <li>📝 Sigma 룰 변환 및 최적화</li>
        <li>🎯 커스텀 탐지 룰 생성 마법사</li>
        <li>📊 쿼리 성능 최적화</li>
        <li>🔗 멀티 플랫폼 쿼리 호환성</li>
        <li>📚 헌팅 쿼리 라이브러리</li>
        <li>⚡ 실시간 쿼리 테스트</li>
        </ul>
        """)
        description.setStyleSheet("QLabel { font-size: 14px; }")
        layout.addWidget(description)
        
        layout.addStretch()
        return tab


# Legacy wrapper for backward compatibility
class StyledAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        modern_tab = ModernAnalysisTab()
        layout.addWidget(modern_tab)
        self.setLayout(layout)


if __name__ == "__main__":
    # 고해상도 지원
    from PyQt6.QtCore import Qt
    import sys
    from PyQt6.QtWidgets import QApplication

    # PyQt6에서는 자동으로 고해상도 지원이 활성화됨
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())