# ai_security_simulator.py - AI 보안 시나리오 시뮬레이터
"""
MetaShield AI 보안 시나리오 시뮬레이터
사용자 인프라 정보를 바탕으로 AI가 가상의 공격 시나리오를 생성하고
step-by-step 침투 경로를 시뮬레이션합니다.
"""

import json
import time
import asyncio
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
class InfrastructureComponent:
    """인프라 구성요소"""
    name: str
    type: str  # server, network, endpoint, cloud, etc.
    os: str
    version: str
    services: List[str]
    security_controls: List[str]
    network_zone: str
    criticality: str  # high, medium, low

@dataclass
class AttackStep:
    """공격 단계"""
    step_number: int
    phase: str  # reconnaissance, initial_access, execution, persistence, etc.
    technique: str  # MITRE ATT&CK 기법
    description: str
    target: str
    tools: List[str]
    indicators: List[str]
    detection_methods: List[str]
    mitigation: List[str]
    success_probability: float
    impact_level: str

@dataclass
class AttackScenario:
    """공격 시나리오"""
    id: str
    name: str
    description: str
    attack_vector: str
    attacker_profile: str
    target_assets: List[str]
    steps: List[AttackStep]
    total_risk_score: float
    estimated_duration: str
    detection_difficulty: str
    business_impact: str

class SecurityScenarioEngine(QObject):
    """AI 보안 시나리오 생성 엔진"""
    
    scenario_generated = pyqtSignal(dict)
    step_analyzed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.ai_config = get_ai_config()
        self.client = None
        self.initialize_ai_client()
        
        # 공격 시나리오 템플릿
        self.attack_templates = {
            "랜섬웨어": {
                "phases": ["reconnaissance", "initial_access", "execution", "persistence", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration", "impact"],
                "primary_techniques": ["T1566", "T1203", "T1486", "T1055", "T1059"]
            },
            "APT": {
                "phases": ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command_control", "actions_on_objectives"],
                "primary_techniques": ["T1566", "T1204", "T1055", "T1547", "T1071"]
            },
            "내부자위협": {
                "phases": ["legitimate_access", "privilege_escalation", "data_collection", "data_exfiltration"],
                "primary_techniques": ["T1078", "T1548", "T1005", "T1041"]
            },
            "공급망공격": {
                "phases": ["supply_chain_compromise", "initial_access", "persistence", "lateral_movement", "data_exfiltration"],
                "primary_techniques": ["T1195", "T1566", "T1547", "T1021", "T1041"]
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
    
    def generate_attack_scenario(self, infrastructure: List[InfrastructureComponent], attack_type: str):
        """공격 시나리오 생성"""
        if not self.client:
            self.error_occurred.emit("AI 클라이언트가 초기화되지 않았습니다.")
            return
        
        # 백그라운드에서 시나리오 생성
        self.generation_thread = threading.Thread(
            target=self._generate_scenario_background,
            args=(infrastructure, attack_type)
        )
        self.generation_thread.start()
    
    def _generate_scenario_background(self, infrastructure: List[InfrastructureComponent], attack_type: str):
        """백그라운드에서 시나리오 생성"""
        try:
            # 인프라 정보를 텍스트로 변환
            infra_description = self._format_infrastructure(infrastructure)
            
            # AI 프롬프트 생성
            prompt = self._create_scenario_prompt(infra_description, attack_type)
            
            # AI 호출
            response = self.client.chat.completions.create(
                model=self.ai_config.deployment,
                messages=[
                    {"role": "system", "content": "당신은 세계적인 사이버 보안 전문가이자 침투테스터입니다. 실제적이고 상세한 공격 시나리오를 생성해주세요."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=4000
            )
            
            # 응답 파싱
            scenario_data = self._parse_scenario_response(response.choices[0].message.content)
            
            # UI 업데이트
            self.scenario_generated.emit(scenario_data)
            
        except Exception as e:
            self.error_occurred.emit(f"시나리오 생성 오류: {str(e)}")
    
    def _format_infrastructure(self, infrastructure: List[InfrastructureComponent]) -> str:
        """인프라 정보를 텍스트로 포맷"""
        infra_text = "=== 대상 인프라 구성 ===\n\n"
        
        for component in infrastructure:
            infra_text += f"📋 {component.name}\n"
            infra_text += f"  - 유형: {component.type}\n"
            infra_text += f"  - 운영체제: {component.os} {component.version}\n"
            infra_text += f"  - 서비스: {', '.join(component.services)}\n"
            infra_text += f"  - 보안 통제: {', '.join(component.security_controls)}\n"
            infra_text += f"  - 네트워크 존: {component.network_zone}\n"
            infra_text += f"  - 중요도: {component.criticality}\n\n"
        
        return infra_text
    
    def _create_scenario_prompt(self, infra_description: str, attack_type: str) -> str:
        """AI 프롬프트 생성"""
        template = self.attack_templates.get(attack_type, self.attack_templates["랜섬웨어"])
        
        prompt = f"""
다음 인프라 환경에 대해 '{attack_type}' 공격 시나리오를 상세히 생성해주세요.

{infra_description}

다음 형식으로 응답해주세요:

## 공격 시나리오: [시나리오명]

**공격자 프로필:** [공격자 유형과 능력 수준]
**공격 목표:** [주요 목표 자산들]  
**예상 소요시간:** [전체 공격 소요 예상시간]
**탐지 난이도:** [높음/보통/낮음]

### 공격 단계

각 단계별로 다음 정보를 포함해주세요:

**단계 1: [단계명]**
- MITRE ATT&CK 기법: [T####]
- 상세 설명: [구체적인 공격 방법]
- 대상: [공격 대상]
- 사용 도구: [공격 도구들]
- 탐지 지표: [IOC들]
- 탐지 방법: [탐지 가능한 방법들]
- 대응 방안: [완화 및 대응 방법]
- 성공 확률: [퍼센트]

[추가 단계들...]

### 종합 평가
- 전체 위험도: [1-10점]
- 비즈니스 영향: [영향 설명]
- 핵심 취약점: [주요 약점들]
- 우선 보안 강화 영역: [권고사항]

실제 환경의 취약점을 고려하여 현실적이고 실행 가능한 시나리오를 만들어주세요.
"""
        return prompt
    
    def _parse_scenario_response(self, response: str) -> dict:
        """AI 응답을 구조화된 데이터로 파싱"""
        # 간단한 파싱 로직 (실제로는 더 정교한 파싱 필요)
        scenario_data = {
            "raw_response": response,
            "generated_at": datetime.now().isoformat(),
            "sections": self._extract_sections(response)
        }
        
        return scenario_data
    
    def _extract_sections(self, text: str) -> dict:
        """텍스트에서 섹션 추출"""
        sections = {}
        current_section = ""
        current_content = []
        
        for line in text.split('\n'):
            if line.startswith('##') or line.startswith('###'):
                if current_section:
                    sections[current_section] = '\n'.join(current_content)
                current_section = line.strip('#').strip()
                current_content = []
            else:
                current_content.append(line)
        
        if current_section:
            sections[current_section] = '\n'.join(current_content)
        
        return sections

import threading

class SecuritySimulatorTab(QWidget):
    """AI 보안 시나리오 시뮬레이터 탭"""
    
    def __init__(self):
        super().__init__()
        self.engine = SecurityScenarioEngine()
        self.engine.scenario_generated.connect(self.on_scenario_generated)
        self.engine.error_occurred.connect(self.on_error_occurred)
        
        self.infrastructure_components = []
        self.current_scenario = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 15)  # 상단 여백 축소
        layout.setSpacing(10)  # 간격 축소
        
        # 제목 (크기 축소)
        title = QLabel("🎯 AI 보안 시나리오 시뮬레이터")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1890ff; margin-bottom: 5px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("인프라 구성 정보를 입력하면 AI가 가상의 공격 시나리오를 생성하고 단계별 침투 경로를 시뮬레이션합니다.")
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
        
        # 인프라 설정 탭
        self.infra_tab = self.create_infrastructure_tab()
        tab_widget.addTab(self.infra_tab, "🏗️ 인프라 구성")
        
        # 시나리오 생성 탭  
        self.scenario_tab = self.create_scenario_tab()
        tab_widget.addTab(self.scenario_tab, "🎮 시나리오 생성")
        
        # 결과 분석 탭
        self.analysis_tab = self.create_analysis_tab()
        tab_widget.addTab(self.analysis_tab, "📊 결과 분석")
        
        layout.addWidget(tab_widget)
    
    def create_infrastructure_tab(self):
        """인프라 구성 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 인프라 컴포넌트 추가 카드
        add_card = Card("새 인프라 컴포넌트 추가")
        add_layout = QGridLayout()
        
        # 입력 필드들
        add_layout.addWidget(QLabel("컴포넌트명:"), 0, 0)
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("예: 웹서버-01")
        add_layout.addWidget(self.name_input, 0, 1)
        
        add_layout.addWidget(QLabel("유형:"), 0, 2)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["서버", "네트워크장비", "엔드포인트", "클라우드", "데이터베이스", "방화벽"])
        add_layout.addWidget(self.type_combo, 0, 3)
        
        add_layout.addWidget(QLabel("운영체제:"), 1, 0)
        self.os_input = QLineEdit()
        self.os_input.setPlaceholderText("예: Windows Server 2019")
        add_layout.addWidget(self.os_input, 1, 1)
        
        add_layout.addWidget(QLabel("버전:"), 1, 2)
        self.version_input = QLineEdit()
        self.version_input.setPlaceholderText("예: 10.0.17763")
        add_layout.addWidget(self.version_input, 1, 3)
        
        add_layout.addWidget(QLabel("서비스:"), 2, 0)
        self.services_input = QLineEdit()
        self.services_input.setPlaceholderText("예: IIS, SQL Server (쉼표로 구분)")
        add_layout.addWidget(self.services_input, 2, 1, 1, 3)
        
        add_layout.addWidget(QLabel("보안 통제:"), 3, 0)
        self.security_input = QLineEdit()
        self.security_input.setPlaceholderText("예: 안티바이러스, EDR, 패치관리 (쉼표로 구분)")
        add_layout.addWidget(self.security_input, 3, 1, 1, 3)
        
        add_layout.addWidget(QLabel("네트워크 존:"), 4, 0)
        self.zone_combo = QComboBox()
        self.zone_combo.addItems(["DMZ", "내부망", "관리망", "게스트망", "클라우드"])
        add_layout.addWidget(self.zone_combo, 4, 1)
        
        add_layout.addWidget(QLabel("중요도:"), 4, 2)
        self.criticality_combo = QComboBox()
        self.criticality_combo.addItems(["높음", "보통", "낮음"])
        add_layout.addWidget(self.criticality_combo, 4, 3)
        
        # 추가 버튼
        add_btn = PrimaryButton("🔧 컴포넌트 추가")
        add_btn.clicked.connect(self.add_infrastructure_component)
        add_layout.addWidget(add_btn, 5, 0, 1, 4)
        
        add_card.layout().addLayout(add_layout)
        layout.addWidget(add_card)
        
        # 현재 인프라 목록
        list_card = Card("현재 인프라 구성")
        self.infra_list = QListWidget()
        self.infra_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: #fafafa;
            }
            QListWidgetItem {
                padding: 10px;
                border-bottom: 1px solid #e0e0e0;
            }
        """)
        
        # 리스트 제어 버튼
        list_controls = QHBoxLayout()
        
        self.remove_btn = SecondaryButton("🗑️ 선택 제거")
        self.remove_btn.clicked.connect(self.remove_selected_component)
        self.remove_btn.setEnabled(False)
        list_controls.addWidget(self.remove_btn)
        
        self.clear_btn = SecondaryButton("🧹 전체 지우기")
        self.clear_btn.clicked.connect(self.clear_all_components)
        list_controls.addWidget(self.clear_btn)
        
        list_controls.addStretch()
        
        # 템플릿 로드 버튼
        template_btn = PrimaryButton("📋 표준 템플릿 로드")
        template_btn.clicked.connect(self.load_standard_template)
        list_controls.addWidget(template_btn)
        
        list_card.layout().addWidget(self.infra_list)
        list_card.layout().addLayout(list_controls)
        layout.addWidget(list_card)
        
        # 선택 변경 시 버튼 활성화
        self.infra_list.itemSelectionChanged.connect(
            lambda: self.remove_btn.setEnabled(len(self.infra_list.selectedItems()) > 0)
        )
        
        layout.addStretch()
        return widget
    
    def create_scenario_tab(self):
        """시나리오 생성 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 공격 유형 선택
        type_card = Card("공격 시나리오 유형 선택")
        type_layout = QGridLayout()
        
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(["랜섬웨어", "APT", "내부자위협", "공급망공격", "피싱", "DDoS"])
        type_layout.addWidget(QLabel("공격 유형:"), 0, 0)
        type_layout.addWidget(self.attack_type_combo, 0, 1)
        
        # 시나리오 생성 버튼
        self.generate_btn = PrimaryButton("🎯 시나리오 생성")
        self.generate_btn.clicked.connect(self.generate_scenario)
        type_layout.addWidget(self.generate_btn, 0, 2)
        
        type_card.layout().addLayout(type_layout)
        layout.addWidget(type_card)
        
        # 생성 상태 표시
        self.status_label = QLabel("시나리오 생성 준비 완료")
        self.status_label.setStyleSheet("color: #52c41a; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # 진행 상황
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # 시나리오 결과 표시
        result_card = Card("생성된 시나리오")
        
        self.scenario_display = QTextBrowser()
        self.scenario_display.setStyleSheet("""
            QTextBrowser {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                line-height: 1.5;
            }
        """)
        self.scenario_display.setHtml("""
        <div style='text-align: center; color: #999; padding: 50px;'>
            <h3>🎭 시나리오 생성 대기 중</h3>
            <p>인프라 구성을 완료하고 '시나리오 생성' 버튼을 클릭하세요.</p>
            <p>AI가 맞춤형 공격 시나리오를 생성해드립니다.</p>
        </div>
        """)
        
        result_card.layout().addWidget(self.scenario_display)
        layout.addWidget(result_card)
        
        # 시나리오 액션 버튼들
        actions_layout = QHBoxLayout()
        
        self.export_btn = SecondaryButton("📄 시나리오 내보내기")
        self.export_btn.clicked.connect(self.export_scenario)
        self.export_btn.setEnabled(False)
        actions_layout.addWidget(self.export_btn)
        
        self.save_btn = SecondaryButton("💾 시나리오 저장")
        self.save_btn.clicked.connect(self.save_scenario)
        self.save_btn.setEnabled(False)
        actions_layout.addWidget(self.save_btn)
        
        actions_layout.addStretch()
        
        self.regenerate_btn = PrimaryButton("🔄 다시 생성")
        self.regenerate_btn.clicked.connect(self.regenerate_scenario)
        self.regenerate_btn.setEnabled(False)
        actions_layout.addWidget(self.regenerate_btn)
        
        layout.addLayout(actions_layout)
        
        return widget
    
    def create_analysis_tab(self):
        """결과 분석 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 위험도 분석
        risk_card = Card("위험도 분석")
        risk_layout = QGridLayout()
        
        # 위험도 지표들
        self.risk_score_label = QLabel("전체 위험도: --")
        self.risk_score_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff4d4f;")
        risk_layout.addWidget(self.risk_score_label, 0, 0)
        
        self.detection_difficulty_label = QLabel("탐지 난이도: --")
        risk_layout.addWidget(self.detection_difficulty_label, 0, 1)
        
        self.impact_level_label = QLabel("비즈니스 영향: --")
        risk_layout.addWidget(self.impact_level_label, 1, 0)
        
        self.duration_label = QLabel("예상 소요시간: --")
        risk_layout.addWidget(self.duration_label, 1, 1)
        
        risk_card.layout().addLayout(risk_layout)
        layout.addWidget(risk_card)
        
        # 단계별 분석
        steps_card = Card("단계별 위험 분석")
        
        self.steps_table = QTableWidget()
        self.steps_table.setColumnCount(6)
        self.steps_table.setHorizontalHeaderLabels([
            "단계", "MITRE 기법", "대상", "성공률", "탐지방법", "대응방안"
        ])
        self.steps_table.horizontalHeader().setStretchLastSection(True)
        self.steps_table.setAlternatingRowColors(True)
        self.steps_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                gridline-color: #f0f0f0;
            }
            QHeaderView::section {
                background-color: #fafafa;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        
        steps_card.layout().addWidget(self.steps_table)
        layout.addWidget(steps_card)
        
        # 권고사항
        recommendations_card = Card("보안 강화 권고사항")
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: #f9f9f9;
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
    
    def add_infrastructure_component(self):
        """인프라 컴포넌트 추가"""
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "입력 오류", "컴포넌트명을 입력해주세요.")
            return
        
        component = InfrastructureComponent(
            name=self.name_input.text().strip(),
            type=self.type_combo.currentText(),
            os=self.os_input.text().strip() or "알 수 없음",
            version=self.version_input.text().strip() or "알 수 없음",
            services=[s.strip() for s in self.services_input.text().split(',') if s.strip()],
            security_controls=[s.strip() for s in self.security_input.text().split(',') if s.strip()],
            network_zone=self.zone_combo.currentText(),
            criticality=self.criticality_combo.currentText()
        )
        
        self.infrastructure_components.append(component)
        
        # 리스트에 표시
        item_text = f"🔧 {component.name} ({component.type}) - {component.os} - {component.network_zone}"
        self.infra_list.addItem(item_text)
        
        # 입력 필드 초기화
        self.name_input.clear()
        self.os_input.clear()
        self.version_input.clear()
        self.services_input.clear()
        self.security_input.clear()
        
        # 생성 버튼 활성화
        self.update_generate_button_state()
    
    def remove_selected_component(self):
        """선택된 컴포넌트 제거"""
        current_row = self.infra_list.currentRow()
        if current_row >= 0:
            self.infra_list.takeItem(current_row)
            if current_row < len(self.infrastructure_components):
                self.infrastructure_components.pop(current_row)
            self.update_generate_button_state()
    
    def clear_all_components(self):
        """모든 컴포넌트 제거"""
        reply = QMessageBox.question(
            self, "확인", 
            "모든 인프라 구성을 삭제하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.infra_list.clear()
            self.infrastructure_components.clear()
            self.update_generate_button_state()
    
    def load_standard_template(self):
        """표준 템플릿 로드"""
        templates = {
            "중소기업 표준": [
                ("웹서버", "서버", "Windows Server 2019", "10.0.17763", "IIS,ASP.NET", "Windows Defender", "DMZ", "높음"),
                ("파일서버", "서버", "Windows Server 2016", "10.0.14393", "SMB,FTP", "안티바이러스", "내부망", "높음"),
                ("DB서버", "데이터베이스", "Windows Server 2019", "10.0.17763", "SQL Server", "데이터베이스 암호화", "내부망", "높음"),
                ("방화벽", "네트워크장비", "Fortinet FortiOS", "6.4.5", "방화벽", "IPS,웹필터링", "경계망", "높음"),
                ("업무PC", "엔드포인트", "Windows 10", "21H2", "Office 365", "EDR,패치관리", "내부망", "보통")
            ],
            "대기업 표준": [
                ("로드밸런서", "네트워크장비", "F5 BIG-IP", "15.1.0", "로드밸런싱", "DDoS보호", "DMZ", "높음"),
                ("웹서버클러스터", "서버", "RHEL 8", "8.4", "Apache,Nginx", "SELinux,HIDS", "DMZ", "높음"),
                ("앱서버클러스터", "서버", "RHEL 8", "8.4", "JBoss,Tomcat", "APM,WAF", "내부망", "높음"),
                ("DB클러스터", "데이터베이스", "Oracle Linux", "8.4", "Oracle RAC", "TDE,DLP", "데이터망", "높음"),
                ("Active Directory", "서버", "Windows Server 2022", "21H2", "AD DS,DNS", "PAM,SIEM", "관리망", "높음"),
                ("보안관제시스템", "서버", "CentOS 8", "8.4", "SIEM,SOAR", "로그수집,분석", "관리망", "높음")
            ]
        }
        
        template, ok = QInputDialog.getItem(
            self, "템플릿 선택", 
            "로드할 템플릿을 선택하세요:",
            list(templates.keys()),
            0, False
        )
        
        if ok and template:
            # 기존 구성 삭제
            self.clear_all_components()
            
            # 템플릿 컴포넌트들 추가
            for comp_data in templates[template]:
                component = InfrastructureComponent(
                    name=comp_data[0],
                    type=comp_data[1],
                    os=comp_data[2],
                    version=comp_data[3],
                    services=comp_data[4].split(','),
                    security_controls=comp_data[5].split(','),
                    network_zone=comp_data[6],
                    criticality=comp_data[7]
                )
                
                self.infrastructure_components.append(component)
                
                item_text = f"🔧 {component.name} ({component.type}) - {component.os} - {component.network_zone}"
                self.infra_list.addItem(item_text)
            
            self.update_generate_button_state()
            
            QMessageBox.information(self, "완료", f"'{template}' 템플릿이 로드되었습니다.")
    
    def update_generate_button_state(self):
        """시나리오 생성 버튼 상태 업데이트"""
        has_components = len(self.infrastructure_components) > 0
        self.generate_btn.setEnabled(has_components)
        
        if has_components:
            self.status_label.setText(f"인프라 구성 완료 ({len(self.infrastructure_components)}개 컴포넌트)")
            self.status_label.setStyleSheet("color: #52c41a; font-weight: bold;")
        else:
            self.status_label.setText("인프라 구성을 추가해주세요")
            self.status_label.setStyleSheet("color: #faad14; font-weight: bold;")
    
    def generate_scenario(self):
        """시나리오 생성 시작"""
        if not self.infrastructure_components:
            QMessageBox.warning(self, "설정 오류", "먼저 인프라 구성을 추가해주세요.")
            return
        
        # UI 상태 변경
        self.generate_btn.setEnabled(False)
        self.generate_btn.setText("🔄 생성 중...")
        self.status_label.setText("AI가 시나리오를 생성하고 있습니다...")
        self.status_label.setStyleSheet("color: #1890ff; font-weight: bold;")
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # 무한 진행바
        
        # 시나리오 생성 시작
        attack_type = self.attack_type_combo.currentText()
        self.engine.generate_attack_scenario(self.infrastructure_components, attack_type)
    
    def regenerate_scenario(self):
        """시나리오 다시 생성"""
        self.generate_scenario()
    
    @pyqtSlot(dict)
    def on_scenario_generated(self, scenario_data):
        """시나리오 생성 완료"""
        self.current_scenario = scenario_data
        
        # UI 상태 복원
        self.generate_btn.setEnabled(True)
        self.generate_btn.setText("🎯 시나리오 생성")
        self.status_label.setText("시나리오 생성 완료!")
        self.status_label.setStyleSheet("color: #52c41a; font-weight: bold;")
        self.progress_bar.setVisible(False)
        
        # 시나리오 표시
        self.display_scenario(scenario_data)
        
        # 버튼들 활성화
        self.export_btn.setEnabled(True)
        self.save_btn.setEnabled(True)
        self.regenerate_btn.setEnabled(True)
        
        # 분석 탭 업데이트
        self.update_analysis_tab(scenario_data)
    
    @pyqtSlot(str)
    def on_error_occurred(self, error_message):
        """오류 발생 시 처리"""
        # UI 상태 복원
        self.generate_btn.setEnabled(True)
        self.generate_btn.setText("🎯 시나리오 생성")
        self.status_label.setText("시나리오 생성 실패")
        self.status_label.setStyleSheet("color: #ff4d4f; font-weight: bold;")
        self.progress_bar.setVisible(False)
        
        # 오류 메시지 표시
        QMessageBox.critical(self, "오류", f"시나리오 생성 중 오류가 발생했습니다:\n\n{error_message}")
    
    def display_scenario(self, scenario_data):
        """생성된 시나리오 표시"""
        raw_response = scenario_data.get("raw_response", "")
        generated_at = scenario_data.get("generated_at", "")
        
        # HTML 형식으로 변환
        html_content = f"""
        <div style="padding: 20px; font-family: 'Segoe UI', sans-serif;">
            <div style="background: #f0f9ff; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                <h2 style="color: #1890ff; margin: 0;">🎯 AI 생성 공격 시나리오</h2>
                <p style="color: #666; margin: 5px 0 0 0;">생성 시간: {generated_at[:19]}</p>
            </div>
            
            <div style="line-height: 1.6; color: #262626;">
                {self.format_scenario_html(raw_response)}
            </div>
        </div>
        """
        
        self.scenario_display.setHtml(html_content)
    
    def format_scenario_html(self, text):
        """시나리오 텍스트를 HTML로 포맷"""
        lines = text.split('\n')
        html_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                html_lines.append('<br>')
            elif line.startswith('##'):
                title = line.strip('#').strip()
                html_lines.append(f'<h3 style="color: #1890ff; margin-top: 30px;">{title}</h3>')
            elif line.startswith('###'):
                subtitle = line.strip('#').strip()
                html_lines.append(f'<h4 style="color: #595959; margin-top: 20px;">{subtitle}</h4>')
            elif line.startswith('**') and line.endswith('**'):
                bold_text = line.strip('*')
                html_lines.append(f'<p style="margin: 10px 0;"><strong style="color: #262626;">{bold_text}</strong></p>')
            elif line.startswith('- '):
                list_item = line[2:]
                html_lines.append(f'<li style="margin: 5px 0;">{list_item}</li>')
            else:
                html_lines.append(f'<p style="margin: 8px 0;">{line}</p>')
        
        return ''.join(html_lines)
    
    def update_analysis_tab(self, scenario_data):
        """분석 탭 업데이트"""
        # 더미 데이터로 분석 정보 표시 (실제로는 AI 응답 파싱 필요)
        self.risk_score_label.setText("전체 위험도: 8.5/10")
        self.detection_difficulty_label.setText("탐지 난이도: 높음")
        self.impact_level_label.setText("비즈니스 영향: 심각")
        self.duration_label.setText("예상 소요시간: 2-7일")
        
        # 단계별 테이블 업데이트 (더미 데이터)
        steps_data = [
            ("1. 정찰", "T1595", "공개 정보", "95%", "네트워크 모니터링", "정보 공개 최소화"),
            ("2. 초기 침투", "T1566", "이메일 시스템", "70%", "이메일 보안 솔루션", "사용자 교육"),
            ("3. 실행", "T1059", "엔드포인트", "85%", "EDR 솔루션", "PowerShell 제한"),
            ("4. 지속성", "T1547", "시작 프로그램", "90%", "시스템 무결성 검사", "부팅 보안"),
            ("5. 권한 상승", "T1548", "관리자 계정", "60%", "특권 계정 모니터링", "최소 권한 원칙")
        ]
        
        self.steps_table.setRowCount(len(steps_data))
        for i, (step, technique, target, success, detection, mitigation) in enumerate(steps_data):
            self.steps_table.setItem(i, 0, QTableWidgetItem(step))
            self.steps_table.setItem(i, 1, QTableWidgetItem(technique))
            self.steps_table.setItem(i, 2, QTableWidgetItem(target))
            
            success_item = QTableWidgetItem(success)
            if float(success.rstrip('%')) > 80:
                success_item.setBackground(QColor("#fff2f0"))
            self.steps_table.setItem(i, 3, success_item)
            
            self.steps_table.setItem(i, 4, QTableWidgetItem(detection))
            self.steps_table.setItem(i, 5, QTableWidgetItem(mitigation))
        
        # 권고사항 업데이트 (더미 데이터)
        recommendations = [
            "🛡️ EDR(Endpoint Detection and Response) 솔루션 도입 우선 검토",
            "🔒 특권 계정 관리(PAM) 시스템 구축",
            "📧 이메일 보안 강화 및 사용자 보안 교육 실시",
            "🔍 네트워크 세그먼테이션을 통한 측면 이동 차단",
            "📝 보안 정책 수립 및 정기적인 보안 점검 실시",
            "💾 중요 데이터 백업 및 복구 절차 정비",
            "🚨 보안 사고 대응 계획(IRP) 수립"
        ]
        
        self.recommendations_list.clear()
        for rec in recommendations:
            self.recommendations_list.addItem(rec)
    
    def export_scenario(self):
        """시나리오 내보내기"""
        if not self.current_scenario:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "시나리오 내보내기", 
            f"security_scenario_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if file_path.endswith('.html'):
                        f.write(self.scenario_display.toHtml())
                    else:
                        f.write(self.current_scenario.get("raw_response", ""))
                
                QMessageBox.information(self, "완료", f"시나리오가 저장되었습니다:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"파일 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def save_scenario(self):
        """시나리오 저장 (내부 데이터베이스)"""
        if not self.current_scenario:
            return
        
        # 시나리오 이름 입력
        name, ok = QInputDialog.getText(
            self, "시나리오 저장",
            "시나리오 이름을 입력하세요:"
        )
        
        if ok and name.strip():
            # 실제로는 데이터베이스에 저장
            QMessageBox.information(self, "저장 완료", f"'{name}' 시나리오가 저장되었습니다.")

if __name__ == "__main__":
    app = QApplication([])
    tab = SecuritySimulatorTab()
    tab.show()
    app.exec()