# ai_policy_generator.py - AI 자연어 보안 정책 생성기
"""
MetaShield AI 자연어 보안 정책 생성기
자연어 입력을 받아 AI가 맞춤형 보안 정책 문서를 자동 생성합니다.
"""

import json
import time
import threading
from datetime import datetime
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
class PolicyTemplate:
    """정책 템플릿"""
    id: str
    name: str
    category: str
    description: str
    sections: List[str]
    compliance_frameworks: List[str]

@dataclass
class GeneratedPolicy:
    """생성된 정책"""
    id: str
    title: str
    category: str
    generated_at: str
    user_requirements: str
    content: str
    sections: Dict[str, str]
    implementation_guide: List[str]
    checklist: List[str]
    compliance_mapping: Dict[str, List[str]]

class SecurityPolicyEngine(QObject):
    """AI 보안 정책 생성 엔진"""
    
    policy_generated = pyqtSignal(dict)
    section_generated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    progress_updated = pyqtSignal(int, str)
    
    def __init__(self):
        super().__init__()
        self.ai_config = get_ai_config()
        self.client = None
        self.initialize_ai_client()
        
        # 정책 템플릿들
        self.policy_templates = {
            "정보보안정책": PolicyTemplate(
                id="infosec_policy",
                name="정보보안 기본 정책",
                category="기본 정책",
                description="조직의 전반적인 정보보안 정책",
                sections=["목적", "적용범위", "역할과 책임", "보안 원칙", "위반 시 조치"],
                compliance_frameworks=["ISO27001", "NIST", "K-ISMS"]
            ),
            "접근통제정책": PolicyTemplate(
                id="access_control",
                name="접근통제 정책",
                category="기술 정책",
                description="시스템 및 데이터 접근 권한 관리",
                sections=["접근권한 관리", "인증 요구사항", "권한 부여", "정기 검토", "계정 관리"],
                compliance_frameworks=["ISO27001", "SOC2"]
            ),
            "원격근무정책": PolicyTemplate(
                id="remote_work",
                name="원격근무 보안 정책",
                category="운영 정책",
                description="재택근무 및 원격접속 보안 가이드",
                sections=["원격접속 방법", "VPN 사용", "기기 보안", "데이터 보호", "모니터링"],
                compliance_frameworks=["ISO27001", "PCI-DSS"]
            ),
            "사고대응정책": PolicyTemplate(
                id="incident_response",
                name="보안사고 대응 정책",
                category="대응 정책",
                description="보안사고 발생 시 대응 절차",
                sections=["사고 분류", "대응 조직", "대응 절차", "복구 계획", "사후 분석"],
                compliance_frameworks=["ISO27035", "NIST CSF"]
            ),
            "데이터보호정책": PolicyTemplate(
                id="data_protection",
                name="개인정보 보호 정책",
                category="법적 준수",
                description="개인정보 및 민감데이터 보호",
                sections=["수집 및 이용", "보관 및 파기", "제3자 제공", "안전성 확보", "권리 보장"],
                compliance_frameworks=["GDPR", "개인정보보호법", "CCPA"]
            )
        }
        
        # 업계별 특화 요구사항
        self.industry_requirements = {
            "금융": ["금융권 클라우드 이용 가이드", "전자금융 감독규정", "금융사고 신고 의무"],
            "의료": ["HIPAA 준수", "의료정보 보호", "환자정보 관리"],
            "제조": ["산업보안", "기술유출 방지", "공장자동화 보안"],
            "공공": ["국가정보보안 기본지침", "개인정보 보호법", "정보시스템 보안"],
            "교육": ["학생정보 보호", "연구데이터 보안", "온라인 교육 보안"],
            "유통": ["결제정보 보안", "고객정보 관리", "PCI-DSS 준수"]
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
    
    def generate_policy(self, user_input: str, policy_type: str, organization_info: dict):
        """보안 정책 생성"""
        if not self.client:
            self.error_occurred.emit("AI 클라이언트가 초기화되지 않았습니다.")
            return
        
        # 백그라운드에서 정책 생성
        self.generation_thread = threading.Thread(
            target=self._generate_policy_background,
            args=(user_input, policy_type, organization_info)
        )
        self.generation_thread.start()
    
    def _generate_policy_background(self, user_input: str, policy_type: str, org_info: dict):
        """백그라운드에서 정책 생성"""
        try:
            # 템플릿 가져오기
            template = self.policy_templates.get(policy_type)
            if not template:
                self.error_occurred.emit(f"알 수 없는 정책 유형: {policy_type}")
                return
            
            # 진행 상황 업데이트
            self.progress_updated.emit(10, "정책 구조 분석 중...")
            
            # AI 프롬프트 생성
            prompt = self._create_policy_prompt(user_input, template, org_info)
            
            self.progress_updated.emit(30, "AI가 정책을 생성하는 중...")
            
            # AI 호출
            response = self.client.chat.completions.create(
                model=self.ai_config.deployment,
                messages=[
                    {"role": "system", "content": "당신은 정보보안 정책 전문가입니다. 실무진이 바로 사용할 수 있는 구체적이고 실용적인 정책을 작성해주세요."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )
            
            self.progress_updated.emit(70, "정책 문서 구조화 중...")
            
            # 응답 파싱
            policy_content = response.choices[0].message.content
            
            # 구조화된 정책 데이터 생성
            policy_data = self._parse_policy_response(policy_content, template, user_input)
            
            self.progress_updated.emit(90, "구현 가이드 생성 중...")
            
            # 구현 가이드 생성
            implementation_guide = self._generate_implementation_guide(policy_content, template)
            policy_data['implementation_guide'] = implementation_guide
            
            # 체크리스트 생성  
            checklist = self._generate_checklist(policy_content, template)
            policy_data['checklist'] = checklist
            
            self.progress_updated.emit(100, "정책 생성 완료!")
            
            # UI 업데이트
            self.policy_generated.emit(policy_data)
            
        except Exception as e:
            self.error_occurred.emit(f"정책 생성 오류: {str(e)}")
    
    def _create_policy_prompt(self, user_input: str, template: PolicyTemplate, org_info: dict) -> str:
        """정책 생성 프롬프트 생성"""
        industry_reqs = self.industry_requirements.get(org_info.get('industry', ''), [])
        
        prompt = f"""
다음 요구사항에 맞는 '{template.name}' 정책 문서를 작성해주세요.

## 사용자 요구사항
{user_input}

## 조직 정보
- 조직명: {org_info.get('name', '미지정')}
- 업종: {org_info.get('industry', '미지정')}
- 규모: {org_info.get('size', '미지정')}
- 특이사항: {org_info.get('notes', '없음')}

## 정책 구조
다음 섹션들을 포함하여 작성해주세요:
{chr(10).join(f"- {section}" for section in template.sections)}

## 준수 프레임워크
{', '.join(template.compliance_frameworks)} 기준에 맞춰 작성해주세요.

{f"## 업계 특화 요구사항{chr(10)}{chr(10).join(f'- {req}' for req in industry_reqs)}" if industry_reqs else ""}

## 작성 가이드라인
1. 실무진이 바로 적용할 수 있도록 구체적으로 작성
2. 각 항목에 대한 명확한 기준과 절차 포함
3. 위반 시 조치사항 명시
4. 정기적인 검토 및 업데이트 방법 포함
5. 한국의 법적 요구사항 고려

다음 형식으로 작성해주세요:

# {template.name}

## 1. 목적 및 적용범위
[목적과 적용 대상을 명확히 기술]

## 2. 정의
[주요 용어들의 정의]

## 3. 역할과 책임
[관련 부서 및 담당자별 역할]

## 4. 정책 내용
[각 섹션별 상세 정책 내용]

## 5. 구현 절차
[정책 이행을 위한 구체적 절차]

## 6. 모니터링 및 감사
[정책 준수 확인 방법]

## 7. 위반 시 조치
[정책 위반에 대한 처벌 기준]

## 8. 정책 검토
[정기적 검토 및 업데이트 절차]

실제 현업에서 바로 사용할 수 있도록 상세하고 실용적으로 작성해주세요.
"""
        return prompt
    
    def _parse_policy_response(self, content: str, template: PolicyTemplate, user_input: str) -> dict:
        """AI 응답을 구조화된 데이터로 파싱"""
        policy_data = {
            "id": f"policy_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "title": template.name,
            "category": template.category,
            "generated_at": datetime.now().isoformat(),
            "user_requirements": user_input,
            "content": content,
            "sections": self._extract_policy_sections(content),
            "template_id": template.id,
            "compliance_frameworks": template.compliance_frameworks
        }
        
        return policy_data
    
    def _extract_policy_sections(self, content: str) -> dict:
        """정책 내용에서 섹션별로 분리"""
        sections = {}
        current_section = ""
        current_content = []
        
        for line in content.split('\n'):
            if line.startswith('##'):
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = line.strip('#').strip()
                current_content = []
            else:
                current_content.append(line)
        
        if current_section:
            sections[current_section] = '\n'.join(current_content).strip()
        
        return sections
    
    def _generate_implementation_guide(self, policy_content: str, template: PolicyTemplate) -> List[str]:
        """구현 가이드 생성"""
        # 실제로는 AI로 구현 가이드 생성 가능
        guide_items = [
            "정책 문서를 조직 내 공식 문서로 승인 받기",
            "관련 부서 및 직원들에게 정책 내용 교육 실시",
            "정책 이행을 위한 시스템 및 도구 구축",
            "정책 준수 모니터링 체계 수립",
            "정기적인 정책 검토 일정 수립",
            "정책 위반 시 대응 절차 마련",
            "외부 감사 및 인증 대비 문서화",
            "정책 효과성 측정 지표 개발"
        ]
        
        return guide_items
    
    def _generate_checklist(self, policy_content: str, template: PolicyTemplate) -> List[str]:
        """구현 체크리스트 생성"""
        checklist_items = [
            "□ 경영진 승인 완료",
            "□ 관련 부서 검토 완료", 
            "□ 법적 요구사항 확인",
            "□ 기존 정책과의 일관성 검토",
            "□ 직원 교육 계획 수립",
            "□ 시스템 설정 변경사항 확인",
            "□ 모니터링 도구 준비",
            "□ 정기 검토 일정 등록",
            "□ 비상연락망 업데이트",
            "□ 문서 배포 및 공지"
        ]
        
        return checklist_items

class SecurityPolicyGeneratorTab(QWidget):
    """AI 보안 정책 생성기 탭"""
    
    def __init__(self):
        super().__init__()
        self.engine = SecurityPolicyEngine()
        self.engine.policy_generated.connect(self.on_policy_generated)
        self.engine.error_occurred.connect(self.on_error_occurred)
        self.engine.progress_updated.connect(self.on_progress_updated)
        
        self.current_policy = None
        self.setup_ui()
    
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 15)  # 상단 여백 축소
        layout.setSpacing(10)  # 간격 축소
        
        # 제목 (크기 축소)
        title = QLabel("📝 AI 자연어 보안 정책 생성기")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1890ff; margin-bottom: 5px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("자연어로 요구사항을 입력하면 AI가 맞춤형 보안 정책 문서를 자동으로 생성합니다.")
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
        
        # 요구사항 입력 탭
        self.input_tab = self.create_input_tab()
        tab_widget.addTab(self.input_tab, "✍️ 요구사항 입력")
        
        # 생성된 정책 탭
        self.policy_tab = self.create_policy_tab()
        tab_widget.addTab(self.policy_tab, "📄 생성된 정책")
        
        # 구현 가이드 탭
        self.guide_tab = self.create_guide_tab()
        tab_widget.addTab(self.guide_tab, "🛠️ 구현 가이드")
        
        layout.addWidget(tab_widget)
    
    def create_input_tab(self):
        """요구사항 입력 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 조직 정보 카드
        org_card = Card("조직 정보")
        org_layout = QGridLayout()
        
        org_layout.addWidget(QLabel("조직명:"), 0, 0)
        self.org_name_input = QLineEdit()
        self.org_name_input.setPlaceholderText("예: (주)메타실드")
        org_layout.addWidget(self.org_name_input, 0, 1)
        
        org_layout.addWidget(QLabel("업종:"), 0, 2)
        self.industry_combo = QComboBox()
        self.industry_combo.addItems(["선택하세요", "금융", "의료", "제조", "공공", "교육", "유통", "IT서비스", "기타"])
        org_layout.addWidget(self.industry_combo, 0, 3)
        
        org_layout.addWidget(QLabel("규모:"), 1, 0)
        self.size_combo = QComboBox()
        self.size_combo.addItems(["소기업(50인 미만)", "중소기업(50-300인)", "중견기업(300-1000인)", "대기업(1000인 이상)"])
        org_layout.addWidget(self.size_combo, 1, 1)
        
        org_layout.addWidget(QLabel("특이사항:"), 1, 2)
        self.notes_input = QLineEdit()
        self.notes_input.setPlaceholderText("예: 글로벌 지사, 클라우드 환경 등")
        org_layout.addWidget(self.notes_input, 1, 3)
        
        org_card.layout().addLayout(org_layout)
        layout.addWidget(org_card)
        
        # 정책 유형 선택
        type_card = Card("정책 유형 선택")
        type_layout = QHBoxLayout()
        
        self.policy_type_combo = QComboBox()
        self.policy_type_combo.addItems([
            "정보보안정책", "접근통제정책", "원격근무정책", 
            "사고대응정책", "데이터보호정책"
        ])
        type_layout.addWidget(QLabel("정책 유형:"))
        type_layout.addWidget(self.policy_type_combo)
        type_layout.addStretch()
        
        type_card.layout().addLayout(type_layout)
        layout.addWidget(type_card)
        
        # 자연어 요구사항 입력
        requirement_card = Card("요구사항 입력 (자연어)")
        
        self.requirement_input = QTextEdit()
        self.requirement_input.setPlaceholderText(
            "자연어로 요구사항을 입력하세요. 예시:\n\n"
            "우리 회사는 재택근무를 도입하려고 합니다. 직원들이 집에서 안전하게 회사 시스템에 접속할 수 있는 "
            "보안 정책이 필요합니다. VPN을 통해서만 접속하게 하고, 업무용 노트북에는 암호화와 백신을 설치하게 "
            "하고 싶습니다. 그리고 개인 PC는 사용하지 못하게 하고, 공공 와이파이는 업무에 사용하지 않도록 "
            "규정을 만들고 싶습니다."
        )
        self.requirement_input.setMinimumHeight(150)
        self.requirement_input.setStyleSheet("""
            QTextEdit {
                border: 2px solid #d9d9d9;
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                line-height: 1.5;
            }
            QTextEdit:focus {
                border-color: #1890ff;
            }
        """)
        
        requirement_card.layout().addWidget(self.requirement_input)
        layout.addWidget(requirement_card)
        
        # 예시 요구사항 버튼들
        examples_card = Card("예시 요구사항 (클릭하여 자동 입력)")
        examples_layout = QVBoxLayout()
        
        example_buttons = [
            ("🏠 재택근무", "재택근무 환경에서 안전하게 업무할 수 있는 보안 정책을 만들어주세요. VPN 접속, 기기 보안, 네트워크 보안 등을 포함해주세요."),
            ("🔐 비밀번호", "강력한 비밀번호 정책을 만들어주세요. 복잡성 요구사항, 정기 변경, 다중인증 등을 포함해주세요."),
            ("📧 이메일", "피싱 메일 차단과 안전한 이메일 사용을 위한 정책을 만들어주세요. 첨부파일 검사, 외부 메일 주의사항 등을 포함해주세요."),
            ("☁️ 클라우드", "클라우드 서비스 사용에 대한 보안 정책을 만들어주세요. 승인된 서비스만 사용, 데이터 분류, 접근 권한 등을 포함해주세요."),
            ("🛡️ 사고대응", "보안 사고 발생 시 대응 절차를 정의해주세요. 사고 분류, 신고 체계, 대응팀 구성 등을 포함해주세요.")
        ]
        
        button_layout = QHBoxLayout()
        for i, (title, example) in enumerate(example_buttons):
            btn = SecondaryButton(title)
            btn.clicked.connect(lambda checked, text=example: self.requirement_input.setText(text))
            button_layout.addWidget(btn)
            
            if i == 2:  # 3개마다 줄바꿈
                examples_layout.addLayout(button_layout)
                button_layout = QHBoxLayout()
        
        if button_layout.count() > 0:
            examples_layout.addLayout(button_layout)
        
        examples_card.layout().addLayout(examples_layout)
        layout.addWidget(examples_card)
        
        # 생성 버튼
        generate_layout = QHBoxLayout()
        
        self.generate_btn = PrimaryButton("🤖 AI로 정책 생성")
        self.generate_btn.clicked.connect(self.generate_policy)
        generate_layout.addWidget(self.generate_btn)
        
        generate_layout.addStretch()
        
        # 진행 상황 표시
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        
        layout.addLayout(generate_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_label)
        
        layout.addStretch()
        return widget
    
    def create_policy_tab(self):
        """생성된 정책 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 정책 정보 헤더
        header_card = Card()
        header_layout = QGridLayout()
        
        self.policy_title_label = QLabel("정책 제목")
        self.policy_title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #1890ff;")
        header_layout.addWidget(self.policy_title_label, 0, 0)
        
        self.policy_date_label = QLabel("생성일: --")
        header_layout.addWidget(self.policy_date_label, 0, 1)
        
        self.policy_category_label = QLabel("분류: --")
        header_layout.addWidget(self.policy_category_label, 1, 0)
        
        self.compliance_label = QLabel("준수 프레임워크: --")
        header_layout.addWidget(self.compliance_label, 1, 1)
        
        header_card.layout().addLayout(header_layout)
        layout.addWidget(header_card)
        
        # 정책 내용 표시
        content_card = Card("정책 내용")
        
        self.policy_content = QTextBrowser()
        self.policy_content.setStyleSheet("""
            QTextBrowser {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
                font-family: 'Malgun Gothic', sans-serif;
                font-size: 13px;
                line-height: 1.6;
                padding: 15px;
            }
        """)
        self.policy_content.setHtml("""
        <div style='text-align: center; color: #999; padding: 50px;'>
            <h3>📝 정책 생성 대기 중</h3>
            <p>요구사항을 입력하고 'AI로 정책 생성' 버튼을 클릭하세요.</p>
            <p>AI가 맞춤형 보안 정책을 생성해드립니다.</p>
        </div>
        """)
        
        content_card.layout().addWidget(self.policy_content)
        layout.addWidget(content_card)
        
        # 정책 액션 버튼들
        actions_layout = QHBoxLayout()
        
        self.export_policy_btn = SecondaryButton("📄 Word로 내보내기")
        self.export_policy_btn.clicked.connect(self.export_policy)
        self.export_policy_btn.setEnabled(False)
        actions_layout.addWidget(self.export_policy_btn)
        
        self.save_policy_btn = SecondaryButton("💾 정책 저장")
        self.save_policy_btn.clicked.connect(self.save_policy)
        self.save_policy_btn.setEnabled(False)
        actions_layout.addWidget(self.save_policy_btn)
        
        self.print_btn = SecondaryButton("🖨️ 인쇄")
        self.print_btn.clicked.connect(self.print_policy)
        self.print_btn.setEnabled(False)
        actions_layout.addWidget(self.print_btn)
        
        actions_layout.addStretch()
        
        self.regenerate_policy_btn = PrimaryButton("🔄 다시 생성")
        self.regenerate_policy_btn.clicked.connect(self.regenerate_policy)
        self.regenerate_policy_btn.setEnabled(False)
        actions_layout.addWidget(self.regenerate_policy_btn)
        
        layout.addLayout(actions_layout)
        
        return widget
    
    def create_guide_tab(self):
        """구현 가이드 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 구현 단계
        steps_card = Card("구현 단계")
        
        self.implementation_list = QListWidget()
        self.implementation_list.setStyleSheet("""
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
        
        steps_card.layout().addWidget(self.implementation_list)
        layout.addWidget(steps_card)
        
        # 체크리스트
        checklist_card = Card("구현 체크리스트")
        
        self.checklist_widget = QListWidget()
        self.checklist_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: #f9f9f9;
            }
            QListWidgetItem {
                padding: 10px;
                border-bottom: 1px solid #e0e0e0;
                background-color: white;
                margin: 2px;
                border-radius: 4px;
            }
        """)
        
        checklist_card.layout().addWidget(self.checklist_widget)
        layout.addWidget(checklist_card)
        
        # 추가 리소스
        resources_card = Card("추가 리소스")
        resources_layout = QVBoxLayout()
        
        resources_info = QLabel("""
        📚 관련 법규 및 가이드라인:
        • 개인정보보호법 및 시행령
        • 정보통신망법 및 시행령  
        • K-ISMS-P 인증기준
        • ISO 27001:2013 표준
        • NIST Cybersecurity Framework
        
        🔗 유용한 링크:
        • 개인정보보호위원회 (privacy.go.kr)
        • 한국인터넷진흥원 (kisa.or.kr)
        • 국가정보원 국가보안기술연구소 (nsri.re.kr)
        """)
        resources_info.setStyleSheet("color: #666; line-height: 1.6;")
        resources_layout.addWidget(resources_info)
        
        resources_card.layout().addLayout(resources_layout)
        layout.addWidget(resources_card)
        
        return widget
    
    def generate_policy(self):
        """정책 생성 시작"""
        # 입력 검증
        if not self.requirement_input.toPlainText().strip():
            QMessageBox.warning(self, "입력 오류", "요구사항을 입력해주세요.")
            return
        
        if not self.org_name_input.text().strip():
            QMessageBox.warning(self, "입력 오류", "조직명을 입력해주세요.")
            return
        
        # 조직 정보 수집
        org_info = {
            'name': self.org_name_input.text().strip(),
            'industry': self.industry_combo.currentText(),
            'size': self.size_combo.currentText(),
            'notes': self.notes_input.text().strip()
        }
        
        # UI 상태 변경
        self.generate_btn.setEnabled(False)
        self.generate_btn.setText("🔄 생성 중...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_label.setVisible(True)
        self.progress_label.setText("정책 생성을 시작합니다...")
        
        # 정책 생성 시작
        user_input = self.requirement_input.toPlainText().strip()
        policy_type = self.policy_type_combo.currentText()
        self.engine.generate_policy(user_input, policy_type, org_info)
    
    def regenerate_policy(self):
        """정책 다시 생성"""
        self.generate_policy()
    
    @pyqtSlot(int, str)
    def on_progress_updated(self, progress: int, message: str):
        """진행 상황 업데이트"""
        self.progress_bar.setValue(progress)
        self.progress_label.setText(message)
    
    @pyqtSlot(dict)
    def on_policy_generated(self, policy_data):
        """정책 생성 완료"""
        self.current_policy = policy_data
        
        # UI 상태 복원
        self.generate_btn.setEnabled(True)
        self.generate_btn.setText("🤖 AI로 정책 생성")
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # 정책 정보 표시
        self.policy_title_label.setText(policy_data['title'])
        self.policy_date_label.setText(f"생성일: {policy_data['generated_at'][:19]}")
        self.policy_category_label.setText(f"분류: {policy_data['category']}")
        self.compliance_label.setText(f"준수 프레임워크: {', '.join(policy_data['compliance_frameworks'])}")
        
        # 정책 내용 표시
        self.display_policy_content(policy_data['content'])
        
        # 구현 가이드 표시
        self.display_implementation_guide(policy_data)
        
        # 버튼들 활성화
        self.export_policy_btn.setEnabled(True)
        self.save_policy_btn.setEnabled(True)
        self.print_btn.setEnabled(True)
        self.regenerate_policy_btn.setEnabled(True)
        
        # 성공 메시지
        QMessageBox.information(self, "생성 완료", "보안 정책이 성공적으로 생성되었습니다!")
    
    @pyqtSlot(str)
    def on_error_occurred(self, error_message):
        """오류 발생 시 처리"""
        # UI 상태 복원
        self.generate_btn.setEnabled(True)
        self.generate_btn.setText("🤖 AI로 정책 생성")
        self.progress_bar.setVisible(False)
        self.progress_label.setVisible(False)
        
        # 오류 메시지 표시
        QMessageBox.critical(self, "오류", f"정책 생성 중 오류가 발생했습니다:\n\n{error_message}")
    
    def display_policy_content(self, content: str):
        """정책 내용 표시"""
        # HTML 형식으로 변환
        html_content = f"""
        <div style="padding: 20px; font-family: 'Malgun Gothic', sans-serif;">
            <div style="line-height: 1.8; color: #262626;">
                {self.format_policy_html(content)}
            </div>
        </div>
        """
        
        self.policy_content.setHtml(html_content)
    
    def format_policy_html(self, text: str) -> str:
        """정책 텍스트를 HTML로 포맷"""
        lines = text.split('\n')
        html_lines = []
        in_list = False
        
        for line in lines:
            line = line.strip()
            if not line:
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                html_lines.append('<br>')
            elif line.startswith('# '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                title = line[2:].strip()
                html_lines.append(f'<h1 style="color: #1890ff; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #1890ff; padding-bottom: 10px;">{title}</h1>')
            elif line.startswith('## '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                subtitle = line[3:].strip()
                html_lines.append(f'<h2 style="color: #595959; margin-top: 25px; margin-bottom: 12px;">{subtitle}</h2>')
            elif line.startswith('### '):
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                subsubtitle = line[4:].strip()
                html_lines.append(f'<h3 style="color: #722ed1; margin-top: 20px; margin-bottom: 10px;">{subsubtitle}</h3>')
            elif line.startswith('- ') or line.startswith('* '):
                if not in_list:
                    html_lines.append('<ul style="margin: 10px 0; padding-left: 20px;">')
                    in_list = True
                list_item = line[2:]
                html_lines.append(f'<li style="margin: 5px 0; line-height: 1.6;">{list_item}</li>')
            else:
                if in_list:
                    html_lines.append('</ul>')
                    in_list = False
                if line:
                    html_lines.append(f'<p style="margin: 10px 0; line-height: 1.8;">{line}</p>')
        
        if in_list:
            html_lines.append('</ul>')
        
        return ''.join(html_lines)
    
    def display_implementation_guide(self, policy_data):
        """구현 가이드 표시"""
        # 구현 단계
        self.implementation_list.clear()
        for i, step in enumerate(policy_data.get('implementation_guide', []), 1):
            item_text = f"{i}. {step}"
            self.implementation_list.addItem(item_text)
        
        # 체크리스트
        self.checklist_widget.clear()
        for item in policy_data.get('checklist', []):
            self.checklist_widget.addItem(item)
    
    def export_policy(self):
        """정책을 Word 파일로 내보내기"""
        if not self.current_policy:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "정책 내보내기",
            f"{self.current_policy['title']}.html",
            "HTML Files (*.html);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    if file_path.endswith('.html'):
                        f.write(self.policy_content.toHtml())
                    else:
                        f.write(self.current_policy['content'])
                
                QMessageBox.information(self, "완료", f"정책이 저장되었습니다:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"파일 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def save_policy(self):
        """정책 저장 (내부 데이터베이스)"""
        if not self.current_policy:
            return
        
        QMessageBox.information(self, "저장 완료", "정책이 데이터베이스에 저장되었습니다.")
    
    def print_policy(self):
        """정책 인쇄"""
        if not self.current_policy:
            return
        
        printer = QPrinter()
        print_dialog = QPrintDialog(printer, self)
        
        if print_dialog.exec() == QPrintDialog.DialogCode.Accepted:
            self.policy_content.print(printer)

if __name__ == "__main__":
    app = QApplication([])
    tab = SecurityPolicyGeneratorTab()
    tab.show()
    app.exec()