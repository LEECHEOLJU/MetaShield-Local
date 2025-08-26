from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextBrowser, QLabel, QHBoxLayout
from modern_ui_style import MODERN_STYLE, DARK_THEME
from advanced_ui_components import Card

class GuideTab(QWidget):
    def __init__(self, html_content="", title="가이드"):
        super().__init__()
        self.setStyleSheet(MODERN_STYLE)
        self.setWindowTitle(title)
        # 가이드 내용이 없으면 기본 가이드 사용
        if not html_content.strip():
            html_content = self.get_default_guide_html()
        self.setup_ui(html_content)
        
    def setup_ui(self, html_content):
        """Setup modern guide UI with card layout"""
        # Main layout with proper spacing
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(24)

        # Header removed to maximize content space

        # Guide content card
        content_card = Card("Documentation")
        
        # Modern text browser with proper styling
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml(html_content)
        browser.setMinimumHeight(600)
        
        # Apply additional styling to the text browser
        browser.setStyleSheet("""
            QTextBrowser {
                background-color: white;
                border: none;
                border-radius: 6px;
                color: #262626;
                font-size: 14px;
                line-height: 1.6;
                padding: 16px;
                selection-background-color: #1890ff;
                selection-color: white;
            }
        """)
        
        content_card.add_widget(browser)

        main_layout.addWidget(content_card)
        
        self.setLayout(main_layout)
        
    def get_default_guide_html(self):
        """기본 가이드 HTML 반환"""
        return """<h2>🛡️ MetaShield - 엔터프라이즈 보안 분석 플랫폼 <span style="font-size:13pt;">(2025)</span></h2>
        <p>
        MetaShield는 통합 보안 플랫폼으로<br>
        <b>취약점 검색</b> · <b>AI 보안 분석</b> · <b>패턴 저장소</b> · <b>관제 고객사 관리</b> 등<br>
        모든 보안관제 업무를 <u>3단 계층 네비게이션</u>으로 체계적으로 수행할 수 있습니다.
        </p>

        <h3>🏗️ <b>1. 새로운 UI 구조</b></h3>
        <div style="background:#f8f9fa; padding:12px; border-left:4px solid #1890ff; margin:10px 0;">
        <b>📊 상단 대분류 탭</b><br>
        • <b>[보안분석]</b> - 핵심 분석 도구<br>
        • <b>[관제 고객사]</b> - 6개 고객사별 대시보드<br>  
        • <b>[사용가이드]</b> - 종합 사용법
        </div>
        
        <div style="background:#f0f8ff; padding:12px; border-left:4px solid #52c41a; margin:10px 0;">
        <b>📋 좌측 세부 네비게이션</b><br>
        • <b>🧠 AI 분석</b> - Azure OpenAI 보안 분석<br>
        • <b>🔍 취약점 검색</b> - NVD CVE 조회·분석<br>
        • <b>📚 패턴 저장소</b> - 탐지 패턴 백과사전<br>
        • <b>🏢 고객사별 전용 대시보드</b> - 굿리치, 컬리, 핀다, GLN, 한화시스템
        </div>

        <h3>🛠️ <b>2. 핵심 기능별 상세 가이드</b></h3>
        
        <h4><b>🧠 AI 보안 분석</b></h4>
        <ul>
        <li><b>Azure OpenAI 기반</b> 실시간 페이로드/로그 분석</li>
        <li><b>IOC 추출</b>: IP, 도메인, URL, 파일 해시 자동 식별</li>
        <li><b>위협 인텔리전스</b>: VirusTotal, AbuseIPDB API 연동</li>
        <li><b>실무형 보고서 포맷</b>: 1~5단계 분석 결과 자동 생성</li>
        <li><b>실시간 진행표시</b>: 분석 단계별 진도 시각화</li>
        <li><b>복사/내보내기</b>: 클립보드, 엑셀, 텍스트 형태로 결과 저장</li>
        </ul>

        <h4><b>🔍 취약점 검색 (CVE 조회)</b></h4>
        <ul>
        <li><b>멀티 CVE 입력</b>: 줄바꿈으로 여러 CVE 동시 검색 가능</li>
        <li><b>NVD API 연동</b>: 실시간 취약점 정보 조회</li>
        <li><b>CVSS v3.1 스코어링</b>: 위험도·영향도 정량적 분석</li>
        <li><b>CWE 분류</b>: 취약점 유형별 체계적 분류</li>
        <li><b>Exploit 정보</b>: 공격 코드 존재 여부 및 링크</li>
        <li><b>최적화된 레이아웃</b>: 상세정보 60% : 검색결과 40% 비율</li>
        <li><b>로컬 캐싱</b>: 반복 검색 속도 최적화</li>
        <li><b>아카이브 관리</b>: 검색 이력 자동 저장·복원</li>
        </ul>

        <h4><b>📚 패턴 분석 저장소</b></h4>
        <ul>
        <li><b>로컬 DB 기반</b>: SQLite 데이터베이스 패턴 관리</li>
        <li><b>실무 분석 템플릿</b>: SOC 표준 분석 포맷 지원</li>
        <li><b>AI 초안 생성</b>: 패턴명 기반 자동 분석 템플릿 작성</li>
        <li><b>즐겨찾기 시스템</b>: ★ 표시로 핫 패턴 관리</li>
        <li><b>검색 기능</b>: 패턴명, 설명, 카테고리별 필터링</li>
        <li><b>평점 시스템</b>: 1-5점 패턴 품질 평가</li>
        <li><b>JIRA 연동</b>: 보안 티켓 자동 임포트</li>
        <li><b>내보내기</b>: 엑셀, CSV, 텍스트 형태 저장</li>
        </ul>

        <h4><b>🏢 관제 고객사 관리</b></h4>
        <ul>
        <li><b>통합 대시보드</b>: 전체 고객사 현황 모니터링</li>
        <li><b>개별 고객사 화면</b>: 굿리치, 컬리, 핀다, GLN, 한화시스템</li>
        <li><b>확장 가능 구조</b>: 신규 고객사 추가 용이</li>
        <li><b>플레이스홀더</b>: 미래 관제 기능 확장 대비</li>
        </ul>

        <h4><b>🧪 실험실 - AI 보안 연구</b></h4>
        <div style="background:#e6f7ff; padding:12px; border-left:4px solid #1890ff; margin:10px 0;">
        <b>실험실은 차세대 AI 보안 분석 도구들을 테스트할 수 있는 고급 환경입니다.</b><br>
        4가지 최첨단 보안 분석 기능으로 구성되어 있습니다.
        </div>

        <h5><b>🔬 1. 고급 IOC 추출 및 분석</b></h5>
        <ul>
        <li><b>하이브리드 IOC 추출</b>: 정규식 + AI 기반 95% 정확도</li>
        <li><b>9가지 IOC 타입</b>: IP, 도메인, 해시, 이메일, URL, 프로세스, 레지스트리 등</li>
        <li><b>AI 품질 평가</b>: 각 IOC의 신뢰도와 위험도 자동 점수 매김</li>
        <li><b>캠페인 클러스터링</b>: 연관된 IOC들을 그룹별로 분류</li>
        <li><b>실시간 위협 인텔리전스</b>: VirusTotal, AbuseIPDB API 자동 조회</li>
        <li><b>사용법</b>: 의심스러운 로그나 페이로드를 입력하여 숨어있는 IOC 발견</li>
        </ul>

        <h5><b>⚡ 2. YARA 룰 자동 생성</b></h5>
        <ul>
        <li><b>멀웨어 샘플 업로드</b>: 파일 선택 후 자동 분석</li>
        <li><b>엔트로피 분석</b>: 패킹 탐지 및 의심 구간 식별</li>
        <li><b>PE 헤더 분석</b>: Windows 실행 파일 구조 해부</li>
        <li><b>AI 패턴 최적화</b>: 기계학습으로 오탐 최소화</li>
        <li><b>템플릿 기반 룰</b>: 메타데이터 자동 생성</li>
        <li><b>사용법</b>: 악성코드 파일을 선택하여 탐지 룰 생성, 보안 솔루션에 적용</li>
        </ul>

        <h5><b>🛡️ 3. 멀웨어 정적 분석</b></h5>
        <ul>
        <li><b>종합 파일 분석</b>: PE/ELF 실행 파일 완전 해부</li>
        <li><b>문자열 추출</b>: 악성 URL, 도메인, API 함수 발견</li>
        <li><b>의심 패턴 탐지</b>: 안티-VM, 난독화, C&C 통신 패턴</li>
        <li><b>위험도 스코어링</b>: 0-100점 위험도 수치화</li>
        <li><b>색상별 등급</b>: 녹색(안전) → 주황(의심) → 빨간(위험)</li>
        <li><b>사용법</b>: 의심 파일을 업로드하여 실행 전 위험성 사전 평가</li>
        </ul>

        <h5><b>🎯 4. 위협 헌팅 쿼리 생성</b></h5>
        <ul>
        <li><b>멀티 플랫폼 지원</b>: Splunk, ELK/Elasticsearch, Sigma 룰</li>
        <li><b>IOC 기반 쿼리</b>: 입력된 IOC로 자동 검색 쿼리 생성</li>
        <li><b>고급 헌팅 시나리오</b>: 측면 이동, C&C 통신, 데이터 유출 탐지</li>
        <li><b>MITRE ATT&CK 매핑</b>: 공격 기법별 태깅 자동 적용</li>
        <li><b>시간 범위 설정</b>: 1시간 ~ 30일 검색 구간 조절</li>
        <li><b>쿼리 최적화</b>: 플랫폼별 성능 튜닝 자동 적용</li>
        <li><b>사용법</b>: IOC나 시나리오 선택 → 플랫폼별 탐지 쿼리 생성 → SIEM에 배포</li>
        </ul>

        <h5><b>💡 실험실 활용 워크플로우</b></h5>
        <ol>
        <li><b>1단계 - IOC 추출</b>: 의심 로그에서 악성 지표 발견</li>
        <li><b>2단계 - 헌팅 쿼리</b>: 추출된 IOC로 SIEM 검색 쿼리 생성</li>
        <li><b>3단계 - 파일 분석</b>: 발견된 악성 파일을 정적 분석</li>
        <li><b>4단계 - YARA 룰</b>: 분석 결과로 탐지 룰 생성</li>
        <li><b>5단계 - 배포 적용</b>: 생성된 쿼리와 룰을 보안 솔루션에 적용</li>
        </ol>

        <div style="background:#fff2e8; padding:12px; border-left:4px solid #fa541c; margin:10px 0;">
        <b>🚨 실험실 주의사항</b><br>
        • 실험 환경이므로 중요한 운영 데이터 사용 금지<br>
        • 멀웨어 분석 시 격리된 환경에서 실행 권장<br>
        • 생성된 룰과 쿼리는 검증 후 운영 환경 적용
        </div>

        <h3>⚡ <b>3. 주요 사용법 및 단축키</b></h3>
        
        <h4><b>📋 기본 네비게이션</b></h4>
        <ul>
        <li><b>상단 탭 전환</b>: [보안분석] → [관제 고객사] → [사용가이드]</li>
        <li><b>좌측 메뉴</b>: 각 대분류 내 세부 기능 선택</li>
        <li><b>메인 콘텐츠</b>: 선택된 기능의 전용 화면 표시</li>
        <li><b>실시간 시계</b>: 상단 우측 현재 시간 표시</li>
        </ul>

        <h4><b>🎯 효율적인 작업 흐름</b></h4>
        <ol>
        <li><b>취약점 분석</b>: CVE 검색 → 상세 정보 확인 → 영향도 평가</li>
        <li><b>패턴 등록</b>: 새로작성 → AI 초안 → 수정·저장 → 즐겨찾기</li>
        <li><b>로그 분석</b>: AI 분석 → IOC 추출 → 위협 인텔리전스 → 보고서</li>
        <li><b>이력 관리</b>: 모든 작업 내용 자동 저장 → 재사용</li>
        </ol>

        <h3>💡 <b>4. 고급 팁 & 모범 사례</b></h3>
        <ul>
        <li><b>CVE 검색</b>: 여러 CVE 동시 입력으로 배치 처리 효율화</li>
        <li><b>패턴 관리</b>: AI 초안을 베이스로 실무 경험 추가</li>
        <li><b>AI 분석</b>: 상세한 페이로드 제공 시 정확도 향상</li>
        <li><b>데이터 백업</b>: 로컬 DB 파일 정기 백업 권장</li>
        <li><b>API 키 관리</b>: 환경변수 설정으로 보안성 확보</li>
        </ul>

        <h3>🎨 <b>6. UI/UX 혁신 사항</b></h3>
        <div style="background:#fff7e6; padding:12px; border-left:4px solid #fa8c16; margin:10px 0;">
        <b>✨ 2025년 업그레이드</b><br>
        • <b>3단 계층 구조</b>로 직관적 기능 분류<br>
        • <b>반응형 레이아웃</b> 다양한 화면 크기 대응<br>
        • <b>모던 버튼 디자인</b> Primary/Secondary/Success/Danger
        </div>

        <h3>📊 <b>7. 데이터 보안 및 개인정보</b></h3>
        <ul>
        <li><b>로컬 처리</b>: 모든 데이터는 로컬 저장, 외부 전송 없음</li>
        <li><b>캐시 관리</b>: 민감 정보 자동 만료</li>
        <li><b>감사 로그</b>: 사용 이력 투명 관리</li>
        </ul>

        <hr>
        <div style="background:#f6ffed; padding:16px; border-radius:6px; border:1px solid #b7eb8f;">
        <p style="margin:0; font-size:14pt; color:#389e0d;"><b>🚀 MetaShield 2025 - 차세대 보안 플랫폼</b></p>
        <p style="margin:8px 0 0; font-size:11pt; color:#666;">
        <b>개발/운영:</b> 이철주 선임 |
        <b>기술스택:</b> PyQt6 + Azure OpenAI + SQLite | <b>업데이트:</b> 2025-08-26
        </p>
        </div>"""
