 - 📋 MetaShield 코드 구조 문서

 - - 프로젝트 개요
 MetaShield 는 차세대 통합 보안 분석 플랫폼으로, CVE 취약점 검색, AI 기반 보안 분석, 패턴 분석 저장소, AI 실험실, 위협 인텔리전스 등의 기능을 제공하는 엔터프라이즈급 보안 솔루션입니다.

 총 코드 라인 수 : 약 6,000+ 라인 (16개 Python 파일)  
 개발 프레임워크 : PyQt6 (엔터프라이즈급 3단 네비게이션 UI)  
 AI 통합 : Azure OpenAI API (GPT-4 기반)  
 데이터베이스 : SQLite (로컬 캐싱 및 패턴 관리)

---

 - - 📁 파일별 상세 코드 구조

 - - - 1. 🚀  MetaShield_main.py  (699 라인) - 메인 애플리케이션
 역할 : 메인 애플리케이션 창 및 AI 분석 탭 구현

 주요 클래스 :
- `MainWindow`: 메인 애플리케이션 창
- `ModernAnalysisTab`: AI 보안 분석 인터페이스

 핵심 기능 :
-  AI 보안 분석  (`perform_ai_analysis()` - 300~350라인)
  - Azure OpenAI API를 통한 페이로드 분석
  - 실시간 분석 진행 상태 표시
  - 한국어 보안 분석 보고서 생성

-  IOC 추출  (`extract_iocs()` - 400~480라인)
  - IP 주소, 도메인, URL, 파일 해시 추출
  - 정규식 기반 패턴 매칭
  - 중복 제거 및 유효성 검증

-  위협 인텔리전스 조회  (`query_threat_intel()` - 490~650라인)
  - VirusTotal API 연동 (500~550라인)
  - AbuseIPDB API 연동 (580~630라인)
  - HTML 형태로 결과 포맷팅

 API 통합 :
```python
 - Azure OpenAI 설정 (config.py에서 로드)
ai_config = get_ai_config()
client = AzureOpenAI(api_key=ai_config.api_key, ...)
```

---

 - - - 2. 🔍  nvd_cve_checker_Pro.py  (약 800+ 라인) - CVE 취약점 검색
 역할 : NVD CVE 데이터베이스 검색 및 관리

 주요 클래스 :
- `CVECheckerTab`: CVE 검색 메인 인터페이스
- `DBManager`: SQLite 데이터베이스 관리
- `CVEDetailDialog`: CVE 상세정보 표시 다이얼로그

 핵심 기능 :
-  CVE 검색 및 조회  (`search_cves()`)
  - 다중 CVE 코드 입력 지원 (줄바꿈 구분)
  - NVD API 실시간 조회
  - 로컬 캐시 우선 조회

-  데이터베이스 관리  (`DBManager` 클래스)
  - CVE 데이터 캐싱 시스템
  - 검색 기록 관리
  - 즐겨찾기 관리

-  결과 표시 
  - CVSS 점수, CWE, 영향도 분석
  - 테이블 형태 결과 표시
  - 엑셀/CSV 내보내기

 데이터베이스 스키마 :
```sql
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    data TEXT,  -- JSON 형태 CVE 데이터
    timestamp TEXT
)
```

---

 - - - 3. 📚  pattern_dict_tab.py  (약 600+ 라인) - 패턴 분석 저장소
 역할 : 보안 탐지 패턴 및 분석 템플릿 관리

 주요 클래스 :
- `PatternDictTab`: 패턴 분석 메인 인터페이스
- `PatternEditDialog`: 패턴 편집 다이얼로그

 핵심 기능 :
-  패턴 데이터베이스 관리 
  - 탐지명별 분석 템플릿 저장
  - 검색, 즐겨찾기, 별점 시스템
  - 분류별 필터링

-  AI 초안 생성  (`generate_ai_draft()` - 370~420라인)
  - Azure OpenAI를 통한 분석 보고서 자동 생성
  - 표준 보안 분석 포맷 적용

-  JIRA 연동  (`import_jira_tickets()` - 250~340라인)
  - 회사 JIRA 시스템에서 보안 이벤트 가져오기
  - 날짜 범위별 티켓 검색
  - 자동 패턴 데이터 생성

 데이터베이스 스키마 :
```sql
CREATE TABLE patterns (
    id INTEGER PRIMARY KEY,
    name TEXT,           -- 탐지명
    description TEXT,    -- 분석 내용
    category TEXT,       -- 분류
    severity TEXT,       -- 심각도
    is_favorite INTEGER, -- 즐겨찾기
    created_at TEXT
)
```

---

 - - - 4. 🧠  comprehensive_report.py  (376 라인) - 종합 보고서 생성
 역할 : 모든 분석 결과를 통합한 종합 보고서 생성

 주요 클래스 :
- `ComprehensiveReportGenerator`: 보고서 생성 엔진
- `ComprehensiveReportDialog`: 보고서 표시 다이얼로그

 핵심 기능 :
-  데이터 통합  (`generate_comprehensive_report()` - 54~80라인)
  - AI 분석 결과
  - CVE 취약점 정보
  - IOC 추출 데이터
  - 위협 인텔리전스 결과

-  AI 기반 최종 보고서 생성  (`generate_final_report_with_ai()` - 82~240라인)
  - 관제업체용 실무 보고서 포맷
  - 고객사 담당자 대상 요약
  - 즉시 조치사항 및 권고사항

 보고서 구조 :
```
🚨 보안 위협 탐지 보고서
├── 📊 탐지 현황 요약
├── 🔍 상세 분석  
├── ✅ 대응 권고사항
└── 📋 기술적 세부사항
```

---

 - - - 5. ⚙️  config.py  (158 라인) - 설정 관리
 역할 : 모든 API 키 및 애플리케이션 설정 중앙 관리

 주요 클래스 :
- `AIConfig`: Azure OpenAI API 설정
- `ThreatIntelConfig`: 위협 인텔리전스 API 설정  
- `JiraConfig`: JIRA API 설정
- `DatabaseConfig`: 데이터베이스 경로 설정
- `UIConfig`: UI 레이아웃 설정

 보안 기능 :
- 환경변수(.env)에서 API 키 자동 로드
- API 설정 유효성 검사
- 하드코딩 방지 시스템

 설정 예시 :
```python
@dataclass
class AIConfig:
    endpoint: str = "https://cj-openai.openai.azure.com/"
    api_key: str = ""   - 환경변수에서 로드
    deployment: str = "cj-sec-analyst-gpt"
    api_version: str = "2024-12-01-preview"
```

---

 - - - 6. 💬  prompts.py  (199 라인) - AI 프롬프트 템플릿
 역할 : Azure OpenAI용 보안 분석 프롬프트 중앙 관리

 주요 클래스 :
- `SecurityPrompts`: 보안 분석 프롬프트 모음
- `PromptConfig`: 프롬프트 설정 및 파라미터

 프롬프트 종류 :
-  기본 보안 분석 : 일반적인 보안 이벤트 분석
-  웹 공격 분석 : SQL Injection, XSS 등 웹 취약점
-  네트워크 침입 : 네트워크 기반 공격 분석
-  악성코드 분석 : 파일 기반 위협 분석

 프롬프트 구조 :
```python
SECURITY_ANALYSIS_PROMPT = """
너는 15년 경력의 시니어 보안 분석가이다.
다음 보안 이벤트를 분석해줘:

{payload}

분석 형식:
1. 위협 유형 및 심각도
2. 공격 시나리오 분석  
3. 영향도 평가
4. 대응 방안
5. IOC 정보
"""
```

---

 - - - 7. 📖  guide_tab.py  (128 라인) - 사용자 가이드
 역할 : MetaShield 사용법 및 보안 분석 가이드 제공

 주요 클래스 :
- `GuideTab`: 가이드 표시 인터페이스

 가이드 내용  (`get_default_guide_html()` - 54~127라인):
- MetaShield 기능 소개
- 각 탭별 사용법 상세 설명
- 보안 분석 실무 팁
- 보고서 작성 가이드

---

 - - - 8. 🎨  modern_ui_style.py  (약 200 라인) - UI 스타일 시스템
 역할 : 현대적 UI 디자인 시스템 정의

 스타일 구성 :
-  색상 팔레트 :  -1890ff (액센트),  -fafafa (배경)
-  폰트 시스템 : 'Malgun Gothic', '맑은 고딕'
-  컴포넌트 스타일 : 버튼, 입력창, 테이블, 카드

 테마 지원 :
```python
MODERN_STYLE = """
QWidget {
    background-color:  -fafafa;
    color:  -262626;
    font-family: 'Malgun Gothic', '맑은 고딕';
}
"""
```

---

 - - - 9. 🧩  advanced_ui_components.py  (약 400 라인) - UI 컴포넌트 라이브러리
 역할 : 재사용 가능한 현대적 UI 컴포넌트

 주요 컴포넌트 :
- `Card`: 카드형 컨테이너
- `PrimaryButton`, `SecondaryButton`: 통일된 버튼 시스템
- `SearchInput`: 검색 입력창
- `ModernTable`: 현대적 테이블
- `StatusBadge`: 상태 표시 뱃지
- `LoadingSpinner`: 로딩 애니메이션

---

 - - - 10. 💾  pattern_db.py  (추정 100+ 라인) - 패턴 데이터베이스
 역할 : 패턴 분석 데이터베이스 스키마 및 관리

---

 - - 🔧 주요 기술 스택 및 의존성

 - - - 핵심 라이브러리
-  PyQt5 : GUI 프레임워크
-  requests : HTTP API 통신
-  sqlite3 : 로컬 데이터베이스
-  openai : Azure OpenAI API 클라이언트
-  re : 정규식 패턴 매칭
-  json : 데이터 직렬화
-  datetime : 시간 관리

 - - - API 통합
-  Azure OpenAI : GPT 기반 보안 분석
-  NVD API : CVE 취약점 정보
-  VirusTotal API : 파일/IP 평판 조회
-  AbuseIPDB API : IP 평판 조회  
-  JIRA API : 보안 이벤트 티켓 연동

---

 - - 📊 코드 품질 및 보안

 - - - 보안 강화 사항
- ✅  API 키 분리 : 모든 민감한 정보를 .env 파일로 분리
- ✅  환경변수 관리 : config.py를 통한 중앙화된 설정 관리
- ✅  유효성 검사 : API 설정 유효성 자동 검증
- ✅  버전관리 제외 : .gitignore를 통한 민감한 파일 제외

 - - - 코드 최적화
- ✅  중복 코드 제거 : 프롬프트 템플릿 중앙화
- ✅  모듈화 : 기능별 명확한 파일 분리
- ✅  재사용성 : 공통 UI 컴포넌트 라이브러리
- ✅  한국어 현지화 : 완전한 한국어 사용자 경험

---

 - - 🚀 최근 개선사항 (2025년 8월)

 - - - 보안 강화
1.  API 키 완전 분리 : comprehensive_report.py, pattern_dict_tab.py의 하드코딩된 API 키 제거
2.  JIRA API 보안 : JIRA 인증 정보 환경변수 이관
3.  통합 설정 시스템 : config.py를 통한 모든 API 설정 중앙 관리

 - - - 코드 최적화  
1.  프롬프트 통합 : MetaShield_main.py의 중복 프롬프트를 prompts.py로 이관
2.  아키텍처 정리 : ModernAnalysisTab 클래스로 통합, 중복 클래스 제거
3.  가이드 이관 : 하드코딩된 가이드 내용을 guide_tab.py로 이동

---

---

 - - 🧪 AI 실험실 모듈 (신규 추가)

 - - - 11. 🔬 advanced_ioc_analyzer.py (약 400+ 라인) - 고급 IOC 분석기
 역할 : AI와 정규식을 결합한 하이브리드 IOC 추출 및 분석

 주요 클래스 :
- `AdvancedIOCAnalyzer`: 메인 IOC 분석 엔진
- `IOCExtractionTab`: UI 인터페이스

 핵심 기능 :
-  하이브리드 IOC 추출  (95% 정확도)
  - 정규식 기반 1차 추출: IP, 도메인, URL, 해시, 이메일 등 9개 타입
  - AI 기반 품질 점수: 0-100점 신뢰도 평가
  - 중복 제거 및 유효성 검증

-  위협 인텔리전스 연동 
  - VirusTotal API: 파일 해시, URL, 도메인 평판 조회
  - AbuseIPDB API: IP 주소 악성 여부 확인
  - 실시간 위협 점수 표시

-  결과 시각화 
  - IOC 타입별 색상 구분
  - 위협 점수 기반 정렬
  - 상세 정보 툴팁 제공

 - - - 12. 🛡️ yara_rule_generator.py (약 350+ 라인) - YARA 룰 생성기
 역할 : 악성코드 샘플 기반 자동 YARA 탐지 룰 생성

 주요 클래스 :
- `YaraRuleGenerator`: YARA 룰 생성 엔진
- `YaraRuleTab`: UI 인터페이스

 핵심 기능 :
-  바이너리 분석 
  - 파일 엔트로피 계산: 패킹/암호화 탐지
  - PE 헤더 분석: 컴파일 시간, 섹션 정보
  - 문자열 패턴 추출: 의심스러운 API, 레지스트리 키

-  YARA 룰 자동 생성 
  - 메타 정보: 생성 날짜, 분석자, 파일 해시
  - 문자열 조건: 특징적인 바이너리 패턴
  - 조건부 로직: 파일 크기, 엔트로피, PE 속성 조합

-  템플릿 기반 생성 
  - 표준 YARA 룰 포맷 준수
  - 메타데이터 자동 삽입
  - 주석 및 설명 자동 생성

 - - - 13. 🦠 malware_static_analyzer.py (약 450+ 라인) - 멀웨어 정적 분석기
 역할 : PE/ELF 바이너리 정적 분석 및 위험도 평가

 주요 클래스 :
- `MalwareStaticAnalyzer`: 정적 분석 엔진
- `MalwareAnalysisTab`: UI 인터페이스

 핵심 기능 :
-  바이너리 형식 분석 
  - PE 파일: Windows 실행 파일 분석
  - ELF 파일: Linux 바이너리 분석
  - 파일 헤더 검증 및 구조 분석

-  위험도 평가 시스템  (0-100점)
  - 엔트로피 분석: 패킹/난독화 탐지 (30점)
  - API 호출 분석: 악성 행위 API 탐지 (25점)
  - 문자열 분석: 의심스러운 키워드 (20점)
  - 구조적 이상: PE 헤더 비정상 (25점)

-  상세 정보 추출 
  - 컴파일 시간, 링커 버전, 섹션 정보
  - 임포트/익스포트 함수 목록
  - 리소스 정보 및 버전 정보
  - 디지털 서명 검증

 - - - 14. 🎯 threat_hunting_query_generator.py (약 400+ 라인) - 위협 헌팅 쿼리 생성기
 역할 : 다중 플랫폼 위협 헌팅 쿼리 자동 생성

 주요 클래스 :
- `ThreatHuntingQueryGenerator`: 쿼리 생성 엔진
- `ThreatHuntingTab`: UI 인터페이스

 핵심 기능 :
-  다중 플랫폼 지원 
  - Splunk SPL: 엔터프라이즈 SIEM 쿼리
  - ELK/Elasticsearch: 오픈소스 로그 분석
  - Sigma Rules: 플랫폼 독립적 탐지 룰

-  MITRE ATT&CK 매핑 
  - 공격 기법별 쿼리 템플릿
  - 전술(Tactic) 및 기법(Technique) 분류
  - 관련 IOC 자동 매핑

-  쿼리 최적화 
  - 시간 범위 자동 설정
  - 인덱스 효율성 고려
  - False Positive 최소화

 - - - 15. 🏢 enterprise_ui_components.py (약 300+ 라인) - 엔터프라이즈 UI 시스템
 역할 : FortiOS/팔로알토 스타일 3단 네비게이션 UI

 주요 클래스 :
- `TopNavigationBar`: 상단 대분류 탭 + 시계
- `SideNavigationPanel`: 좌측 세부 기능 탭
- `EnterpriseDashboard`: 관제 고객사 템플릿

 핵심 기능 :
-  3단 계층 네비게이션 
  - 대분류: 보안분석, 관제 고객사, 사용가이드
  - 세부분류: 기능별 서브 탭
  - 콘텐츠: 선택된 기능의 전용 화면

-  확장 가능한 구조 
  - 관제 고객사: 굿리치, 컬리, 핀다, GLN, 한화시스템
  - 실험실 서브 탭: 4개 AI 분석 도구
  - 모듈형 설계로 신규 기능 추가 용이

---

 문서 최종 업데이트 : 2025년 8월 26일  
 코드 리뷰어 : 이철주 
 프로젝트 상태 : ✅ AI 실험실 기능 완성, 엔터프라이즈 UI 구축 완료

> 이 문서는 MetaShield 프로젝트의 전체 코드 구조를 이해하고 유지보수하기 위한 기술 문서입니다. AI 실험실 모듈과 엔터프라이즈 UI 시스템이 새롭게 추가되어 차세대 보안 분석 플랫폼으로 발전했습니다.
