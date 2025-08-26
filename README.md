 ' 🛡️ MetaShield - Advanced Security Analysis Platform

> 차세대 통합 보안 분석 플랫폼으로 AI 기반 페이로드 분석, CVE 취약점 검색, 패턴 분석, AI 실험실 기능을 제공하는 보안 플랫폼 입니다.

 ' ' ✨ 주요 기능

 ' ' ' 🧠 AI 보안 분석
-  Azure OpenAI 기반 페이로드 분석 : GPT-4 모델을 활용한 고도화된 보안 이벤트 자동 분석
-  IOC 추출 : IP, 도메인, URL, 파일 해시 등 침해지표 자동 추출 및 분류
-  위협 인텔리전스 : VirusTotal, AbuseIPDB 연동을 통한 실시간 위협 평판 조회
-  표준화된 보고서 : 위협도 판단부터 대응방안까지 체계적인 분석 리포트
-  MITRE ATT&CK 매핑 : 공격 기법을 MITRE 프레임워크로 분류

 ' ' ' 🔍 CVE 취약점 검색
-  실시간 NVD API 조회 : 최신 CVE 취약점 정보 자동 수집 및 캐싱
-  다중 CVE 검색 : 여러 CVE를 한 번에 검색하는 배치 처리 기능
-  아카이브 관리 : 검색한 CVE 정보 로컬 SQLite 캐싱 및 관리
-  상세 분석 : CVSS 점수, 영향도, CWE 분류, 참고 링크 등 종합 정보 제공
-  엑셀/CSV 내보내기 : 분석 결과를 다양한 형식으로 export

 ' ' ' 📊 패턴 분석 저장소
-  탐지 패턴 관리 : 보안 탐지 룰과 패턴 템플릿 데이터베이스
-  AI 초안 생성 : Azure OpenAI를 활용한 자동 분석 보고서 초안 생성
-  JIRA 연동 : 사내 JIRA 시스템과 연동하여 보안 이벤트 티켓 자동 가져오기
-  검색 및 필터링 : 패턴명, 내용 기반 검색 및 즐겨찾기 관리
-  패턴 효율성 분석 : 기존 패턴의 탐지 성능 및 개선사항 분석

 ' ' ' 🧪 AI 실험실 (신규)
-  고급 IOC 분석기 : AI와 정규식을 결합한 하이브리드 IOC 추출 (95% 정확도)
-  YARA 룰 생성기 : 악성코드 샘플 기반 자동 YARA 탐지 룰 생성
-  멀웨어 정적 분석 : PE/ELF 바이너리 분석 및 위험도 평가 (0-100점)
-  위협 헌팅 쿼리 생성 : Splunk, ELK, Sigma 플랫폼용 쿼리 자동 생성

 ' ' 🚀 설치 및 실행

 ' ' ' 필요 환경
- Python 3.8+
- PyQt6
- requests, pandas, openai, matplotlib, deep_translator 등

 ' ' ' 설치 방법
```bash
 ' 리포지토리 클론
git clone https://github.com/YOUR_USERNAME/MetaShield_Local.git
cd MetaShield

 ' 의존성 설치
pip install PyQt6 requests pandas openai matplotlib deep_translator python-dotenv

 ' 프로그램 실행
python MetaShield_main.py
```

 ' ' 🛠️ 기술 스택

-  Frontend : PyQt6 
-  AI Integration : Azure OpenAI API (GPT-4 기반)
-  Database : SQLite3 (로컬 캐싱)
-  APIs : NVD CVE API, VirusTotal API, AbuseIPDB API, JIRA REST API
-  Language : Python 3.x
-  UI/UX : 모던 Material Design 3 + Ant Design 스타일

 ' ' 📋 프로젝트 구조

```
MetaShield/
├── MetaShield_main.py               ' 메인 애플리케이션 (699 라인)
├── nvd_cve_checker_Pro.py           ' CVE 검색 모듈 (800+ 라인)
├── pattern_dict_tab.py              ' 패턴 분석 모듈 (600+ 라인)
├── comprehensive_report.py          ' 종합 보고서 생성 (376 라인)
├── config.py                        ' 설정 관리 (172 라인)
├── prompts.py                       ' AI 프롬프트 관리 (199 라인)
├── guide_tab.py                     ' 사용자 가이드 (128 라인)
├── pattern_db.py                    ' 패턴 DB 관리 (66 라인)
├── modern_ui_style.py               ' UI 스타일 시스템 (621 라인)
├── advanced_ui_components.py        ' 재사용 UI 컴포넌트 (400+ 라인)
├── enterprise_ui_components.py      ' 엔터프라이즈 UI 컴포넌트
├── advanced_ioc_analyzer.py         ' 고급 IOC 분석기 (AI 실험실)
├── yara_rule_generator.py           ' YARA 룰 생성기 (AI 실험실)
├── malware_static_analyzer.py       ' 멀웨어 정적 분석 (AI 실험실)
├── threat_hunting_query_generator.py  ' 위협 헌팅 쿼리 생성 (AI 실험실)
├── cve_cache_3_1.db                ' CVE 데이터 캐시
└── pattern_dict.db                 ' 패턴 분석 데이터베이스
```

 ' ' 🔧 설정

1. `.env` 파일을 생성하고 API 키 설정:
```env
 ' Azure OpenAI 설정
AZURE_OPENAI_API_KEY=your_api_key_here
AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=your-deployment-name
AZURE_OPENAI_API_VERSION=2024-12-01-preview

 ' 위협 인텔리전스 API 설정
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ABUSEIPDB_API_KEY=your_abuse_api_key_here

 ' JIRA 연동 설정
JIRA_URL=https://your-company.atlassian.net
JIRA_API_USER=your_email@company.com
JIRA_API_TOKEN=your_jira_api_token_here
```

2. 데이터베이스 파일은 자동 생성됩니다
3. 모든 설정은 `config.py`에서 중앙 관리됩니다

 ' ' 📸 스크린샷

*(스크린샷을 추가해주세요)*

 ' ' 👨‍💻 개발자

 이철주 선임  - 보안 분석 전문가
- 개발 기간: 2025년 8월
- 버전: v2.0.0

 ' ' 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 있습니다.

 ' ' 🤝 기여하기

1. 이 저장소를 Fork하세요
2. 새로운 기능 브랜치를 만드세요 (`git checkout -b feature/AmazingFeature`)
3. 변경사항을 커밋하세요 (`git commit -m 'Add some AmazingFeature'`)
4. 브랜치에 푸시하세요 (`git push origin feature/AmazingFeature`)
5. Pull Request를 생성하세요

---
🛡️  MetaShield  - 차세대 보안 분석 플랫폼