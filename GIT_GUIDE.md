' 🚀 MetaShield GitHub 버전 관리 완전 가이드

> MetaShield 프로젝트를 여러 PC에서 안전하고 효율적으로 관리하기 위한 Git/GitHub 사용 가이드입니다.

'' 📋 목차
1. [초기 GitHub 리포지토리 설정]('초기-github-리포지토리-설정)
2. [프로젝트 업로드]('프로젝트-업로드)
3. [다른 PC에서 작업하기]('다른-pc에서-작업하기)
4. [일상적인 버전 관리 워크플로우]('일상적인-버전-관리-워크플로우)
5. [브랜치 전략]('브랜치-전략)
6. [충돌 해결]('충돌-해결)
7. [선택적 파일 업로드]('선택적-파일-업로드)

---

'' 🌟 초기 GitHub 리포지토리 설정

''' 1단계: GitHub 리포지토리 생성

1.  GitHub.com 접속  → 로그인
2.  "New repository" 버튼 클릭 
3.  리포지토리 설정 :
   ```
   Repository name: MetaShield
   Description: 🛡️ Advanced Security Analysis Platform with AI Laboratory
   ✅ Public (또는 Private - 회사 프로젝트라면 Private 권장)
   ✅ Add a README file
   ✅ Add .gitignore (Python 선택)
   ❌ Choose a license (나중에 추가 가능)
   ```

''' 2단계: 로컬 Git 설정

```bash
' Git 사용자 정보 설정 (처음 한 번만)
git config --global user.name "이철주"
git config --global user.email "your-email@company.com"

' 기본 브랜치명 설정
git config --global init.defaultBranch main

' 에디터 설정 (선택사항)
git config --global core.editor "code --wait"  ' VS Code 사용시
```

---

'' 📤 프로젝트 업로드

''' 1단계: 현재 프로젝트 폴더에서 Git 초기화

```bash
' 프로젝트 폴더로 이동
cd "C:\Users\Metanet\Desktop\Python 자동화 테스트\MetaShield\MetaShield_git\MetaShield_local\MetaShield_local"

' Git 초기화
git init
```

''' 2단계: .gitignore 파일 생성

프로젝트 루트에 `.gitignore` 파일 생성:

```gitignore
' Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

' 환경변수 및 비밀 정보
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

' 데이터베이스 파일
*.db
*.sqlite
*.sqlite3

' 로그 파일
*.log
*.out

' 임시 파일
*.tmp
*.temp
*~
*.bak
*.orig

' IDE 설정 파일
.vscode/
.idea/
*.swp
*.swo
.DS_Store

' Windows
Thumbs.db
ehthumbs.db
Desktop.ini
$RECYCLE.BIN/

' 프로젝트 특정 파일
cve_cache_3_1.db
pattern_dict.db
*.spec

' API 키 및 설정 파일
config_local.py
secrets.py

' 테스트 파일
test_*.py
*_test.py
tests/
```

''' 3단계: 환경변수 템플릿 파일 생성

`.env.example` 파일 생성:

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

''' 4단계: 리모트 연결 및 업로드

```bash
' GitHub 리포지토리와 연결 (본인 계정명으로 변경)
git remote add origin https://github.com/YOUR_USERNAME/MetaShield.git

' 현재 브랜치를 main으로 변경
git branch -M main

' 모든 파일 스테이징
git add .

' 첫 번째 커밋
git commit -m "🎉 Initial commit: MetaShield v2.1.0

✨ Features:
- AI 보안 분석 시스템 (Azure OpenAI GPT-4 연동)
- CVE 취약점 검색 (NVD API 연동)
- 패턴 분석 저장소 (JIRA 연동)
- AI 실험실 13개 기능 완성
  * 고급 IOC 분석기, YARA 룰 생성기
  * 멀웨어 정적 분석기, 위협 헌팅 쿼리 생성기
  * AI 로그 스토리텔링, AI 보안정책 생성기
  * AI 보안 시나리오 시뮬레이터, AI 취약점 영향도 예측기
- 엔터프라이즈급 3단 네비게이션 UI (FortiOS/팔로알토 스타일)

🛠️ Tech Stack:
- Python 3.8+ / PyQt6
- Azure OpenAI API, SQLite3
- VirusTotal API, AbuseIPDB API, JIRA API
- 현대적 UI/UX 디자인 시스템

📈 Status:
- 총 6,000+ 라인 코드
- 실험실 기능 100% 완성
- Production Ready

📝 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

' GitHub에 업로드
git push -u origin main
```

---

'' 💻 다른 PC에서 작업하기

''' PC A → PC B로 이동할 때

 PC B에서 수행: 

```bash
' 1. 리포지토리 클론
git clone https://github.com/YOUR_USERNAME/MetaShield.git
cd MetaShield

' 2. 가상환경 설정
python -m venv venv
venv\Scripts\activate  ' Windows
' 또는
source venv/bin/activate  ' Mac/Linux

' 3. 의존성 설치
pip install PyQt6 requests pandas openai matplotlib deep_translator python-dotenv psutil

' 4. 환경변수 설정
copy .env.example .env  ' Windows
' cp .env.example .env  ' Mac/Linux
' .env 파일을 편집하여 API 키 입력

' 5. 작업 준비 완료
python MetaShield_main.py
```

---

'' 🔄 일상적인 버전 관리 워크플로우

''' 매일 작업 시작 전

```bash
' 최신 코드 받기
git pull origin main

' 현재 상태 확인
git status

' 브랜치 확인
git branch
```

''' 작업 중 저장 (수시로)

```bash
' 변경사항 확인
git status
git diff

' 특정 파일만 스테이징
git add MetaShield_main.py
git add advanced_ioc_analyzer.py

' 또는 모든 변경사항 스테이징
git add .

' 커밋 (의미있는 메시지 작성)
git commit -m "🔧 Fix: 위협 헌팅 쿼리 UI 레이아웃 개선

- QGroupBox 기반 섹션 구분으로 가독성 향상
- 한국어 라벨 적용 및 매핑 시스템 구현
- 시간 범위 선택 UI 개선"
```

''' 작업 완료 후 업로드

```bash
' GitHub에 업로드
git push origin main
```

''' 📝 커밋 메시지 컨벤션

 이모지 + 타입 + 간단한 설명  형식 사용:

```bash
' ✨ 기능 추가
git commit -m "✨ feat: AI 실험실 멀웨어 분석기 추가

- PE/ELF 바이너리 정적 분석 구현
- 0-100점 위험도 평가 시스템
- 4개 카테고리 기반 점수 산정

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

' 🐛 버그 수정
git commit -m "🐛 fix: JIRA API 연동 404 오류 해결

- API v2 엔드포인트 사용
- URL 구성 방식 변경
- 에러 핸들링 강화"

' 📝 문서 업데이트
git commit -m "📝 docs: 실험실 기능 상세 문서 추가

- 4개 AI 도구 완전 분석
- 코드 소스 및 구현 로직 문서화
- 기대 결과 및 성능 지표 포함"

' 💄 UI/UX 개선
git commit -m "💄 style: 위협 헌팅 쿼리 UI 개선

- 좌측 패널 레이아웃 재구성
- 한국어 인터페이스 적용
- 사용자 친화적 컨트롤 배치"

' ♻️ 리팩토링
git commit -m "♻️ refactor: 코드 구조 개선

- 중복 코드 제거
- 함수 분리 및 모듈화
- 성능 최적화"

' 🔒 보안
git commit -m "🔒 security: API 키 하드코딩 제거

- config.py 환경변수 시스템 적용
- .env 파일로 민감한 정보 분리
- 보안 설정 검증 로직 추가"
```

---

'' 🌿 브랜치 전략

''' 기본 브랜치 구조

```
main (기본 브랜치)
├── feature/새기능명 (기능 개발)
├── fix/버그명 (버그 수정)
├── docs/문서명 (문서 작업)
└── release/v2.2.0 (릴리즈 준비)
```

''' 기능별 개발 브랜치 사용

```bash
' 새 기능 개발 시
git checkout -b feature/advanced-yara-generator

' 작업 후
git add .
git commit -m "✨ feat: 고급 YARA 룰 생성기 구현"
git push origin feature/advanced-yara-generator

' GitHub에서 Pull Request 생성 후 merge

' 메인 브랜치로 돌아가기
git checkout main
git pull origin main

' 완료된 브랜치 삭제
git branch -d feature/advanced-yara-generator
git push origin --delete feature/advanced-yara-generator
```

---

'' ⚠️ 주의사항 및 베스트 프랙티스

''' 🚨 절대 커밋하면 안 되는 것들

1.  API 키 및 비밀번호 
   ```bash
   .env
   config_local.py
   secrets.py
   api_keys.txt
   ```

2.  데이터베이스 파일 
   ```bash
   *.db
   *.sqlite
   cve_cache_3_1.db
   pattern_dict.db
   ```

3.  대용량 파일 
   ```bash
   *.zip
   *.exe
   *.msi
   *.bin
   ```

4.  시스템 파일 
   ```bash
   __pycache__/
   .DS_Store
   Thumbs.db
   *.pyc
   ```

''' ✅ 좋은 관습들

1.  커밋 전 항상 테스트 
   ```bash
   python MetaShield_main.py  ' 실행 테스트
   python -m py_compile *.py  ' 구문 검사
   git add .
   git commit -m "✨ feat: 새 기능 추가"
   ```

2.  의미있는 커밋 메시지 
   - 무엇을 했는지 명확하게
   - 왜 했는지 설명 (필요시)
   - 이모지로 카테고리 구분
   - Claude Code 협업 표시

3.  정기적인 백업 
   ```bash
   ' 하루 최소 1회 push
   git push origin main
   ```

---

'' 📋 일일 워크플로우 체크리스트

''' 🌅 작업 시작 시
- [ ] `git pull origin main` - 최신 코드 받기
- [ ] `git status` - 현재 상태 확인
- [ ] 가상환경 활성화 (`venv\Scripts\activate`)
- [ ] 의존성 업데이트 확인

''' 💻 작업 중
- [ ] 기능별로 작은 단위 커밋
- [ ] 의미있는 커밋 메시지 작성 (이모지 + 설명)
- [ ] 정기적으로 `git push` (하루 1-2회)
- [ ] 코드 테스트 후 커밋

''' 🌆 작업 종료 시  
- [ ] 모든 변경사항 스테이징 (`git add .`)
- [ ] 최종 커밋 (`git commit -m "...오늘 작업 요약..."`)
- [ ] `git push origin main`
- [ ] 다음 작업 계획 메모

---

'' 🎯 MetaShield 전용 커밋 템플릿

```bash
' AI 실험실 기능 개발
git commit -m "🧪 lab: [기능명] 구현

- [구현 내용 요약]
- [주요 기능 설명]
- [성능/정확도 정보]

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

' UI/UX 개선
git commit -m "🎨 ui: [UI 요소] 개선

- [변경 내용]
- [사용자 경험 개선 사항]
- [레이아웃 최적화]"

' 보안 강화
git commit -m "🔒 security: [보안 영역] 강화

- [보안 이슈 해결]
- [API 키 보호]
- [데이터 암호화/검증]"

' 성능 최적화  
git commit -m "⚡ perf: [대상] 성능 개선

- [최적화 내용]
- [성능 향상 수치]
- [메모리/CPU 사용량 개선]"
```

---

 🎉 이제 MetaShield v2.1.0을 여러 PC에서 안전하게 관리할 수 있습니다! 

📝  최종 업데이트 : 2025-08-28  
👨‍💻  작성자 : 이철주  
📊  문서 버전 : v2.1.0  
🛡️  프로젝트 상태 : Production Ready