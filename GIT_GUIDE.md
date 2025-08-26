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
cd "C:\Users\Metanet\Desktop\Python 자동화 테스트\MetaShield\백업\MetaShield_local_250825\MetaShield_local_2"

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
git commit -m "🎉 Initial commit: MetaShield v2.0.0

✨ Features:
- AI 보안 분석 시스템
- CVE 취약점 검색
- 패턴 분석 저장소  
- AI 실험실 (IOC 분석기, YARA 생성기, 멀웨어 분석기, 위협 헌팅)
- 엔터프라이즈급 3단 네비게이션 UI

🛠️ Tech Stack:
- Python 3.8+ / PyQt6
- Azure OpenAI API
- SQLite3, VirusTotal API, AbuseIPDB API, JIRA API

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
pip install PyQt6 requests pandas openai matplotlib deep_translator python-dotenv

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
- 4개 카테고리 기반 점수 산정"

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

' 🔥 코드/파일 제거
git commit -m "🔥 remove: 불필요한 테스트 파일 제거"

' 🚀 배포
git commit -m "🚀 deploy: v2.1.0 릴리즈"

' 🔒 보안
git commit -m "🔒 security: API 키 하드코딩 제거"
```

---

'' 🌿 브랜치 전략

''' 기본 브랜치 구조

```
main (기본 브랜치)
├── feature/새기능명 (기능 개발)
├── fix/버그명 (버그 수정)
├── docs/문서명 (문서 작업)
└── release/v2.1.0 (릴리즈 준비)
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

''' 릴리즈 브랜치

```bash
' 릴리즈 준비
git checkout -b release/v2.1.0

' 버그 수정 및 문서 정리 후
git checkout main
git merge release/v2.1.0

' 태그 생성
git tag v2.1.0
git push origin main --tags

' 릴리즈 브랜치 삭제
git branch -d release/v2.1.0
```

---

'' ⚔️ 충돌 해결

''' 충돌 발생 시

```bash
' pull 시 충돌 발생
git pull origin main
' Auto-merging 파일명.py
' CONFLICT (content): Merge conflict in 파일명.py

' 충돌 파일 확인
git status
```

''' 충돌 파일 편집

충돌이 발생한 파일을 열면 다음과 같은 마커가 보입니다:

```python
def some_function():
<<<<<<< HEAD
    ' 현재 브랜치의 코드
    return "local_change"
=======
    ' 원격 브랜치의 코드  
    return "remote_change"
>>>>>>> origin/main
```

 해결 방법: 
1. 필요한 코드만 남기고 마커 제거
2. 두 코드를 모두 통합
3. 완전히 새로운 코드로 대체

```python
def some_function():
    ' 통합된 최종 코드
    return "merged_change"
```

''' 충돌 해결 완료

```bash
' 충돌 해결 후
git add .
git commit -m "🔀 merge: 충돌 해결 및 코드 통합"
git push origin main
```

---

'' 📁 선택적 파일 업로드

''' 방법 1: .gitignore 사용 (권장)

 단계별 설정: 

```bash
' 1. .gitignore 파일 생성/편집
echo "' 업로드하지 않을 파일들" > .gitignore

' 2. 제외하려는 파일/폴더 추가
echo "*.py" >> .gitignore        ' 모든 Python 파일 제외
echo "*.db" >> .gitignore        ' 모든 데이터베이스 파일 제외
echo "config.py" >> .gitignore   ' 특정 파일 제외
echo "__pycache__/" >> .gitignore ' 특정 폴더 제외

' 3. README.md만 포함하고 싶다면
echo "*" >> .gitignore           ' 모든 파일 제외
echo "!README.md" >> .gitignore  ' README.md만 포함
echo "!.gitignore" >> .gitignore ' .gitignore 자체도 포함
```

 README.md와 문서들만 업로드하는 .gitignore 예시: 

```gitignore
' 모든 파일 제외
*

' 문서 파일들만 포함
!README.md
!*.md
!.gitignore
!.env.example

' 특정 폴더의 문서만 포함 (필요시)
!docs/
!docs/ /*.md
```

''' 방법 2: 수동 선택 추가

```bash
' 특정 파일만 추가
git add README.md
git add GIT_GUIDE.md
git add LABORATORY_FEATURES.md

' 패턴으로 추가
git add *.md

' 확인 후 커밋
git status
git commit -m "📝 docs: 프로젝트 문서 업로드"
git push origin main
```

''' 방법 3: 이미 추적중인 파일 제외

```bash
' 이미 Git에 추가된 파일을 제외하고 싶은 경우
git rm --cached 파일명.py
git rm --cached -r 폴더명/

' .gitignore에 추가
echo "파일명.py" >> .gitignore
echo "폴더명/" >> .gitignore

' 커밋
git add .gitignore
git commit -m "🔥 remove: 불필요한 파일 추적 제거"
git push origin main
```

---

'' 🛠️ 고급 Git 명령어

''' 히스토리 관리

```bash
' 커밋 히스토리 예쁘게 보기
git log --oneline --graph --all --decorate

' 특정 파일의 변경 이력
git log -p MetaShield_main.py

' 특정 기간의 커밋 보기
git log --since="2025-08-01" --until="2025-08-31"

' 작업 내용 임시 저장
git stash
git stash list
git stash pop

' 특정 커밋으로 되돌리기 (주의!)
git reset --hard HEAD~1      ' 이전 커밋으로 (위험)
git reset --soft HEAD~1      ' 커밋만 취소 (안전)
```

''' 브랜치 관리

```bash
' 모든 브랜치 확인
git branch -a

' 원격 브랜치 정보 업데이트
git fetch --all

' 병합된 브랜치 정리
git branch --merged | grep -v main | xargs -n 1 git branch -d

' 원격의 삭제된 브랜치 정리
git remote prune origin
```

''' 실수 복구

```bash
' 마지막 커밋 메시지 수정
git commit --amend -m "새로운 커밋 메시지"

' 파일을 이전 상태로 복구
git checkout HEAD -- 파일명.py

' 커밋 취소 (안전하게)
git revert HEAD
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
- [ ] 최종 커밋 (`git commit -m "...올늘 작업 요약..."`)
- [ ] `git push origin main`
- [ ] 다음 작업 계획 메모

''' 🎯 주간 관리
- [ ] 불필요한 브랜치 정리
- [ ] 태그 생성 (버전 릴리즈 시)
- [ ] README.md 및 문서 업데이트
- [ ] 의존성 버전 체크

---

'' 🚨 주의사항 및 베스트 프랙티스

''' ⚠️ 절대 커밋하면 안 되는 것들

1.  API 키 및 비밀번호 
   ```bash
   .env
   config_local.py
   secrets.py
   ```

2.  데이터베이스 파일 
   ```bash
   *.db
   *.sqlite
   ```

3.  대용량 파일 
   ```bash
   *.zip
   *.exe
   *.msi
   ```

4.  시스템 파일 
   ```bash
   __pycache__/
   .DS_Store
   Thumbs.db
   ```

''' ✅ 좋은 관습들

1.  커밋 전 항상 테스트 
   ```bash
   python MetaShield_main.py  ' 실행 테스트
   git add .
   git commit -m "✨ feat: 새 기능 추가"
   ```

2.  의미있는 커밋 메시지 
   - 무엇을 했는지 명확하게
   - 왜 했는지 설명 (필요시)
   - 이모지로 카테고리 구분

3.  정기적인 백업 
   ```bash
   ' 하루 최소 1회 push
   git push origin main
   ```

4.  브랜치 활용 
   ```bash
   ' 큰 기능 개발시 별도 브랜치
   git checkout -b feature/new-analyzer
   ```

''' 🔒 보안 관련

 이미 커밋된 비밀 정보 완전 제거: 
```bash
' 히스토리에서 완전 제거 (위험한 명령어!)
git filter-branch --force --index-filter \
'git rm --cached --ignore-unmatch .env' \
--prune-empty --tag-name-filter cat -- --all

' 강제 푸시
git push origin --force --all
```

''' 📱 GUI 도구 추천

1.  GitHub Desktop  (초보자 추천)
   - 직관적인 인터페이스
   - 드래그 앤 드롭으로 파일 관리

2.  VS Code Git 확장 
   - 코드 에디터에 통합
   - 실시간 차이점 확인

3.  SourceTree  (고급 기능)
   - 복잡한 브랜치 관리
   - 시각적 히스토리 표시

---

'' 🆘 문제 해결 FAQ

''' Q: push가 거부될 때
```bash
' 에러: ! [rejected] main -> main (fetch first)
git pull origin main
' 충돌 해결 후
git push origin main
```

''' Q: 잘못된 파일을 커밋했을 때
```bash
' 마지막 커밋에서 파일 제거
git reset --soft HEAD~1
git reset HEAD 파일명.py
git commit -m "수정된 커밋 메시지"
```

''' Q: .gitignore가 작동하지 않을 때
```bash
' 캐시 삭제 후 다시 추가
git rm -r --cached .
git add .
git commit -m "🔧 fix: .gitignore 적용"
```

''' Q: 원격 저장소 URL 변경
```bash
git remote set-url origin https://github.com/새계정/새저장소.git
```

---

 🎉 이제 MetaShield를 여러 PC에서 안전하게 관리할 수 있습니다! 

📝  작성일 : 2025-08-26  
👨‍💻  작성자 : 이철주  
📊  버전 : v1.0


● 🧪 MetaShield 실험실 테스트용 샘플 파일 가이드

  ⚠️ 중요한 보안 주의사항
  악성코드 샘플은 격리된 가상 환경에서만 사용하세요!
  실제 시스템에서 테스트하면 보안 위험이 있습니다.

  🎯 테스트 시나리오별 샘플 파일

  1. 🦠 멀웨어 정적 분석 테스트

  안전한 테스트 파일들 (실제 악성코드 아님)

  EICAR 테스트 파일:
  ' 메모장에서 다음 텍스트를 입력 후 eicar.com으로 저장
  X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-F
  ILE!$H+H*
  - 설명: 안티바이러스 테스트용 표준 파일
  - 위험도: 무해 (실제 악성코드 아님)
  - 점수 예상: 15-25점 (LOW)

  실제 악성코드 샘플 (주의 필요)

  1. VirusTotal 샘플
  - 링크: https://www.virustotal.com/gui/home/search
  - 사용법:
  1. 검색창에 파일 해시 입력
  2. 샘플 다운로드 (로그인 필요)
  3. 가상머신에서만 테스트
  - 추천 해시들:
  MD5: 44d88612fea8a8f36de82e1278abb02f  ' 테스트용 샘플
  SHA1: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc ' 경량 샘플

  2. MalwareBazaar
  - 링크: https://bazaar.abuse.ch/
  - 특징:
    - 최신 악성코드 샘플 제공
    - 연구 목적 무료 다운로드
    - 분류별 검색 가능
  - 다운로드:
  1. Browse 탭 클릭
  2. 파일 형식 선택 (PE32, ELF 등)
  3. Download 클릭 (비밀번호: infected)

  3. Hybrid Analysis
  - 링크: https://www.hybrid-analysis.com/
  - 사용법: 공개 샘플 검색 및 다운로드

  2. 🛡️ YARA 룰 생성기 테스트

  PE 파일 샘플들

  정상 PE 파일:
  ' Windows 시스템 파일 사용 (안전함)
  C:\Windows\System32\notepad.exe    ' 메모장
  C:\Windows\System32\calc.exe       ' 계산기
  C:\Windows\System32\ping.exe       ' 네트워크 도구

  패킹된 파일 샘플:
  - UPX 패커: https://upx.github.io/
  ' 정상 파일을 UPX로 패킹해서 테스트
  upx.exe -9 notepad_copy.exe  ' 최대 압축
  - 예상 결과: 엔트로피 7.5+ 점수

  3. 🔬 고급 IOC 분석기 테스트

  IOC 포함 로그 샘플

  테스트용 보안 이벤트 로그 생성