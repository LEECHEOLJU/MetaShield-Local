import json
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QListWidget, QTextEdit,
    QMessageBox, QLabel, QFileDialog, QApplication, QDateEdit, QSplitter, QProgressDialog
)
from PyQt6.QtCore import Qt, QDate, pyqtSlot, QMetaObject, Q_ARG
from datetime import datetime
import requests
from pattern_db import PatternDB
import os, csv, requests
from modern_ui_style import MODERN_STYLE, DARK_THEME
from advanced_ui_components import Card, ActionButton, SecondaryButton, SearchInput, SidebarList, StatusBadge, Divider

class PatternDictTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(MODERN_STYLE)
        self.db = PatternDB()
        self.selected_id = None
        self.setup_ui()

    def setup_ui(self):
        """Setup modern UI with card-based layout"""
        # Main layout with proper spacing
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(24)

        # Header section
        header_section = self.create_header_section()
        main_layout.addWidget(header_section)

        # Main content area with horizontal splitter
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        content_splitter.setHandleWidth(8)

        # Left panel - Pattern list and search
        left_panel = self.create_pattern_list_panel()
        content_splitter.addWidget(left_panel)

        # Right panel - Pattern editor
        right_panel = self.create_editor_panel()
        content_splitter.addWidget(right_panel)

        # Set fixed splitter proportions - expanded right panel for better content visibility
        content_splitter.setSizes([180, 1600])  # 좌측 최대한 축소, 우측 최대한 확장

        main_layout.addWidget(content_splitter)
        self.setLayout(main_layout)
        self.refresh_list()

    def create_header_section(self):
        """헤더에서 버튼 제거 - 요구사항: 상단 버튼을 하단 작업영역으로 이동"""
        # 빈 위젯 반환 (버튼들은 하단 작업영역으로 이동)
        return QWidget()

    def create_pattern_list_panel(self):
        """Create left panel with pattern list and search"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 12, 0)
        layout.setSpacing(16)

        # Search card
        search_card = Card("패턴 검색")
        
        self.search_input = SearchInput("탐지명 또는 패턴으로 검색...")
        self.search_input.textChanged.connect(self.refresh_list)
        search_card.add_widget(self.search_input)

        # Pattern list
        list_card = Card("패턴 라이브러리")
        
        self.list_widget = SidebarList()
        self.list_widget.setMinimumHeight(400)
        self.list_widget.itemClicked.connect(self.load_pattern)
        list_card.add_widget(self.list_widget)

        # Jira integration card
        jira_card = Card("Jira 연동")
        
        # Date range
        date_layout = QHBoxLayout()
        date_layout.setSpacing(8)
        
        date_layout.addWidget(QLabel("시작:"))
        self.jira_start = QDateEdit(calendarPopup=True)
        self.jira_start.setDate(QDate.currentDate().addDays(-7))
        date_layout.addWidget(self.jira_start)
        
        date_layout.addWidget(QLabel("종료:"))
        self.jira_end = QDateEdit(calendarPopup=True)  
        self.jira_end.setDate(QDate.currentDate())
        date_layout.addWidget(self.jira_end)

        jira_card.add_layout(date_layout)

        self.jira_import_btn = SecondaryButton("📥 티켓 가져오기")
        self.jira_import_btn.clicked.connect(self.import_jira_tickets)
        jira_card.add_widget(self.jira_import_btn)

        layout.addWidget(search_card)
        layout.addWidget(list_card)
        layout.addWidget(jira_card)
        layout.addStretch()

        return panel

    def create_editor_panel(self):
        """Create right panel with pattern editor"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 0, 0, 0)
        layout.setSpacing(16)

        # Pattern info card
        info_card = Card("패턴 정보")
        
        # Pattern name - 수평 레이아웃으로 공간 절약
        name_layout = QHBoxLayout()
        name_layout.setSpacing(8)
        name_layout.addWidget(QLabel("탐지명:"))
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("예: WAF - SQL Injection 탐지")
        name_layout.addWidget(self.name_input)
        
        info_card.add_layout(name_layout)

        # Pattern content card
        content_card = Card("분석 내용")
        
        # Content editor
        content_layout = QVBoxLayout()
        content_layout.setSpacing(4)
        
        content_layout.addWidget(QLabel("패턴 분석:"))
        
        self.content_edit = QTextEdit()
        self.content_edit.setPlaceholderText(
            "표준 템플릿을 사용하여 분석 내용을 입력하세요:\n\n"
            "1. 탐지 이벤트 분석 요약:\n"
            "2. 상세 분석:\n"
            "3. 영향 받는 제품/시스템:\n"
            "4. 대응 방안:\n"
            "5. 참고 자료:\n\n"
            "Markdown 포맷을 사용할 수 있으며 필요에 따라 수정 가능합니다."
        )
        # 고정 높이 제거 - 남은 공간을 모두 사용하도록 설정
        content_layout.addWidget(self.content_edit)
        
        # 안내 문구 제거 - 공간 절약을 위해
        
        content_card.add_layout(content_layout)

        # 작업 영역 - 새로작성, AI 초안 버튼을 여기로 이동 (요구사항)
        actions_card = Card("작업 영역")
        
        # 상단에서 이동한 버튼들 + 기존 작업 버튼들
        all_actions = QHBoxLayout()
        all_actions.setSpacing(6)  # 간격 축소
        
        # 새로운 액션 버튼 적용 - 크기와 디자인 개선
        self.new_btn = ActionButton("새로작성", button_type="secondary")
        self.new_btn.clicked.connect(self.clear_inputs)

        self.ai_btn = ActionButton("AI 초안", button_type="primary")
        self.ai_btn.clicked.connect(self.gen_ai_draft)
        
        # 기존 작업 버튼들
        self.save_btn = ActionButton("저장", button_type="success")
        self.save_btn.clicked.connect(self.save_pattern)
        
        self.del_btn = ActionButton("삭제", button_type="danger")
        self.del_btn.clicked.connect(self.delete_pattern)
        
        all_actions.addWidget(self.new_btn)
        all_actions.addWidget(self.ai_btn)
        all_actions.addWidget(self.save_btn)
        all_actions.addWidget(self.del_btn)
        all_actions.addStretch()
        
        actions_card.add_layout(all_actions)
        
        # Secondary actions
        secondary_actions = QHBoxLayout()
        secondary_actions.setSpacing(8)
        
        self.fav_btn = ActionButton("⭐ 즐겨찾기", button_type="secondary")
        self.fav_btn.clicked.connect(self.toggle_fav)
        
        self.copy_btn = ActionButton("📋 복사", button_type="secondary")
        self.copy_btn.clicked.connect(self.copy_content)
        
        self.export_btn = ActionButton("📤 내보내기", button_type="secondary")
        self.export_btn.clicked.connect(self.export_to_txt)
        
        secondary_actions.addWidget(self.fav_btn)
        secondary_actions.addWidget(self.copy_btn)
        secondary_actions.addWidget(self.export_btn)
        secondary_actions.addStretch()
        
        actions_card.add_layout(secondary_actions)

        # 패턴 정보와 버튼을 최대한 축소하고 분석 내용에 모든 공간 할당
        layout.addWidget(info_card)  # 고정 크기
        layout.addWidget(content_card, 10)  # 압도적으로 많은 공간 할당
        layout.addWidget(actions_card)  # 고정 크기

        return panel

    def refresh_list(self):
        keyword = self.search_input.text().strip()
        self.list_widget.clear()
        for row in self.db.get_patterns(keyword):
            star = '★' if row[4] else '☆'
            self.list_widget.addItem(f"{star} {row[1]} ({row[3]})")

    def load_pattern(self, item):
        name = item.text().split(' ', 1)[1].rsplit(' (', 1)[0]
        row = self.db.get_pattern(name)
        if row:
            self.selected_id = row[0]
            self.name_input.setText(row[1])
            self.content_edit.setPlainText(row[2])

    def save_pattern(self):
        name = self.name_input.text().strip()
        content = self.content_edit.toPlainText().strip()
        if not name or not content:
            QMessageBox.warning(self, "입력 오류", "탐지명과 분석내용을 모두 입력하세요."); return
        reg_date = datetime.now().strftime("%Y-%m-%d")
        try:
            self.db.add_pattern(name, content, reg_date)
            self.refresh_list()
            QMessageBox.information(self, "저장 완료", "저장되었습니다.")
        except Exception as e:
            import traceback
            print("[UI 저장 오류]", e)
            traceback.print_exc()
            QMessageBox.critical(self, "저장 오류", f"DB 저장 중 문제가 발생했습니다:\n{str(e)}")
    
    def import_jira_tickets(self):
        """JIRA 티켓 가져오기 - simplified version"""
        start = self.jira_start.date().toPyDate().strftime("%Y-%m-%d")
        end = self.jira_end.date().toPyDate().strftime("%Y-%m-%d")
        
        # JIRA API 설정 (config.py에서 로드)
        from config import get_jira_config
        jira_config = get_jira_config()
        
        if not jira_config.is_valid():
            QMessageBox.critical(self, "JIRA 설정 오류", 
                "JIRA API 설정이 유효하지 않습니다.\n"
                ".env 파일의 JIRA_API_USER, JIRA_API_TOKEN을 확인해주세요.")
            return
        
        # 간단한 진행 표시
        progress = QProgressDialog("JIRA 티켓을 가져오고 있습니다...", "취소", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(500)
        progress.show()
        
        try:
            # JIRA 연결 및 검색
            progress.setLabelText("JIRA 서버 연결 중...")
            progress.setValue(10)
            QApplication.processEvents()
            
            jira_url = jira_config.url
            api_user = jira_config.api_user
            api_token = jira_config.api_token
            headers = {"Accept": "application/json"}
            
            # 간단한 JQL부터 시작 - 점진적으로 조건 추가
            # 우선 날짜 조건만으로 테스트
            simple_jql = f'created >= "{start}" AND created <= "{end}"'
            
            # 복잡한 JQL (원래 조건)
            ISSUE_TYPE = "보안이벤트"  
            PROJECTS = ["GOODRICH", "WCVS", "FINDA", "GLN", "SAMKOO", "ISU", "KURLY"]
            RESOLVED_STATES = ["협의된 차단 완료", "승인 대기", "오탐 확인 완료", "기 차단 완료", "정탐(승인필요 대상)", "차단 미승인 완료"]
            
            # 상태 목록을 미리 생성
            status_list = ','.join([f'"{s}"' for s in RESOLVED_STATES])
            project_list = ','.join(PROJECTS)
            
            complex_jql = (
                f'project in ({project_list}) AND '
                f'issuetype = "{ISSUE_TYPE}" AND '
                f'status in ({status_list}) AND '
                f'created >= "{start}" AND created <= "{end}"'
            )
            
            # 우선 간단한 JQL로 시도
            jql = simple_jql
            
            progress.setLabelText("티켓 검색 중...")
            progress.setValue(30)
            QApplication.processEvents()
            
            # URL 구성 - API v2 사용
            import urllib.parse
            base_url = jira_url.rstrip('/')
            search_url = f"{base_url}/rest/api/2/search"
            
            # JQL 디버깅을 위해 출력
            progress.setLabelText(f"JQL 쿼리: {jql[:100]}...")
            QApplication.processEvents()
            print(f"  - 기간: {start} ~ {end}")
            print(f"  - JQL: {jql}")
            print(f"  - URL: {search_url}")
            
            params = {
                'jql': jql,
                'maxResults': 100,  # 우선 100개로 제한
                'fields': 'key,created,customfield_10249,customfield_10246'  # 필요한 필드만
            }
            
            response = requests.get(search_url, headers=headers, auth=(api_user, api_token), 
                                  params=params, timeout=30)
            
            # 상세한 에러 처리
            if response.status_code == 401:
                raise Exception("JIRA 인증 실패. 사용자명과 API 토큰을 확인해주세요.")
            elif response.status_code == 400:
                raise Exception(f"JIRA 요청 오류. JQL 문법을 확인해주세요.\n응답: {response.text}")
            elif response.status_code == 404:
                raise Exception(f"JIRA API 엔드포인트를 찾을 수 없습니다: {search_url}")
            elif response.status_code != 200:
                raise Exception(f"JIRA API 오류 (코드: {response.status_code}): {response.text}")
            
            response.raise_for_status()
            
            data = response.json()
            issues = data.get("issues", [])
            total_issues = len(issues)
            
            print(f"  - 전체 결과: {data.get('total', 0)}개")
            print(f"  - 현재 페이지: {total_issues}개")
            print(f"  - maxResults: {data.get('maxResults', 0)}")
            
            # 결과가 0개면 추가 디버깅
            if total_issues == 0:
                # 최소한의 조건으로 재시도
                test_jql = f'created >= "{start}"'
                test_params = {
                    'jql': test_jql,
                    'maxResults': 10
                }
                
                test_response = requests.get(search_url, headers=headers, auth=(api_user, api_token), 
                                           params=test_params, timeout=30)
                
                if test_response.status_code == 200:
                    test_data = test_response.json()
                    test_total = test_data.get('total', 0)
                    
                    if test_total > 0:
                        # 샘플 이슈 정보 출력
                        if test_data.get('issues'):
                            sample_issue = test_data['issues'][0]
                            print(f"  - Key: {sample_issue.get('key')}")
                            print(f"  - Project: {sample_issue.get('fields', {}).get('project', {}).get('key')}")
                            print(f"  - Issue Type: {sample_issue.get('fields', {}).get('issuetype', {}).get('name')}")
                            print(f"  - Status: {sample_issue.get('fields', {}).get('status', {}).get('name')}")
                    else:
                        print(f"No issues found for project: {project_key}")
                else:
                    print(f"Failed to get issues for project: {project_key}")
            
            # 티켓 데이터 처리
            progress.setLabelText(f"{total_issues}개 티켓 처리 중...")
            progress.setValue(50)
            QApplication.processEvents()
            
            imported_count = 0
            patterns_to_save = []
            
            for i, issue in enumerate(issues):
                if progress.wasCanceled():
                    break
                
                try:
                    # 티켓 정보 파싱
                    key = issue["key"]
                    fields = issue.get('fields', {})
                    created = fields.get('created', '')
                    
                    # 커스텀 필드에서 패턴명과 분석내용 추출
                    pattern_name_raw = fields.get('customfield_10249', '')
                    analysis_raw = fields.get('customfield_10246', '')
                    
                    # None 값 체크 후 안전하게 처리
                    pattern_name = pattern_name_raw.strip() if pattern_name_raw else ''
                    analysis = analysis_raw.strip() if analysis_raw else ''
                    
                    reg_date = created[:10] if created else datetime.now().strftime('%Y-%m-%d')
                    
                    
                    # 패턴명과 분석내용이 모두 있는 경우만 처리
                    if pattern_name and analysis:
                        # 중복 확인
                        existing = self.db.get_pattern(pattern_name)
                        if existing:
                            continue
                        
                        pattern = {
                            'name': pattern_name,
                            'content': analysis,
                            'reg_date': reg_date
                        }
                        patterns_to_save.append(pattern)
                        imported_count += 1
                    else:
                        # 이미 존재하는 패턴인 경우 건너뛰기
                        continue
                
                except Exception as e:
                    continue
                
                # 진행률 업데이트
                if i % 10 == 0:  # 10개마다 업데이트
                    progress.setValue(50 + int((i / total_issues) * 30))
                    QApplication.processEvents()
            
            # 데이터베이스 저장
            progress.setLabelText("패턴 저장 중...")
            progress.setValue(90)
            QApplication.processEvents()
            
            # 중복 제거
            unique_patterns = []
            seen_names = set()
            
            for pattern in patterns_to_save:
                if pattern['name'] not in seen_names:
                    unique_patterns.append(pattern)
                    seen_names.add(pattern['name'])
            
            saved_count = 0
            for pattern in unique_patterns:
                try:
                    self.db.add_pattern(
                        name=pattern['name'],
                        content=pattern['content'],
                        reg_date=pattern['reg_date']
                    )
                    saved_count += 1
                except Exception as e:
                    print(f"패턴 저장 오류: {str(e)}")
                    continue
            
            # 목록 새로고침
            progress.setValue(100)
            self.refresh_list()
            
            QMessageBox.information(self, "JIRA 가져오기 완료", 
                f"총 {saved_count}개의 패턴이 성공적으로 추가되었습니다.")
            
        except Exception as e:
            QMessageBox.critical(self, "JIRA 가져오기 오류", f"JIRA 티켓 가져오기 중 오류가 발생했습니다:\n{str(e)}")
            
        finally:
            progress.close()


    def clear_inputs(self):
        self.selected_id = None
        self.name_input.clear()
        self.content_edit.clear()

    def delete_pattern(self):
        if self.selected_id:
            self.db.delete_pattern(self.selected_id)
            self.clear_inputs()
            self.refresh_list()

    def toggle_fav(self):
        if self.selected_id:
            self.db.toggle_favorite(self.selected_id)
            self.refresh_list()

    def copy_content(self):
        content = self.content_edit.toPlainText()
        if content:
            QApplication.clipboard().setText(content)
            QMessageBox.information(self, "복사됨", "분석 내용이 복사되었습니다.")

    def export_to_txt(self):
        content = self.content_edit.toPlainText()
        if not content:
            QMessageBox.warning(self, "오류", "분석 내용을 입력하세요.")
            return
        file, _ = QFileDialog.getSaveFileName(self, "분석내용 내보내기", "", "Text Files (*.txt)")
        if file:
            with open(file, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "완료", "파일 저장 완료")

    def gen_ai_draft(self):
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "입력 오류", "AI초안을 원할 경우 탐지명을 입력하세요.")
            return
        # Azure OpenAI 연동 (config.py에서 로드)
        try:
            from openai import AzureOpenAI
            from config import get_ai_config
            
            ai_config = get_ai_config()
            if not ai_config.is_valid():
                QMessageBox.critical(self, "API 설정 오류", 
                    "Azure OpenAI API 설정이 유효하지 않습니다.\n"
                    ".env 파일의 AZURE_OPENAI_API_KEY를 확인해주세요.")
                return
                
            client = AzureOpenAI(
                api_key=ai_config.api_key,
                api_version=ai_config.api_version,
                azure_endpoint=ai_config.endpoint,
            )
            prompt = (
                f"아래 탐지명에 대한 최신 보안 분석 보고서 초안을 Markdown 스타일로 표준 포맷에 맞춰 작성해줘.\n\n"
                f"탐지명: {name}\n\n"
                "1. 탐지 이벤트 분석 요약:\n2. 상세 분석:\n3. 영향 받는 제품:\n4. 대응 방안:\n5. 참고 자료:"
            )
            response = client.chat.completions.create(
                model=ai_config.deployment,
                messages=[
                    {"role": "system", "content": "너는 숙련된 보안관제 전문가야."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_completion_tokens=1200,
                top_p=1.0,
            )
            self.content_edit.setPlainText(response.choices[0].message.content)
        except Exception as e:
            QMessageBox.warning(self, "AI 오류", str(e))
