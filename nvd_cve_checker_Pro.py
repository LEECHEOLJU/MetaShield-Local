import sys
import requests
import json
import pandas as pd
import sqlite3
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit, QPushButton, QVBoxLayout, QMessageBox,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QFileDialog, QTabWidget, QListWidget,
    QTextBrowser, QAbstractItemView, QMenu, QCheckBox, QLineEdit, QGroupBox, QSplitter
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QTimer
from deep_translator import GoogleTranslator
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from modern_ui_style import MODERN_STYLE, DARK_THEME
from advanced_ui_components import Card, ActionButton, SearchInput, ModernTable, SidebarList, StatusBadge, Divider

# -------------------------
# DB 파일명
# -------------------------
DB_FILE = "cve_cache_3_1.db"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# -------------------------
# CVE 기본 데이터셋
# -------------------------
DEFAULT_CVES = [
    "CVE-2017-0144",  # EternalBlue
    "CVE-2021-44228", # Log4Shell
    "CVE-2019-0708",  # BlueKeep
    "CVE-2018-8174",  # VBScript RCE
    "CVE-2022-22965"  # Spring4Shell
]

# -------------------------
# DB 매니저 클래스
# -------------------------
class DBManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                cve TEXT PRIMARY KEY,
                data TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                cve TEXT PRIMARY KEY,
                searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                favorite INTEGER DEFAULT 0
            )
        """)
        self.conn.commit()

    def save_cache(self, cve, data):
        self.conn.execute("REPLACE INTO cache VALUES (?,?)", (cve, data))
        self.conn.commit()

    def get_cache(self, cve):
        cur = self.conn.cursor()
        cur.execute("SELECT data FROM cache WHERE cve=?", (cve,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def save_history(self, cve):
        self.conn.execute("INSERT OR IGNORE INTO history(cve) VALUES (?)", (cve,))
        self.conn.commit()

    def delete_from_archive(self, cve):
        self.conn.execute("DELETE FROM history WHERE cve=?", (cve,))
        self.conn.execute("DELETE FROM cache WHERE cve=?", (cve,))
        self.conn.commit()

    def mark_favorite(self, cve, fav=1):
        self.conn.execute("UPDATE history SET favorite=? WHERE cve=?", (fav, cve))
        self.conn.commit()

    def load_history(self):
        cur = self.conn.cursor()
        cur.execute("SELECT cve,favorite FROM history ORDER BY searched_at DESC")
        return cur.fetchall()

# -------------------------
# KEV(공개 Exploit) 데이터 로드
# -------------------------
def load_kev_list():
    try:
        response = requests.get(KEV_URL, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {item["cveID"] for item in data["vulnerabilities"]}
    except:
        return set()
    return set()

# -------------------------
# CVE API 요청 함수
# -------------------------
def get_cve_details(cve_id):
    # CVE 형식 검증 추가
    import re
    cve_pattern = r'^CVE-\d{4}-\d{4,}$'
    if not re.match(cve_pattern, cve_id.upper()):
        print(f"Invalid CVE format: {cve_id} (expected format: CVE-YYYY-NNNN)")
        return None
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id.upper()}
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                return data["vulnerabilities"][0]["cve"]
        else:
            print(f"NVD API Error for {cve_id}: Status {response.status_code}")
    except Exception as e:
        print(f"Network error for {cve_id}: {str(e)}")
        return None
    return None

# -------------------------
# CVSS 벡터 분석 함수
# -------------------------
def parse_cvss_vector(vector):
    mapping = {
        "AV:N": "🌐 <b>네트워크 접근</b>",
        "AV:A": "📶 <b>인접 네트워크</b>",
        "AV:L": "💻 <b>로컬 접근</b>",
        "AV:P": "🔒 <b>물리적 접근</b>",
        "AC:L": "⚡ <b>낮은 복잡도</b>",
        "AC:H": "🔑 <b>높은 복잡도</b>",
        "PR:N": "🚫 <b>권한 불필요</b>",
        "PR:L": "🔐 <b>낮은 권한 필요</b>",
        "PR:H": "🔏 <b>높은 권한 필요</b>",
        "UI:N": "🤖 <b>사용자 개입 불필요</b>",
        "UI:R": "👤 <b>사용자 개입 필요</b>",
        "S:U": "🔹 <b>범위 불변</b>",
        "S:C": "🔸 <b>범위 변경</b>",
        "C:H": "🔴 <b>기밀성 영향 높음</b>",
        "C:L": "🟡 <b>기밀성 영향 낮음</b>",
        "C:N": "🟢 <b>기밀성 영향 없음</b>",
        "I:H": "🔴 <b>무결성 영향 높음</b>",
        "I:L": "🟡 <b>무결성 영향 낮음</b>",
        "I:N": "🟢 <b>무결성 영향 없음</b>",
        "A:H": "🔴 <b>가용성 영향 높음</b>",
        "A:L": "🟡 <b>가용성 영향 낮음</b>",
        "A:N": "🟢 <b>가용성 영향 없음</b>"
    }
    if not vector:
        return "데이터 없음"
    return "<br>".join([mapping.get(p, p) for p in vector.split("/")])

# -------------------------
# 텍스트 번역 함수
# -------------------------
def translate_text(text):
    try:
        return GoogleTranslator(source='en', target='ko').translate(text)
    except:
        return text

# -------------------------
# 메인 클래스
# -------------------------
class CVEApp(QWidget):
    def __init__(self):
        super().__init__()
        self.db = DBManager()
        self.results = []
        self.kev_list = load_kev_list()
        self.setWindowTitle('🔒 NVD CVE 로컬 백과사전 (SOC PRO 3.1)')
        self.setGeometry(200, 100, 1400, 750)
        self.setStyleSheet("QWidget { background-color: #FFFFFF; color: #000000; } QPushButton { background-color: #0078D7; color:white; }")
        self.initUI()
        self.insert_default_cves()
        self.load_archive_history()

    # -------------------------
    # UI 구성
    # -------------------------
    def initUI(self):
        """Modern CVE search UI with card-based design"""
        self.setStyleSheet(MODERN_STYLE)
        
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

        # Left panel - Search and navigation
        left_panel = self.create_search_panel()
        content_splitter.addWidget(left_panel)

        # Right panel - Results and details
        right_panel = self.create_results_panel()
        content_splitter.addWidget(right_panel)

        # Set fixed splitter proportions - expanded right panel for better visibility
        content_splitter.setSizes([200, 1400])  # 상세정보 분석과 번역 내용 표시 최적화

        main_layout.addWidget(content_splitter)
        self.setLayout(main_layout)

    def create_header_section(self):
        """Header removed to maximize functional space"""
        return QWidget()

    def create_search_panel(self):
        """Create the left panel with search and navigation - 요구사항 반영: 가로 1/3 차지"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 12, 0)
        layout.setSpacing(16)

        # CVE 검색 카드 - 화면 가로 1/3 차지하도록 최적화
        search_card = Card("CVE 검색")
        
        # CVE 입력창 - 기능에 맞는 초적 사이즈로 조정
        self.entry = QTextEdit()
        self.entry.setPlaceholderText("CVE 코드 입력 (한 줄에 하나씩):\n\nCVE-2021-44228\nCVE-2017-0144\nCVE-2019-0708\n\n※ 형식: CVE-YYYY-NNNN\n※ MITRE ATT&CK 기법(T1086 등)은 지원되지 않습니다.")
        self.entry.setMinimumHeight(160)  # 입력 공간 확대  
        self.entry.setMaximumHeight(200)
        search_card.add_widget(self.entry)

        # 검색/지우기 버튼 - 조금 작게 만듦 (요구사항)
        button_layout = QHBoxLayout()
        button_layout.setSpacing(6)

        self.search_btn = ActionButton("검색", button_type="primary")
        self.search_btn.clicked.connect(self.search_cve_thread)
        
        self.btn_clear = ActionButton("지우기", button_type="secondary")
        self.btn_clear.clicked.connect(self.clear_search)

        button_layout.addWidget(self.search_btn)
        button_layout.addWidget(self.btn_clear)
        button_layout.addStretch()

        search_card.add_layout(button_layout)


        # 고급 검색과 빠른 검색 기능 제거 - 기존 기능 공간 확보
        
        # CVE 아카이브 - 최근 검색 및 즐겨찾기
        archive_card = Card("최근 검색 & 아카이브")
        
        # 아카이브 검색
        self.archive_search = SearchInput("아카이브 검색...")
        self.archive_search.textChanged.connect(self.filter_archive)
        archive_card.add_widget(self.archive_search)

        # 아카이브 리스트 - 남은 공간 모두 사용
        self.archive_list = SidebarList()
        self.archive_list.itemDoubleClicked.connect(self.load_from_cache)
        archive_card.add_widget(self.archive_list)

        # 즐겨찾기, 세션기록 기능 삭제 (요구사항에 따라 제거)
        
        layout.addWidget(search_card)
        layout.addWidget(archive_card, 1)  # 아카이브가 남은 모든 공간 차지

        return panel

    def create_results_panel(self):
        """Create the right panel with results table and details"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 0, 0, 0)
        layout.setSpacing(16)

        # 검색 결과 테이블 - 카드 제목 제거
        results_widget = QWidget()
        results_widget.setStyleSheet("""
            QWidget {
                background-color: white;
                border: 1px solid #f0f0f0;
                border-radius: 8px;
            }
        """)
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(16, 16, 16, 16)
        
        self.table = ModernTable()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "CVE ID", "CVSS v3", "위험도", "Exploit", "CWE", "게시일", "수정일"
        ])
        # 고정 높이 제거 - 비율로 제어
        self.table.cellClicked.connect(self.show_details)
        
        results_layout.addWidget(self.table)

        # 취약점 상세정보 - 카드 제목 제거
        details_widget = QWidget()
        details_widget.setStyleSheet("""
            QWidget {
                background-color: white;
                border: 1px solid #f0f0f0;
                border-radius: 8px;
            }
        """)
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(16, 16, 16, 16)
        
        # 탭 기반 상세 뷰
        self.tabs = QTabWidget()
        
        # 기본 정보 탭
        self.tab_info = QTextBrowser()
        self.tab_info.setOpenExternalLinks(True)
        # 고정 높이 제거 - 유연하게 공간 사용
        self.tabs.addTab(self.tab_info, "기본 정보")
        
        # 영향 분석 탭
        self.tab_impact = QTextBrowser()
        self.tab_impact.setOpenExternalLinks(True)
        # 고정 높이 제거 - 유연하게 공간 사용
        self.tabs.addTab(self.tab_impact, "영향 분석")
        
        # 참고 링크 탭
        self.tab_refs = QTextBrowser()
        self.tab_refs.setOpenExternalLinks(True)
        self.tab_refs.setMinimumHeight(460)
        self.tabs.addTab(self.tab_refs, "참고 링크")

        # Dashboard tab
        self.tab_dashboard = QWidget()
        self.dashboard_layout = QVBoxLayout(self.tab_dashboard)
        
        # matplotlib Figure
        self.figure = Figure(figsize=(6, 4))
        self.canvas = FigureCanvas(self.figure)
        self.dashboard_layout.addWidget(self.canvas)
        
        self.tabs.addTab(self.tab_dashboard, "📊 대시보드")

        details_layout.addWidget(self.tabs)

        # 6:4 비율로 정확히 배치 - 상세정보 60%, 검색결과 40%
        layout.addWidget(details_widget, 6)  # 상세 정보 - 60% 공간
        layout.addWidget(results_widget, 4)  # 검색 결과 - 40% 공간

        return panel
    
    # quick_search 함수 제거됨 - 기존 기능에 집중
    
    def clear_search(self):
        """Clear search input and results"""
        self.entry.clear()
        self.table.setRowCount(0)
        self.tab_info.clear()
        self.tab_impact.clear()
        self.tab_refs.clear()

    # Toggle theme method removed - no longer needed in CVE tab

    # -------------------------
    # 기본 CVE 초기 데이터
    # -------------------------
    def insert_default_cves(self):
        for cve in DEFAULT_CVES:
            self.db.save_history(cve)
            if not self.db.get_cache(cve):
                data = get_cve_details(cve)
                if data:
                    self.db.save_cache(cve, json.dumps(data))

    # -------------------------
    # 검색 기능 (스레드 실행)
    # -------------------------
    def search_cve_thread(self):
        threading.Thread(target=self.search_cve).start()

    def search_cve(self):
        try:
            cve_list = [c.strip().upper() for c in self.entry.toPlainText().split("\n") if c.strip()]
            
            if not cve_list:
                QMessageBox.warning(self, "입력 오류", "CVE 코드를 입력하세요.")
                return

            # CVE 형식 사전 검증
            import re
            cve_pattern = r'^CVE-\d{4}-\d{4,}$'
            invalid_cves = [cve for cve in cve_list if not re.match(cve_pattern, cve)]
            
            if invalid_cves:
                invalid_list = '\n'.join(invalid_cves[:5])  # 최대 5개만 표시
                if len(invalid_cves) > 5:
                    invalid_list += f'\n... 및 {len(invalid_cves)-5}개 더'
                
                # MITRE ATT&CK 기법인지 확인
                mitre_pattern = r'^T\d{4}(\.\d{3})?$'
                if any(re.match(mitre_pattern, cve) for cve in invalid_cves):
                    QMessageBox.information(self, "입력 형식 오류", 
                        f"MITRE ATT&CK 기법 코드가 감지되었습니다:\n{invalid_list}\n\n"
                        "CVE 검색에는 다음 형식을 사용하세요:\n"
                        "• CVE-2021-44228 (Log4Shell)\n"
                        "• CVE-2017-0144 (EternalBlue)\n"
                        "• CVE-2019-0708 (BlueKeep)")
                else:
                    QMessageBox.warning(self, "입력 형식 오류", 
                        f"잘못된 CVE 형식입니다:\n{invalid_list}\n\n"
                        "올바른 형식: CVE-YYYY-NNNN\n"
                        "예시: CVE-2021-44228")
                return

            self.table.setRowCount(0)
            self.results = []

            for cve_id in cve_list:
                data = get_cve_details(cve_id)
                
                if not data:
                    QMessageBox.warning(self, "검색 오류", f"{cve_id} 정보가 NVD에 없습니다.\n(아카이브에 저장되지 않음)")
                    self.db.delete_from_archive(cve_id)
                    continue

                self.db.save_history(cve_id)
                self.db.save_cache(cve_id, json.dumps(data))
                parsed = self.parse_cve_data(cve_id, data)

                # 중복 검색 제거
                if parsed["CVE"] not in [r["CVE"] for r in self.results]:
                    self.results.append(parsed)

            self.update_table()
            self.load_archive_history()
            self.update_dashboard()
            
        except Exception as e:
            QMessageBox.critical(self, "오류", f"CVE 검색 중 오류가 발생했습니다: {str(e)}")
            import traceback
            traceback.print_exc()

    # -------------------------
    # 데이터 파싱
    # -------------------------
    def parse_cve_data(self, cve_id, data):
        desc_en = next((d["value"] for d in data.get("descriptions", []) if d["lang"] == "en"), "No description")
        desc_kr = translate_text(desc_en)
        score = data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
        vector = data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString", "")
        cwe = next((w["description"][0]["value"] for w in data.get("weaknesses", []) if w["description"]), "N/A")
        published = data.get("published", "N/A")
        last_modified = data.get("lastModified", "N/A")
        exploit = "✅ Yes" if cve_id in self.kev_list else "❌ No"
        severity = self.get_severity(score)

        # ✅ 참고 링크
        refs = [r.get("url", "") for r in data.get("references", [])]

        # ✅ Exploit-DB 링크 자동 추가
        exploit_db_link = f"https://www.exploit-db.com/search?cve={cve_id}"

        return {
            "CVE": cve_id,
            "CVSS": score,
            "위험도": severity,
            "Exploit": exploit,
            "CWE": cwe,
            "게시일": published,
            "최종 수정일": last_modified,
            "설명(원문)": desc_en,
            "설명(번역)": desc_kr,
            "참고링크": refs,
            "ExploitDB": exploit_db_link,   # ✅ 추가
            "벡터": vector
        }

    # -------------------------
    # 테이블 갱신
    # -------------------------
    def update_table(self):
        self.table.setRowCount(0)
        for result in self.results:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(result["CVE"]))
            self.table.setItem(row, 1, QTableWidgetItem(str(result["CVSS"])))
            self.table.setItem(row, 2, QTableWidgetItem(result["위험도"]))
            self.table.setItem(row, 3, QTableWidgetItem(result["Exploit"]))
            self.table.setItem(row, 4, QTableWidgetItem(result["CWE"]))
            self.table.setItem(row, 5, QTableWidgetItem(result["게시일"]))
            self.table.setItem(row, 6, QTableWidgetItem(result["최종 수정일"]))

    # -------------------------
    # 심각도 자동 분류
    # -------------------------
    def get_severity(self, score):
        try:
            s = float(score)
            if s >= 9: return "🔥 Critical"
            elif s >= 7: return "🔴 High"
            elif s >= 4: return "🟡 Medium"
            else: return "🟢 Low"
        except:
            return "N/A"

    # -------------------------
    # 상세 정보 표시
    # -------------------------
    def show_details(self, row, col):
        if row >= len(self.results):
            return
        data = self.results[row]
        vector_info = parse_cvss_vector(data['벡터']) if data['벡터'] else "데이터 없음"
        vector_info_html = vector_info.replace('\n', '<br>')
        
        # ✅ 기본 정보 탭
        self.tab_info.setText(
            f"📌 CVE ID: {data['CVE']}\n"
            f"📊 CVSS v3 점수: {data['CVSS']} ({data['위험도']})\n"
            f"🛠 Exploit 공개 여부: {data['Exploit']}\n"
            f"🔹 CWE: {data['CWE']}\n"
            f"📅 게시일: {data['게시일']}\n"
            f"🕓 최종 수정일: {data['최종 수정일']}\n\n"
            f"📝 설명(원문):\n{data['설명(원문)']}\n\n"
            f"📝 설명(번역):\n{data['설명(번역)']}"
        )

        # ✅ CVSS 벡터 시각화 탭
        self.tab_impact.setHtml(f"""
    <h3>🛡️ CVSS 벡터 시각화</h3>
    <p><b>Vector String:</b> {data['벡터']}</p>
    <div style='background:#f5f5f5;padding:8px;border-radius:5px;font-size:12pt;'>
    {vector_info_html}
    </div>
""")

        # ✅ 참고 링크 탭 (Exploit-DB 추가)
        refs_html = ""
        if "참고링크" in data and data["참고링크"]:
            refs_html += "<br>".join([f"<a href='{url}'>{url}</a>" for url in data["참고링크"]])
        if "ExploitDB" in data and data["ExploitDB"]:
            refs_html += f"<br><a href='{data['ExploitDB']}'>🔗 Exploit-DB 검색 결과</a>"

        self.tab_refs.setHtml(refs_html)

    def update_dashboard(self):
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        exploit_counts = {"Exploit 공개됨": 0, "Exploit 없음": 0}

        for row in self.results:
            sev = row.get("위험도", "N/A")
            if "Critical" in sev:
                severity_counts["Critical"] += 1
            elif "High" in sev:
                severity_counts["High"] += 1
            elif "Medium" in sev:
                severity_counts["Medium"] += 1
            elif "Low" in sev:
                severity_counts["Low"] += 1

            if "Yes" in row.get("Exploit", ""):
                exploit_counts["Exploit 공개됨"] += 1
            else:
                exploit_counts["Exploit 없음"] += 1

        self.figure.clear()
        ax1 = self.figure.add_subplot(121)
        if sum(severity_counts.values()) > 0:
            ax1.pie(severity_counts.values(), labels=severity_counts.keys(),
                    autopct='%1.1f%%', startangle=140)
            ax1.set_title("심각도 분포")
        else:
            ax1.text(0.5, 0.5, "데이터 없음", ha='center', va='center')

        ax2 = self.figure.add_subplot(122)
        ax2.bar(exploit_counts.keys(), exploit_counts.values(), color=['green', 'gray'])
        ax2.set_title("Exploit 공개 여부")
        self.canvas.draw()

    # -------------------------
    # 아카이브 갱신
    # -------------------------
    def load_archive_history(self):
        """아카이브만 로드 - 즐겨찾기 기능 삭제로 단순화"""
        self.archive_list.clear()
        for row in self.db.load_history():
            if row[1] == 0:  # 아카이브 항목만
                self.archive_list.addItem(row[0])

    # -------------------------
    # 아카이브 검색 필터
    # -------------------------
    def filter_archive(self):
        text = self.archive_search.text().lower()
        self.archive_list.clear()
        for row in self.db.load_history():
            if row[1] == 0 and text in row[0].lower():
                self.archive_list.addItem(row[0])

    # -------------------------
    # 캐시에서 로드
    # -------------------------
    def load_from_cache(self, item):
        cve_id = item.text()
        data = self.db.get_cache(cve_id)
        if not data:
            QMessageBox.warning(self, "데이터 없음", f"{cve_id} 정보가 캐시에 없습니다.")
            self.db.delete_from_archive(cve_id)
            self.load_archive_history()
            return
        parsed = self.parse_cve_data(cve_id, data)
        self.results = [parsed]
        self.update_table()
        self.show_details(0, 0)

    # -------------------------
    # 우클릭 메뉴
    # -------------------------
    def contextMenuEvent(self, event):
        menu = QMenu(self)
        selected_item = None
        list_widget = None

        if self.archive_list.underMouse():
            list_widget = self.archive_list
        elif self.favorite_list.underMouse():
            list_widget = self.favorite_list

        if list_widget:
            item = list_widget.itemAt(list_widget.mapFromGlobal(event.globalPos()))
            if item:
                selected_item = item.text()

        if selected_item:
            if list_widget == self.archive_list:
                menu.addAction("⭐ 즐겨찾기 추가", lambda: self.db.mark_favorite(selected_item, 1))
                menu.addAction("🗑️ 아카이브에서 삭제", lambda: self.db.delete_from_archive(selected_item))
            elif list_widget == self.favorite_list:
                menu.addAction("❌ 즐겨찾기 제거", lambda: self.db.mark_favorite(selected_item, 0))
        menu.exec_(event.globalPos())
        self.load_archive_history()


# -------------------------
# 프로그램 실행
# -------------------------
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = CVEApp()
    ex.show()
    sys.exit(app.exec())