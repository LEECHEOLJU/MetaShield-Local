# integrated_dashboard.py - JIRA 티켓 기반 자동 위협 분석 대시보드
"""
JIRA 티켓 기반 자동 위협 분석 대시보드 (올인원 구현)
- JIRA 티켓 번호로 단일 티켓 조회
- 커스텀 필드에서 출발지 IP, 목적지 URL, Count 추출
- 실시간 위협 인텔리전스 분석
- 웹 스크린샷 및 응답 코드 조회
- 통합 결과 대시보드 표시
"""

import json
import requests
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, ActionButton, SecondaryButton, SearchInput, ModernTable, StatusBadge
from modern_ui_style import MODERN_STYLE, DARK_THEME
from config import get_jira_config
from advanced_ioc_analyzer import AdvancedIOCAnalyzer, IOCResult

@dataclass
class ThreatAnalysisResult:
    """위협 분석 결과 데이터 클래스"""
    ticket_number: str
    source_ip: str
    destination_url: str 
    count: int
    ip_analysis: Dict[str, Any]
    url_analysis: Dict[str, Any]
    screenshot_path: str = ""
    analysis_time: str = ""

class JiraThreatDashboard(QWidget):
    """JIRA 티켓 기반 자동 위협 분석 대시보드"""
    
    def __init__(self):
        super().__init__()
        self.setStyleSheet(MODERN_STYLE)
        self.ioc_analyzer = AdvancedIOCAnalyzer()
        self.current_result: Optional[ThreatAnalysisResult] = None
        self.setup_ui()
        
    def setup_ui(self):
        """대시보드 UI 구성 - 좌우 분할 레이아웃"""
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(24)
        
        # 왼쪽 패널 - 분석 설정 (좁게)
        left_panel = QWidget()
        left_panel.setFixedWidth(400)  # 고정 너비 400px
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(16)
        
        # 입력 섹션
        input_card = self.create_input_section()
        left_layout.addWidget(input_card)
        left_layout.addStretch()  # 남는 공간을 아래로 밀기
        
        main_layout.addWidget(left_panel)
        
        # 오른쪽 패널 - 결과 표시 (넓게)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)
        
        # 결과 제목
        results_title = QLabel("📊 분석 결과")
        results_title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #1890ff;
                padding: 12px 0px;
                border-bottom: 2px solid #f0f0f0;
            }
        """)
        right_layout.addWidget(results_title)
        
        # 결과 섹션 (스크롤 가능)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.results_widget = QWidget()
        self.results_layout = QVBoxLayout(self.results_widget)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(16)
        
        scroll_area.setWidget(self.results_widget)
        right_layout.addWidget(scroll_area)
        
        main_layout.addWidget(right_panel)
        
        self.setLayout(main_layout)
        
        
    def create_input_section(self):
        """입력 섹션 생성"""
        card = Card("📝 분석 설정")
        
        # 티켓 번호 입력
        ticket_layout = QHBoxLayout()
        ticket_label = QLabel("JIRA 티켓 번호:")
        ticket_label.setFixedWidth(120)
        
        self.ticket_input = SearchInput("예: TICKET-1234")
        self.ticket_input.setFixedHeight(36)
        
        ticket_layout.addWidget(ticket_label)
        ticket_layout.addWidget(self.ticket_input)
        card.add_layout(ticket_layout)
        
        # 커스텀 필드 설정
        fields_label = QLabel("커스텀 필드 설정:")
        fields_label.setStyleSheet("font-weight: bold; margin-top: 12px;")
        card.add_widget(fields_label)
        
        fields_layout = QGridLayout()
        
        # 출발지 IP 필드
        fields_layout.addWidget(QLabel("출발지 IP 필드:"), 0, 0)
        self.source_ip_field = QLineEdit("customfield_10001")  # 기본값
        self.source_ip_field.setPlaceholderText("예: customfield_10001")
        fields_layout.addWidget(self.source_ip_field, 0, 1)
        
        # 목적지 URL 필드  
        fields_layout.addWidget(QLabel("목적지 URL 필드:"), 1, 0)
        self.dest_url_field = QLineEdit("customfield_10002")  # 기본값
        self.dest_url_field.setPlaceholderText("예: customfield_10002")
        fields_layout.addWidget(self.dest_url_field, 1, 1)
        
        # Count 필드
        fields_layout.addWidget(QLabel("Count 필드:"), 2, 0)
        self.count_field = QLineEdit("customfield_10003")  # 기본값
        self.count_field.setPlaceholderText("예: customfield_10003")
        fields_layout.addWidget(self.count_field, 2, 1)
        
        card.add_layout(fields_layout)
        
        # 분석 시작 버튼
        self.analyze_btn = ActionButton("🚀 위협 분석 시작")
        self.analyze_btn.clicked.connect(self.start_threat_analysis)
        card.add_widget(self.analyze_btn)
        
        # 진행 상태 표시
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("""
            QLabel {
                color: #1890ff;
                font-weight: bold;
                padding: 8px 0px;
            }
        """)
        self.progress_label.hide()
        card.add_widget(self.progress_label)
        
        return card
        
    def start_threat_analysis(self):
        """위협 분석 시작"""
        ticket_number = self.ticket_input.text().strip()
        if not ticket_number:
            QMessageBox.warning(self, "입력 오류", "JIRA 티켓 번호를 입력해주세요.")
            return
            
        # UI 업데이트
        self.analyze_btn.setText("분석 중...")
        self.analyze_btn.setEnabled(False)
        self.progress_label.setText("🔄 JIRA 티켓 조회 중...")
        self.progress_label.show()
        
        # 기존 결과 초기화
        self.clear_results()
        
        # 워커 스레드에서 분석 실행
        self.worker = ThreatAnalysisWorker(
            ticket_number,
            self.source_ip_field.text().strip(),
            self.dest_url_field.text().strip(),
            self.count_field.text().strip(),
            self.ioc_analyzer
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.analysis_completed.connect(self.on_analysis_completed)
        self.worker.error_occurred.connect(self.on_analysis_error)
        self.worker.start()
        
    def update_progress(self, message: str):
        """진행 상태 업데이트"""
        self.progress_label.setText(message)
        
    def on_analysis_completed(self, result: ThreatAnalysisResult):
        """분석 완료 처리"""
        self.current_result = result
        
        # UI 복구
        self.analyze_btn.setText("🚀 위협 분석 시작")
        self.analyze_btn.setEnabled(True)
        self.progress_label.hide()
        
        # 결과 표시
        self.display_analysis_results(result)
        
    def on_analysis_error(self, error_msg: str):
        """분석 오류 처리"""
        # UI 복구
        self.analyze_btn.setText("🚀 위협 분석 시작")
        self.analyze_btn.setEnabled(True)
        self.progress_label.hide()
        
        QMessageBox.critical(self, "분석 오류", error_msg)
        
    def clear_results(self):
        """기존 결과 초기화"""
        while self.results_layout.count():
            child = self.results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
                
    def display_analysis_results(self, result: ThreatAnalysisResult):
        """분석 결과 표시"""
        # 티켓 정보 카드
        ticket_card = self.create_ticket_info_card(result)
        self.results_layout.addWidget(ticket_card)
        
        # IP 분석 결과 카드
        ip_card = self.create_ip_analysis_card(result)
        self.results_layout.addWidget(ip_card)
        
        # URL 분석 결과 카드
        url_card = self.create_url_analysis_card(result)
        self.results_layout.addWidget(url_card)
        
        # 종합 평가 카드
        summary_card = self.create_summary_card(result)
        self.results_layout.addWidget(summary_card)
        
    def create_ticket_info_card(self, result: ThreatAnalysisResult):
        """티켓 정보 카드 생성"""
        card = Card("📋 티켓 정보")
        
        info_layout = QGridLayout()
        
        info_layout.addWidget(QLabel("티켓 번호:"), 0, 0)
        info_layout.addWidget(QLabel(result.ticket_number), 0, 1)
        
        info_layout.addWidget(QLabel("출발지 IP:"), 1, 0) 
        ip_label = QLabel(result.source_ip)
        ip_label.setStyleSheet("font-weight: bold; color: #1890ff;")
        info_layout.addWidget(ip_label, 1, 1)
        
        info_layout.addWidget(QLabel("목적지 URL:"), 2, 0)
        url_label = QLabel(result.destination_url)
        url_label.setStyleSheet("font-weight: bold; color: #52c41a;")
        info_layout.addWidget(url_label, 2, 1)
        
        info_layout.addWidget(QLabel("발생 횟수:"), 3, 0)
        count_label = QLabel(f"{result.count:,}회")
        count_label.setStyleSheet("font-weight: bold; color: #fa541c;")
        info_layout.addWidget(count_label, 3, 1)
        
        info_layout.addWidget(QLabel("분석 시간:"), 4, 0)
        info_layout.addWidget(QLabel(result.analysis_time), 4, 1)
        
        card.add_layout(info_layout)
        return card
        
    def create_ip_analysis_card(self, result: ThreatAnalysisResult):
        """IP 분석 결과 카드 생성"""
        card = Card("🌐 출발지 IP 분석")
        
        ip_data = result.ip_analysis
        
        # VirusTotal 결과
        if 'virustotal' in ip_data and ip_data['virustotal']:
            vt_data = ip_data['virustotal']
            
            vt_label = QLabel("VirusTotal 분석:")
            vt_label.setStyleSheet("font-weight: bold;")
            card.add_widget(vt_label)
            
            if 'detected_urls' in vt_data:
                detected = len(vt_data['detected_urls']) if vt_data['detected_urls'] else 0
                status_text = f"악성 URL 탐지: {detected}개"
                status_color = "#fa541c" if detected > 0 else "#52c41a"
            else:
                status_text = "탐지 정보 없음"
                status_color = "#666666"
                
            status_label = QLabel(status_text)
            status_label.setStyleSheet(f"color: {status_color}; padding-left: 16px;")
            card.add_widget(status_label)
            
        # AbuseIPDB 결과
        if 'abuseipdb' in ip_data and ip_data['abuseipdb']:
            abuse_data = ip_data['abuseipdb'].get('data', {})
            
            abuse_label = QLabel("AbuseIPDB 분석:")
            abuse_label.setStyleSheet("font-weight: bold; margin-top: 8px;")
            card.add_widget(abuse_label)
            
            abuse_percentage = abuse_data.get('abuseConfidencePercentage', 0)
            usage_type = abuse_data.get('usageType', 'Unknown')
            country = abuse_data.get('countryCode', 'Unknown')
            
            abuse_info = QLabel(f"악성 신뢰도: {abuse_percentage}% | 유형: {usage_type} | 국가: {country}")
            color = "#fa541c" if abuse_percentage > 25 else "#52c41a" if abuse_percentage == 0 else "#fa8c16"
            abuse_info.setStyleSheet(f"color: {color}; padding-left: 16px;")
            card.add_widget(abuse_info)
            
        return card
        
    def create_url_analysis_card(self, result: ThreatAnalysisResult):
        """URL 분석 결과 카드 생성"""
        card = Card("🔗 목적지 URL 분석")
        
        url_data = result.url_analysis
        
        # HTTP 응답 정보
        if 'http_status' in url_data:
            status_code = url_data['http_status']
            status_text = url_data.get('status_text', 'Unknown')
            
            http_label = QLabel(f"HTTP 상태: {status_code} - {status_text}")
            color = "#52c41a" if 200 <= status_code < 300 else "#fa541c"
            http_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            card.add_widget(http_label)
            
        # 스크린샷 표시
        if result.screenshot_path and result.screenshot_path != "":
            screenshot_label = QLabel("웹 페이지 스크린샷:")
            screenshot_label.setStyleSheet("font-weight: bold; margin-top: 8px;")
            card.add_widget(screenshot_label)
            
            try:
                pixmap = QPixmap(result.screenshot_path)
                if not pixmap.isNull():
                    # 스크린샷 크기 조정 (최대 400x300)
                    scaled_pixmap = pixmap.scaled(400, 300, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    screenshot_widget = QLabel()
                    screenshot_widget.setPixmap(scaled_pixmap)
                    screenshot_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    screenshot_widget.setStyleSheet("border: 1px solid #d9d9d9; border-radius: 4px; padding: 8px; margin-left: 16px;")
                    card.add_widget(screenshot_widget)
            except Exception as e:
                error_label = QLabel(f"스크린샷 로드 실패: {str(e)}")
                error_label.setStyleSheet("color: #fa541c; padding-left: 16px;")
                card.add_widget(error_label)
        else:
            no_screenshot = QLabel("스크린샷 캡처 실패 또는 불가")
            no_screenshot.setStyleSheet("color: #666666; padding-left: 16px;")
            card.add_widget(no_screenshot)
            
        return card
        
    def create_summary_card(self, result: ThreatAnalysisResult):
        """종합 평가 카드 생성"""
        card = Card("📊 위협 종합 평가")
        
        # 위험도 계산
        risk_score = self.calculate_risk_score(result)
        risk_level, risk_color = self.get_risk_level(risk_score)
        
        # 위험도 표시
        risk_layout = QHBoxLayout()
        risk_layout.addWidget(QLabel("위험도 평가:"))
        
        risk_badge = StatusBadge(f"{risk_level} ({risk_score}/100)")
        risk_badge.setStyleSheet(f"""
            StatusBadge {{
                background-color: {risk_color};
                color: white;
                font-weight: bold;
                padding: 4px 12px;
                border-radius: 12px;
            }}
        """)
        risk_layout.addWidget(risk_badge)
        risk_layout.addStretch()
        
        card.add_layout(risk_layout)
        
        # 권장 조치
        recommendations = self.get_recommendations(result, risk_score)
        if recommendations:
            rec_label = QLabel("권장 조치:")
            rec_label.setStyleSheet("font-weight: bold; margin-top: 12px;")
            card.add_widget(rec_label)
            
            for rec in recommendations:
                rec_item = QLabel(f"• {rec}")
                rec_item.setWordWrap(True)
                rec_item.setStyleSheet("padding-left: 16px; color: #666666;")
                card.add_widget(rec_item)
                
        return card
        
    def calculate_risk_score(self, result: ThreatAnalysisResult) -> int:
        """위험도 점수 계산"""
        score = 0
        
        # IP 분석 기반 점수
        if 'abuseipdb' in result.ip_analysis and result.ip_analysis['abuseipdb']:
            abuse_percentage = result.ip_analysis['abuseipdb'].get('data', {}).get('abuseConfidencePercentage', 0)
            score += min(abuse_percentage, 40)  # 최대 40점
            
        if 'virustotal' in result.ip_analysis and result.ip_analysis['virustotal']:
            vt_data = result.ip_analysis['virustotal']
            if 'detected_urls' in vt_data and vt_data['detected_urls']:
                detected = len(vt_data['detected_urls'])
                score += min(detected * 5, 30)  # 최대 30점
                
        # 발생 횟수 기반 점수 (단다발성)
        if result.count > 100:
            score += 20
        elif result.count > 50:
            score += 15
        elif result.count > 10:
            score += 10
        elif result.count > 1:
            score += 5
            
        # HTTP 상태 기반 점수
        if 'http_status' in result.url_analysis:
            status_code = result.url_analysis['http_status']
            if status_code >= 400:
                score += 10  # 에러 상태 코드
                
        return min(score, 100)  # 최대 100점
        
    def get_risk_level(self, score: int) -> tuple:
        """위험도 레벨 및 색상 반환"""
        if score >= 70:
            return ("고위험", "#fa541c")
        elif score >= 40:
            return ("중위험", "#fa8c16")
        elif score >= 20:
            return ("저위험", "#faad14")
        else:
            return ("안전", "#52c41a")
            
    def get_recommendations(self, result: ThreatAnalysisResult, risk_score: int) -> List[str]:
        """위험도에 따른 권장 조치"""
        recommendations = []
        
        if risk_score >= 70:
            recommendations.extend([
                "즉시 해당 IP를 차단 조치하세요",
                "관련 시스템에 대한 정밀 점검을 수행하세요",
                "사고 대응팀에 즉시 보고하세요"
            ])
        elif risk_score >= 40:
            recommendations.extend([
                "해당 IP에 대한 모니터링을 강화하세요",
                "관련 로그를 추가 분석하세요",
                "필요시 임시 차단을 검토하세요"
            ])
        elif risk_score >= 20:
            recommendations.extend([
                "지속적인 모니터링을 유지하세요",
                "패턴 분석을 통한 추가 검증을 수행하세요"
            ])
        else:
            recommendations.append("현재 위험도는 낮으나 주기적인 모니터링을 권장합니다")
            
        return recommendations


class ThreatAnalysisWorker(QThread):
    """위협 분석 워커 스레드"""
    
    progress_updated = pyqtSignal(str)
    analysis_completed = pyqtSignal(ThreatAnalysisResult)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, ticket_number: str, source_ip_field: str, dest_url_field: str, count_field: str, ioc_analyzer):
        super().__init__()
        self.ticket_number = ticket_number
        self.source_ip_field = source_ip_field
        self.dest_url_field = dest_url_field
        self.count_field = count_field
        self.ioc_analyzer = ioc_analyzer
        
    def run(self):
        try:
            # 1. JIRA 티켓 조회
            self.progress_updated.emit("🔄 JIRA 티켓 조회 중...")
            ticket_data = self.fetch_jira_ticket()
            
            if not ticket_data:
                self.error_occurred.emit("JIRA 티켓을 찾을 수 없습니다.")
                return
                
            # 2. 커스텀 필드에서 데이터 추출
            self.progress_updated.emit("📋 커스텀 필드 데이터 추출 중...")
            source_ip, dest_url, count = self.extract_custom_fields(ticket_data)
            
            if not source_ip or not dest_url:
                self.error_occurred.emit("필요한 커스텀 필드 데이터를 찾을 수 없습니다.")
                return
                
            # 3. IP 위협 인텔리전스 조회
            self.progress_updated.emit("🌐 출발지 IP 위협 인텔리전스 분석 중...")
            ip_analysis = self.analyze_ip_threat(source_ip)
            
            # 4. URL 분석 및 스크린샷
            self.progress_updated.emit("🔗 목적지 URL 분석 및 스크린샷 캡처 중...")
            url_analysis, screenshot_path = self.analyze_url_threat(dest_url)
            
            # 5. 결과 구성
            result = ThreatAnalysisResult(
                ticket_number=self.ticket_number,
                source_ip=source_ip,
                destination_url=dest_url,
                count=count,
                ip_analysis=ip_analysis,
                url_analysis=url_analysis,
                screenshot_path=screenshot_path,
                analysis_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            self.analysis_completed.emit(result)
            
        except Exception as e:
            self.error_occurred.emit(f"분석 중 오류 발생: {str(e)}")
            
    def fetch_jira_ticket(self) -> Optional[Dict]:
        """JIRA 티켓 조회"""
        try:
            jira_config = get_jira_config()
            if not jira_config.is_valid():
                raise Exception("JIRA API 설정이 유효하지 않습니다")
                
            url = f"{jira_config.url.rstrip('/')}/rest/api/2/issue/{self.ticket_number}"
            headers = {'Accept': 'application/json'}
            
            response = requests.get(
                url, 
                auth=(jira_config.api_user, jira_config.api_token),
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                raise Exception(f"JIRA API 오류 (코드: {response.status_code}): {response.text}")
                
        except Exception as e:
            raise Exception(f"JIRA 티켓 조회 실패: {str(e)}")
            
    def extract_custom_fields(self, ticket_data: Dict) -> tuple:
        """커스텀 필드에서 데이터 추출"""
        try:
            fields = ticket_data.get('fields', {})
            
            source_ip = fields.get(self.source_ip_field, "")
            dest_url = fields.get(self.dest_url_field, "")
            count_value = fields.get(self.count_field, 0)
            
            # Count 값 변환
            try:
                count = int(count_value) if count_value else 1
            except (ValueError, TypeError):
                count = 1
                
            return source_ip, dest_url, count
            
        except Exception as e:
            raise Exception(f"커스텀 필드 데이터 추출 실패: {str(e)}")
            
    def analyze_ip_threat(self, ip_address: str) -> Dict:
        """IP 위협 인텔리전스 분석"""
        result = {}
        
        try:
            # IOCResult 객체 생성
            ioc_result = IOCResult(
                ioc_type='ipv4',
                value=ip_address,
                confidence_score=90.0,
                risk_score=0.0,
                context=f"JIRA 티켓 {self.ticket_number}에서 추출"
            )
            
            # VirusTotal 조회
            vt_data = self.ioc_analyzer._query_virustotal(ioc_result)
            if vt_data:
                result['virustotal'] = vt_data
                
            # AbuseIPDB 조회  
            abuse_data = self.ioc_analyzer._query_abuseipdb(ioc_result)
            if abuse_data:
                result['abuseipdb'] = abuse_data
                
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    def analyze_url_threat(self, url: str) -> tuple:
        """URL 위협 분석 및 스크린샷"""
        result = {}
        screenshot_path = ""
        
        try:
            # URL 정규화
            normalized_url = self._normalize_url(url)
            
            # 브라우저 헤더로 요청
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # HTTP 응답 코드 조회
            response = requests.get(
                normalized_url, 
                timeout=15, 
                allow_redirects=True, 
                headers=headers,
                verify=False  # SSL 인증서 검증 비활성화
            )
            
            result['http_status'] = response.status_code
            result['status_text'] = response.reason
            result['final_url'] = str(response.url)
            result['response_time'] = response.elapsed.total_seconds()
            result['content_type'] = response.headers.get('content-type', 'Unknown')
            
            # 웹 스크린샷 캡처
            screenshot_path = self.capture_screenshot(normalized_url)
            
        except requests.exceptions.SSLError as e:
            result['error'] = f"SSL 인증서 오류: {str(e)}"
            result['http_status'] = 0
            result['status_text'] = "SSL 오류"
            
        except requests.exceptions.Timeout as e:
            result['error'] = f"연결 시간 초과: {str(e)}"
            result['http_status'] = 0
            result['status_text'] = "연결 시간 초과"
            
        except requests.exceptions.ConnectionError as e:
            result['error'] = f"연결 오류: {str(e)}"
            result['http_status'] = 0
            result['status_text'] = "연결 실패"
            
        except requests.exceptions.RequestException as e:
            result['error'] = f"요청 오류: {str(e)}"
            result['http_status'] = 0
            result['status_text'] = "요청 실패"
            
        except Exception as e:
            result['error'] = f"예상치 못한 오류: {str(e)}"
            result['http_status'] = 0
            result['status_text'] = "분석 실패"
            
        return result, screenshot_path
    
    def _normalize_url(self, url: str) -> str:
        """URL 정규화"""
        if not url:
            raise ValueError("URL이 비어있습니다")
            
        url = url.strip()
        
        # http:// 또는 https:// 추가
        if not url.startswith(('http://', 'https://')):
            # 기본적으로 https 사용
            url = 'https://' + url
            
        # URL 유효성 검증
        import re
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            
        if not url_pattern.match(url):
            raise ValueError(f"유효하지 않은 URL 형식: {url}")
            
        return url
        
    def capture_screenshot(self, url: str) -> str:
        """웹 페이지 스크린샷 캡처 (selenium 기반)"""
        try:
            import os
            from datetime import datetime
            
            # 스크린샷 저장 디렉토리
            screenshot_dir = "screenshots"
            if not os.path.exists(screenshot_dir):
                os.makedirs(screenshot_dir)
                
            # 파일명 생성
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"
            filepath = os.path.join(screenshot_dir, filename)
            
            # selenium으로 실제 스크린샷 캡처 시도
            screenshot_path = self._capture_real_screenshot(url, filepath)
            if screenshot_path:
                return screenshot_path
                
            # selenium 실패 시 PIL로 더미 이미지 생성
            return self._create_dummy_screenshot(url, filepath)
                
        except Exception as e:
            print(f"스크린샷 캡처 오류: {str(e)}")
            return ""
    
    def _capture_real_screenshot(self, url: str, filepath: str) -> str:
        """selenium을 사용한 실제 스크린샷 캡처"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.common.exceptions import TimeoutException, WebDriverException
            
            # Chrome 옵션 설정
            chrome_options = Options()
            chrome_options.add_argument('--headless')  # 백그라운드 실행
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            
            driver = None
            try:
                # ChromeDriver 자동 관리 시도
                try:
                    from webdriver_manager.chrome import ChromeDriverManager
                    service = Service(ChromeDriverManager().install())
                    driver = webdriver.Chrome(service=service, options=chrome_options)
                except ImportError:
                    # webdriver_manager가 없으면 시스템 PATH에서 찾기
                    driver = webdriver.Chrome(options=chrome_options)
                
                # 페이지 로드 타임아웃 설정
                driver.set_page_load_timeout(30)
                
                # URL 접속
                driver.get(url)
                
                # 페이지 로딩 대기 (최대 10초)
                try:
                    WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                except TimeoutException:
                    pass  # 타임아웃이어도 스크린샷은 캡처 시도
                
                # 추가 대기 (JavaScript 렌더링)
                driver.implicitly_wait(3)
                
                # 스크린샷 캡처
                driver.save_screenshot(filepath)
                
                print(f"실제 스크린샷 캡처 성공: {filepath}")
                return filepath
                
            finally:
                if driver:
                    driver.quit()
                    
        except ImportError as e:
            print(f"selenium 라이브러리가 설치되지 않음: {str(e)}")
            return ""
            
        except WebDriverException as e:
            print(f"ChromeDriver 오류: {str(e)}")
            return ""
            
        except Exception as e:
            print(f"실제 스크린샷 캡처 실패: {str(e)}")
            return ""
    
    def _create_dummy_screenshot(self, url: str, filepath: str) -> str:
        """PIL을 사용한 더미 스크린샷 생성"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            from datetime import datetime
            
            # 더미 스크린샷 이미지 생성
            img = Image.new('RGB', (1200, 800), color='#f8f9fa')
            draw = ImageDraw.Draw(img)
            
            # 폰트 설정
            try:
                title_font = ImageFont.truetype("arial.ttf", 24)
                content_font = ImageFont.truetype("arial.ttf", 18)
                small_font = ImageFont.truetype("arial.ttf", 14)
            except:
                title_font = ImageFont.load_default()
                content_font = ImageFont.load_default()
                small_font = ImageFont.load_default()
            
            # 헤더 배경
            draw.rectangle([(0, 0), (1200, 80)], fill='#1890ff')
            draw.text((20, 25), "🔍 MetaShield 위협 분석 - 웹페이지 스크린샷", fill='white', font=title_font)
            
            # 콘텐츠 영역
            draw.text((40, 120), f"📄 URL: {url}", fill='#262626', font=content_font)
            draw.text((40, 160), f"⏰ 캡처 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", fill='#595959', font=content_font)
            
            # 안내 메시지
            draw.text((40, 220), "⚠️ 실제 웹페이지 스크린샷을 캡처하려면:", fill='#fa8c16', font=content_font)
            draw.text((60, 260), "1. selenium 라이브러리 설치: pip install selenium", fill='#595959', font=small_font)
            draw.text((60, 290), "2. ChromeDriver 설치 (자동): pip install webdriver-manager", fill='#595959', font=small_font)
            draw.text((60, 320), "3. 또는 수동으로 ChromeDriver를 PATH에 추가", fill='#595959', font=small_font)
            
            # 상태 표시
            draw.text((40, 380), "📊 현재 상태: 더미 이미지 (실제 웹페이지 아님)", fill='#d9534f', font=content_font)
            
            # 테두리
            draw.rectangle([(20, 100), (1180, 780)], outline='#d9d9d9', width=2)
            
            # 하단 정보
            draw.text((40, 750), f"Generated by MetaShield v2.1.0", fill='#8c8c8c', font=small_font)
            
            img.save(filepath)
            print(f"더미 스크린샷 생성 완료: {filepath}")
            return filepath
            
        except ImportError:
            # PIL도 없는 경우 텍스트 파일 생성
            with open(filepath.replace('.png', '.txt'), 'w', encoding='utf-8') as f:
                f.write(f"MetaShield 웹페이지 스크린샷 보고서\n")
                f.write(f"URL: {url}\n")
                f.write(f"캡처 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"상태: PIL 라이브러리 미설치로 인한 텍스트 보고서\n")
            return filepath.replace('.png', '.txt')
            
        except Exception as e:
            print(f"더미 스크린샷 생성 실패: {str(e)}")
            return ""