# ai_threat_predictor.py - AI 기반 위협 예측 시스템
"""
AI 기반 실시간 위협 예측 및 분석 시스템
"""

import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import sqlite3
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from config import AIConfig
from prompts import SecurityPrompts
from advanced_ui_components import Card, PrimaryButton, SecondaryButton
from modern_ui_style import MODERN_STYLE
import openai

@dataclass
class ThreatPrediction:
    """위협 예측 결과"""
    threat_type: str
    confidence: float
    severity: str  # "낮음", "보통", "높음", "심각"
    description: str
    indicators: List[str]
    timeline: str
    mitigation: List[str]
    created_at: str

@dataclass
class ThreatPattern:
    """위협 패턴 데이터"""
    pattern_id: str
    pattern_type: str
    indicators: List[str]
    frequency: int
    last_seen: str
    threat_score: float

class ThreatPredictionEngine(QObject):
    """AI 기반 위협 예측 엔진"""
    
    prediction_ready = pyqtSignal(dict)
    pattern_detected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.ai_config = AIConfig()
        self.predictions_db = "threat_predictions.db"
        self.init_database()
        self.prediction_models = {
            "behavioral": self._analyze_behavioral_patterns,
            "temporal": self._analyze_temporal_patterns,
            "network": self._analyze_network_patterns,
            "endpoint": self._analyze_endpoint_patterns
        }
        
    def init_database(self):
        """위협 예측 데이터베이스 초기화"""
        conn = sqlite3.connect(self.predictions_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT,
                confidence REAL,
                severity TEXT,
                description TEXT,
                indicators TEXT,
                timeline TEXT,
                mitigation TEXT,
                created_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id TEXT UNIQUE,
                pattern_type TEXT,
                indicators TEXT,
                frequency INTEGER,
                last_seen TEXT,
                threat_score REAL
            )
        """)
        
        conn.commit()
        conn.close()
    
    def predict_threats(self, data: Dict) -> List[ThreatPrediction]:
        """위협 예측 실행"""
        predictions = []
        
        for model_name, model_func in self.prediction_models.items():
            try:
                model_predictions = model_func(data)
                predictions.extend(model_predictions)
            except Exception as e:
                print(f"모델 {model_name} 예측 오류: {e}")
        
        # AI 분석으로 예측 강화
        enhanced_predictions = self._enhance_with_ai(predictions, data)
        
        # 데이터베이스에 저장
        self._save_predictions(enhanced_predictions)
        
        return enhanced_predictions
    
    def _analyze_behavioral_patterns(self, data: Dict) -> List[ThreatPrediction]:
        """행위 패턴 분석"""
        predictions = []
        
        # 비정상적인 로그인 패턴 탐지
        if "login_attempts" in data:
            attempts = data["login_attempts"]
            if attempts > 10:
                predictions.append(ThreatPrediction(
                    threat_type="브루트포스 공격",
                    confidence=0.85,
                    severity="높음",
                    description=f"비정상적인 로그인 시도 ({attempts}회) 탐지",
                    indicators=[f"로그인 시도 횟수: {attempts}", "짧은 시간 내 반복 시도"],
                    timeline="즉시",
                    mitigation=["계정 잠금", "IP 차단", "2FA 적용"],
                    created_at=datetime.now().isoformat()
                ))
        
        # 파일 접근 패턴 분석
        if "file_access" in data:
            access_count = data["file_access"].get("count", 0)
            if access_count > 100:
                predictions.append(ThreatPrediction(
                    threat_type="데이터 유출 시도",
                    confidence=0.75,
                    severity="높음",
                    description=f"대량 파일 접근 ({access_count}개) 탐지",
                    indicators=[f"파일 접근 수: {access_count}", "비정상적인 접근 패턴"],
                    timeline="30분 이내",
                    mitigation=["파일 접근 제한", "사용자 활동 모니터링"],
                    created_at=datetime.now().isoformat()
                ))
        
        return predictions
    
    def _analyze_temporal_patterns(self, data: Dict) -> List[ThreatPrediction]:
        """시간적 패턴 분석"""
        predictions = []
        current_hour = datetime.now().hour
        
        # 비정상 시간대 활동
        if "activity_time" in data:
            activity_hour = data["activity_time"]
            if activity_hour < 6 or activity_hour > 22:
                predictions.append(ThreatPrediction(
                    threat_type="비정상 시간대 활동",
                    confidence=0.70,
                    severity="보통",
                    description=f"업무 시간외 활동 탐지 ({activity_hour}시)",
                    indicators=[f"활동 시간: {activity_hour}시", "업무 시간외"],
                    timeline="실시간",
                    mitigation=["활동 로그 검토", "관리자 알림"],
                    created_at=datetime.now().isoformat()
                ))
        
        return predictions
    
    def _analyze_network_patterns(self, data: Dict) -> List[ThreatPrediction]:
        """네트워크 패턴 분석"""
        predictions = []
        
        # 비정상적인 네트워크 트래픽
        if "network_traffic" in data:
            traffic = data["network_traffic"]
            if traffic.get("outbound_mb", 0) > 1000:
                predictions.append(ThreatPrediction(
                    threat_type="데이터 유출",
                    confidence=0.80,
                    severity="심각",
                    description=f"대량 아웃바운드 트래픽 ({traffic['outbound_mb']}MB)",
                    indicators=[f"송신 트래픽: {traffic['outbound_mb']}MB", "비정상적인 송신량"],
                    timeline="즉시 대응 필요",
                    mitigation=["네트워크 차단", "트래픽 분석", "데이터 유출 조사"],
                    created_at=datetime.now().isoformat()
                ))
        
        return predictions
    
    def _analyze_endpoint_patterns(self, data: Dict) -> List[ThreatPrediction]:
        """엔드포인트 패턴 분석"""
        predictions = []
        
        # 프로세스 생성 패턴
        if "process_creation" in data:
            processes = data["process_creation"]
            suspicious_processes = ["powershell.exe", "cmd.exe", "wscript.exe"]
            
            for proc in processes:
                if any(sus in proc.lower() for sus in suspicious_processes):
                    predictions.append(ThreatPrediction(
                        threat_type="의심스러운 프로세스 실행",
                        confidence=0.75,
                        severity="보통",
                        description=f"의심스러운 프로세스 실행: {proc}",
                        indicators=[f"프로세스: {proc}", "스크립트 실행"],
                        timeline="실시간 모니터링",
                        mitigation=["프로세스 종료", "상세 분석 필요"],
                        created_at=datetime.now().isoformat()
                    ))
        
        return predictions
    
    def _enhance_with_ai(self, predictions: List[ThreatPrediction], data: Dict) -> List[ThreatPrediction]:
        """AI를 통한 예측 강화"""
        if not self.ai_config.validate_config()[0] or not predictions:
            return predictions
        
        try:
            # AI 분석을 위한 프롬프트 생성
            context = {
                "predictions": [asdict(p) for p in predictions],
                "raw_data": data,
                "timestamp": datetime.now().isoformat()
            }
            
            prompt = f"""
다음 보안 위협 예측 결과를 분석하고 개선해주세요:

예측 결과:
{json.dumps(context, ensure_ascii=False, indent=2)}

다음 항목을 분석해주세요:
1. 예측의 정확도 평가
2. 추가 위협 요소 식별
3. 연관성 분석
4. 대응 우선순위 제안
5. 개선된 대응 방안

JSON 형태로 응답해주세요.
"""
            
            client = openai.AzureOpenAI(
                azure_endpoint=self.ai_config.endpoint,
                api_key=self.ai_config.api_key,
                api_version=self.ai_config.api_version
            )
            
            response = client.chat.completions.create(
                model=self.ai_config.deployment_name,
                messages=[
                    {"role": "system", "content": "당신은 사이버보안 위협 분석 전문가입니다."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            ai_analysis = response.choices[0].message.content
            
            # AI 분석 결과를 바탕으로 예측 개선
            enhanced_predictions = self._apply_ai_enhancements(predictions, ai_analysis)
            
            return enhanced_predictions
            
        except Exception as e:
            print(f"AI 분석 오류: {e}")
            return predictions
    
    def _apply_ai_enhancements(self, predictions: List[ThreatPrediction], ai_analysis: str) -> List[ThreatPrediction]:
        """AI 분석 결과 적용"""
        # 실제 구현에서는 AI 응답을 파싱하여 예측을 개선
        # 현재는 간단히 confidence 조정
        enhanced = []
        for pred in predictions:
            if "심각" in pred.description:
                pred.confidence = min(0.95, pred.confidence + 0.1)
            enhanced.append(pred)
        
        return enhanced
    
    def _save_predictions(self, predictions: List[ThreatPrediction]):
        """예측 결과 저장"""
        conn = sqlite3.connect(self.predictions_db)
        cursor = conn.cursor()
        
        for pred in predictions:
            cursor.execute("""
                INSERT INTO threat_predictions 
                (threat_type, confidence, severity, description, indicators, timeline, mitigation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pred.threat_type, pred.confidence, pred.severity, pred.description,
                json.dumps(pred.indicators), pred.timeline, 
                json.dumps(pred.mitigation), pred.created_at
            ))
        
        conn.commit()
        conn.close()

class ThreatPredictionTab(QWidget):
    """위협 예측 탭 UI"""
    
    def __init__(self):
        super().__init__()
        self.prediction_engine = ThreatPredictionEngine()
        self.prediction_engine.prediction_ready.connect(self.on_prediction_ready)
        self.setup_ui()
        
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 제목
        title = QLabel("🔮 AI 기반 위협 예측")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("실시간 데이터 분석을 통해 향후 발생 가능한 보안 위협을 AI로 예측합니다.")
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # 입력 섹션
        input_card = Card()
        input_layout = QVBoxLayout(input_card)
        
        # 데이터 입력 영역
        input_label = QLabel("🔍 분석할 보안 데이터 입력:")
        input_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        input_layout.addWidget(input_label)
        
        self.data_input = QTextEdit()
        self.data_input.setPlaceholderText("""분석할 보안 데이터를 JSON 형태로 입력하세요. 예시:
{
  "login_attempts": 25,
  "activity_time": 2,
  "network_traffic": {"outbound_mb": 1500},
  "process_creation": ["powershell.exe", "notepad.exe"],
  "file_access": {"count": 150}
}""")
        self.data_input.setMinimumHeight(150)
        self.data_input.setStyleSheet("""
            QTextEdit {
                border: 2px solid #d9d9d9;
                border-radius: 8px;
                padding: 10px;
                font-family: monospace;
                font-size: 12px;
            }
            QTextEdit:focus {
                border-color: #1890ff;
            }
        """)
        input_layout.addWidget(self.data_input)
        
        # 버튼 영역
        button_layout = QHBoxLayout()
        
        self.predict_btn = PrimaryButton("🔮 위협 예측 시작")
        self.predict_btn.clicked.connect(self.start_prediction)
        button_layout.addWidget(self.predict_btn)
        
        self.clear_btn = SecondaryButton("🗑️ 초기화")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        input_layout.addLayout(button_layout)
        
        layout.addWidget(input_card)
        
        # 결과 표시 영역
        self.results_card = Card()
        results_layout = QVBoxLayout(self.results_card)
        
        results_label = QLabel("📊 예측 결과:")
        results_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        results_layout.addWidget(results_label)
        
        self.results_area = QScrollArea()
        self.results_area.setWidgetResizable(True)
        self.results_area.setMinimumHeight(300)
        self.results_area.setStyleSheet("""
            QScrollArea {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
            }
        """)
        
        self.results_widget = QWidget()
        self.results_layout = QVBoxLayout(self.results_widget)
        self.results_area.setWidget(self.results_widget)
        
        results_layout.addWidget(self.results_area)
        layout.addWidget(self.results_card)
        
        # 초기 메시지
        self.show_initial_message()
        
    def show_initial_message(self):
        """초기 메시지 표시"""
        msg_label = QLabel("🎯 보안 데이터를 입력하고 '위협 예측 시작' 버튼을 클릭하세요.")
        msg_label.setStyleSheet("color: #999; text-align: center; padding: 50px;")
        msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_layout.addWidget(msg_label)
    
    def start_prediction(self):
        """위협 예측 시작"""
        data_text = self.data_input.toPlainText().strip()
        if not data_text:
            QMessageBox.warning(self, "입력 오류", "분석할 데이터를 입력해주세요.")
            return
        
        try:
            # JSON 파싱
            data = json.loads(data_text)
        except json.JSONDecodeError:
            QMessageBox.warning(self, "형식 오류", "올바른 JSON 형식으로 입력해주세요.")
            return
        
        # 기존 결과 삭제
        self.clear_results_display()
        
        # 로딩 표시
        loading_label = QLabel("🔄 AI가 위협을 분석하고 있습니다...")
        loading_label.setStyleSheet("color: #1890ff; text-align: center; padding: 50px; font-size: 14px;")
        loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_layout.addWidget(loading_label)
        
        # 백그라운드에서 예측 실행
        self.prediction_thread = threading.Thread(target=self.run_prediction, args=(data,))
        self.prediction_thread.start()
    
    def run_prediction(self, data: Dict):
        """백그라운드에서 예측 실행"""
        predictions = self.prediction_engine.predict_threats(data)
        self.prediction_engine.prediction_ready.emit({"predictions": predictions})
    
    @pyqtSlot(dict)
    def on_prediction_ready(self, result):
        """예측 완료 시 호출"""
        predictions = result["predictions"]
        self.clear_results_display()
        self.display_predictions(predictions)
    
    def display_predictions(self, predictions: List[ThreatPrediction]):
        """예측 결과 표시"""
        if not predictions:
            no_threat_label = QLabel("✅ 현재 데이터에서 특별한 위협이 감지되지 않았습니다.")
            no_threat_label.setStyleSheet("color: #52c41a; text-align: center; padding: 50px; font-size: 14px;")
            no_threat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.results_layout.addWidget(no_threat_label)
            return
        
        # 위협 수준별 정렬
        severity_order = {"심각": 0, "높음": 1, "보통": 2, "낮음": 3}
        predictions.sort(key=lambda x: (severity_order.get(x.severity, 4), -x.confidence))
        
        for i, pred in enumerate(predictions):
            pred_card = self.create_prediction_card(pred, i + 1)
            self.results_layout.addWidget(pred_card)
        
        # 요약 통계
        summary_card = self.create_summary_card(predictions)
        self.results_layout.insertWidget(0, summary_card)
    
    def create_prediction_card(self, prediction: ThreatPrediction, index: int) -> QWidget:
        """개별 예측 결과 카드 생성"""
        card = Card()
        layout = QVBoxLayout(card)
        
        # 심각도별 색상
        severity_colors = {
            "심각": "#ff4d4f",
            "높음": "#ff7a45", 
            "보통": "#faad14",
            "낮음": "#52c41a"
        }
        color = severity_colors.get(prediction.severity, "#999")
        
        # 헤더
        header_layout = QHBoxLayout()
        
        title = QLabel(f"{index}. {prediction.threat_type}")
        title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {color};")
        header_layout.addWidget(title)
        
        confidence_badge = QLabel(f"{prediction.confidence:.1%}")
        confidence_badge.setStyleSheet(f"""
            background-color: {color};
            color: white;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        """)
        header_layout.addWidget(confidence_badge)
        
        severity_badge = QLabel(prediction.severity)
        severity_badge.setStyleSheet(f"""
            background-color: {color}22;
            color: {color};
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            border: 1px solid {color};
        """)
        header_layout.addWidget(severity_badge)
        
        layout.addLayout(header_layout)
        
        # 설명
        desc = QLabel(prediction.description)
        desc.setStyleSheet("color: #333; margin: 10px 0;")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # 세부 정보
        details_layout = QGridLayout()
        
        # 지표
        indicators_label = QLabel("🔍 탐지 지표:")
        indicators_label.setStyleSheet("font-weight: bold;")
        details_layout.addWidget(indicators_label, 0, 0)
        
        indicators_text = QLabel(", ".join(prediction.indicators))
        indicators_text.setWordWrap(True)
        indicators_text.setStyleSheet("color: #666;")
        details_layout.addWidget(indicators_text, 0, 1)
        
        # 타임라인
        timeline_label = QLabel("⏰ 대응 시간:")
        timeline_label.setStyleSheet("font-weight: bold;")
        details_layout.addWidget(timeline_label, 1, 0)
        
        timeline_text = QLabel(prediction.timeline)
        timeline_text.setStyleSheet("color: #666;")
        details_layout.addWidget(timeline_text, 1, 1)
        
        # 대응 방안
        mitigation_label = QLabel("🛡️ 대응 방안:")
        mitigation_label.setStyleSheet("font-weight: bold;")
        details_layout.addWidget(mitigation_label, 2, 0)
        
        mitigation_text = QLabel(", ".join(prediction.mitigation))
        mitigation_text.setWordWrap(True)
        mitigation_text.setStyleSheet("color: #666;")
        details_layout.addWidget(mitigation_text, 2, 1)
        
        layout.addLayout(details_layout)
        
        return card
    
    def create_summary_card(self, predictions: List[ThreatPrediction]) -> QWidget:
        """요약 통계 카드"""
        card = Card()
        layout = QVBoxLayout(card)
        
        title = QLabel("📊 위협 예측 요약")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # 통계 정보
        stats_layout = QGridLayout()
        
        total_threats = len(predictions)
        severity_counts = {}
        for pred in predictions:
            severity_counts[pred.severity] = severity_counts.get(pred.severity, 0) + 1
        
        avg_confidence = sum(pred.confidence for pred in predictions) / len(predictions) if predictions else 0
        
        stats_layout.addWidget(QLabel("총 위협 수:"), 0, 0)
        stats_layout.addWidget(QLabel(f"{total_threats}개"), 0, 1)
        
        stats_layout.addWidget(QLabel("평균 신뢰도:"), 0, 2)
        stats_layout.addWidget(QLabel(f"{avg_confidence:.1%}"), 0, 3)
        
        row = 1
        for severity, count in severity_counts.items():
            stats_layout.addWidget(QLabel(f"{severity} 위협:"), row, 0)
            stats_layout.addWidget(QLabel(f"{count}개"), row, 1)
            row += 1
        
        layout.addLayout(stats_layout)
        
        return card
    
    def clear_results(self):
        """결과 초기화"""
        self.data_input.clear()
        self.clear_results_display()
        self.show_initial_message()
    
    def clear_results_display(self):
        """결과 표시 영역 초기화"""
        while self.results_layout.count():
            child = self.results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

if __name__ == "__main__":
    app = QApplication([])
    tab = ThreatPredictionTab()
    tab.show()
    app.exec()