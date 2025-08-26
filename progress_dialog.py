# progress_dialog.py - 진행 상황 표시 다이얼로그
"""
MetaShield 진행 상황 표시 컴포넌트
- 작업 진행 단계별 표시
- 취소 가능한 작업 지원
- 실시간 진행률 및 메시지 업데이트
- 에러 처리 및 로깅
"""

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from typing import List, Optional, Callable
from datetime import datetime

class ProgressStep:
    """진행 단계 정보"""
    def __init__(self, name: str, description: str = "", weight: int = 1):
        self.name = name
        self.description = description
        self.weight = weight
        self.status = "pending"  # pending, running, completed, failed
        self.message = ""
        self.start_time = None
        self.end_time = None

class ModernProgressDialog(QDialog):
    """현대적인 진행 상황 표시 다이얼로그"""
    
    # 시그널
    cancelled = pyqtSignal()
    step_started = pyqtSignal(int, str)  # step_index, step_name
    step_completed = pyqtSignal(int, str, bool)  # step_index, step_name, success
    
    def __init__(self, title: str = "작업 진행 중", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowTitleHint)
        self.resize(500, 400)
        
        # 내부 변수
        self.steps = []
        self.current_step_index = 0
        self.is_cancelled = False
        self.start_time = None
        self.total_weight = 0
        self.completed_weight = 0
        
        self.setup_ui()
        self.apply_modern_style()
    
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)
        
        # 헤더 영역
        header_layout = QHBoxLayout()
        
        # 아이콘
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(32, 32)
        self.icon_label.setPixmap(self.style().standardPixmap(QStyle.StandardPixmap.SP_ComputerIcon))
        header_layout.addWidget(self.icon_label)
        
        # 제목 및 설명
        title_layout = QVBoxLayout()
        self.title_label = QLabel("작업을 진행하고 있습니다...")
        self.title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #262626;")
        
        self.subtitle_label = QLabel("잠시만 기다려 주세요.")
        self.subtitle_label.setStyleSheet("font-size: 12px; color: #8c8c8c;")
        
        title_layout.addWidget(self.title_label)
        title_layout.addWidget(self.subtitle_label)
        title_layout.addStretch()
        
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # 전체 진행률 바
        self.overall_progress = QProgressBar()
        self.overall_progress.setMaximum(100)
        self.overall_progress.setValue(0)
        self.overall_progress.setTextVisible(True)
        layout.addWidget(self.overall_progress)
        
        # 현재 단계 정보
        self.current_step_label = QLabel("준비 중...")
        self.current_step_label.setStyleSheet("font-weight: bold; color: #1890ff;")
        layout.addWidget(self.current_step_label)
        
        # 단계별 진행 상황
        self.steps_widget = QScrollArea()
        self.steps_widget.setWidgetResizable(True)
        self.steps_widget.setMaximumHeight(200)
        
        self.steps_content = QWidget()
        self.steps_layout = QVBoxLayout(self.steps_content)
        self.steps_layout.setSpacing(8)
        self.steps_widget.setWidget(self.steps_content)
        
        layout.addWidget(self.steps_widget)
        
        # 상세 메시지 영역
        self.detail_text = QTextEdit()
        self.detail_text.setMaximumHeight(100)
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("작업 상세 내용이 여기에 표시됩니다...")
        layout.addWidget(self.detail_text)
        
        # 하단 버튼
        button_layout = QHBoxLayout()
        
        # 경과 시간 표시
        self.elapsed_label = QLabel("경과 시간: 00:00")
        self.elapsed_label.setStyleSheet("color: #8c8c8c; font-size: 11px;")
        button_layout.addWidget(self.elapsed_label)
        
        button_layout.addStretch()
        
        # 취소 버튼
        self.cancel_btn = QPushButton("취소")
        self.cancel_btn.setMinimumWidth(80)
        self.cancel_btn.clicked.connect(self.cancel_operation)
        button_layout.addWidget(self.cancel_btn)
        
        # 완료 버튼 (처음엔 숨김)
        self.close_btn = QPushButton("닫기")
        self.close_btn.setMinimumWidth(80)
        self.close_btn.clicked.connect(self.accept)
        self.close_btn.setVisible(False)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        
        # 타이머 설정 (경과 시간 업데이트)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_elapsed_time)
        self.timer.start(1000)  # 1초마다
        
        self.setLayout(layout)
    
    def apply_modern_style(self):
        """모던 스타일 적용"""
        self.setStyleSheet("""
            ModernProgressDialog {
                background-color: #fafafa;
                border-radius: 8px;
            }
            QProgressBar {
                border: 1px solid #d9d9d9;
                border-radius: 4px;
                text-align: center;
                background-color: #f5f5f5;
                height: 22px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                    stop:0 #1890ff, stop:1 #40a9ff);
                border-radius: 3px;
            }
            QPushButton {
                background-color: white;
                border: 1px solid #d9d9d9;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 14px;
            }
            QPushButton:hover {
                border-color: #40a9ff;
                color: #1890ff;
            }
            QPushButton:pressed {
                background-color: #f0f0f0;
            }
            QTextEdit {
                border: 1px solid #d9d9d9;
                border-radius: 6px;
                padding: 8px;
                background-color: white;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QScrollArea {
                border: 1px solid #d9d9d9;
                border-radius: 6px;
                background-color: white;
            }
        """)
    
    def set_steps(self, steps: List[ProgressStep]):
        """진행 단계 설정"""
        self.steps = steps
        self.total_weight = sum(step.weight for step in steps)
        self.completed_weight = 0
        self.current_step_index = 0
        
        # 단계별 UI 생성
        self._create_step_widgets()
        
        # 전체 진행률 초기화
        self.overall_progress.setValue(0)
        
    def _create_step_widgets(self):
        """단계별 위젯 생성"""
        # 기존 위젯 정리
        for i in reversed(range(self.steps_layout.count())):
            child = self.steps_layout.itemAt(i).widget()
            if child:
                child.setParent(None)
        
        # 단계별 위젯 생성
        self.step_widgets = []
        for i, step in enumerate(self.steps):
            step_widget = self._create_step_widget(i, step)
            self.steps_layout.addWidget(step_widget)
            self.step_widgets.append(step_widget)
        
        self.steps_layout.addStretch()
    
    def _create_step_widget(self, index: int, step: ProgressStep) -> QWidget:
        """개별 단계 위젯 생성"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Shape.Box)
        widget.setStyleSheet("""
            QFrame {
                border: 1px solid #f0f0f0;
                border-radius: 4px;
                background-color: white;
                padding: 4px;
            }
        """)
        
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(8, 6, 8, 6)
        
        # 상태 아이콘
        status_label = QLabel()
        status_label.setFixedSize(16, 16)
        self._update_step_icon(status_label, "pending")
        layout.addWidget(status_label)
        
        # 단계 정보
        info_layout = QVBoxLayout()
        
        name_label = QLabel(f"{index + 1}. {step.name}")
        name_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        info_layout.addWidget(name_label)
        
        if step.description:
            desc_label = QLabel(step.description)
            desc_label.setStyleSheet("color: #8c8c8c; font-size: 11px;")
            info_layout.addWidget(desc_label)
        
        layout.addLayout(info_layout)
        layout.addStretch()
        
        # 위젯 저장 (나중에 업데이트용)
        widget.status_label = status_label
        widget.name_label = name_label
        
        return widget
    
    def _update_step_icon(self, label: QLabel, status: str):
        """단계 상태 아이콘 업데이트"""
        icons = {
            "pending": "⏳",
            "running": "🔄", 
            "completed": "✅",
            "failed": "❌"
        }
        
        colors = {
            "pending": "#8c8c8c",
            "running": "#1890ff",
            "completed": "#52c41a", 
            "failed": "#ff4d4f"
        }
        
        icon_text = icons.get(status, "⏳")
        color = colors.get(status, "#8c8c8c")
        
        label.setText(icon_text)
        label.setStyleSheet(f"color: {color}; font-size: 14px;")
    
    def start_operation(self):
        """작업 시작"""
        self.start_time = datetime.now()
        self.is_cancelled = False
        
        # 첫 번째 단계로 이동
        if self.steps:
            self.start_step(0)
    
    def start_step(self, step_index: int):
        """특정 단계 시작"""
        if step_index >= len(self.steps) or self.is_cancelled:
            return
        
        self.current_step_index = step_index
        step = self.steps[step_index]
        
        # 단계 상태 업데이트
        step.status = "running"
        step.start_time = datetime.now()
        step.message = "진행 중..."
        
        # UI 업데이트
        self.current_step_label.setText(f"🔄 {step.name}")
        self._update_step_widget(step_index, "running")
        
        # 시그널 발생
        self.step_started.emit(step_index, step.name)
        
        # 진행률 업데이트
        self._update_overall_progress()
    
    def complete_step(self, step_index: int, success: bool = True, message: str = ""):
        """단계 완료"""
        if step_index >= len(self.steps):
            return
        
        step = self.steps[step_index]
        
        # 단계 상태 업데이트
        step.status = "completed" if success else "failed"
        step.end_time = datetime.now()
        step.message = message or ("완료" if success else "실패")
        
        # UI 업데이트
        self._update_step_widget(step_index, step.status)
        
        # 완료된 가중치 업데이트
        if success:
            self.completed_weight += step.weight
        
        # 시그널 발생
        self.step_completed.emit(step_index, step.name, success)
        
        # 진행률 업데이트
        self._update_overall_progress()
        
        # 상세 메시지 추가
        if message:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.detail_text.append(f"[{timestamp}] {step.name}: {message}")
        
        # 모든 단계 완료 확인
        if step_index == len(self.steps) - 1:
            self._operation_completed(success)
    
    def _update_step_widget(self, step_index: int, status: str):
        """단계 위젯 UI 업데이트"""
        if step_index < len(self.step_widgets):
            widget = self.step_widgets[step_index]
            self._update_step_icon(widget.status_label, status)
    
    def _update_overall_progress(self):
        """전체 진행률 업데이트"""
        if self.total_weight > 0:
            progress = int((self.completed_weight / self.total_weight) * 100)
            self.overall_progress.setValue(progress)
            
            # 현재 진행 단계 추가 (실행 중인 단계 50% 가중치)
            if self.current_step_index < len(self.steps):
                current_step = self.steps[self.current_step_index]
                if current_step.status == "running":
                    additional_progress = (current_step.weight * 0.5) / self.total_weight * 100
                    self.overall_progress.setValue(min(100, progress + int(additional_progress)))
    
    def update_step_message(self, step_index: int, message: str):
        """단계 진행 메시지 업데이트"""
        if step_index < len(self.steps):
            step = self.steps[step_index]
            step.message = message
            
            # 현재 단계면 UI 업데이트
            if step_index == self.current_step_index:
                self.current_step_label.setText(f"🔄 {step.name}: {message}")
                
            # 상세 메시지 추가
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.detail_text.append(f"[{timestamp}] {message}")
    
    def cancel_operation(self):
        """작업 취소"""
        self.is_cancelled = True
        self.cancelled.emit()
        
        # 현재 실행 중인 단계를 실패로 표시
        if self.current_step_index < len(self.steps):
            self.complete_step(self.current_step_index, False, "사용자에 의해 취소됨")
        
        # UI 업데이트
        self.title_label.setText("작업이 취소되었습니다")
        self.subtitle_label.setText("일부 작업이 완료되지 않았을 수 있습니다.")
        self.current_step_label.setText("❌ 취소됨")
        
        # 버튼 상태 변경
        self.cancel_btn.setVisible(False)
        self.close_btn.setVisible(True)
    
    def _operation_completed(self, success: bool):
        """전체 작업 완료"""
        # UI 업데이트
        if success:
            self.title_label.setText("✅ 작업이 완료되었습니다")
            self.subtitle_label.setText("모든 단계가 성공적으로 처리되었습니다.")
            self.current_step_label.setText("🎉 완료")
            self.overall_progress.setValue(100)
        else:
            self.title_label.setText("❌ 작업이 실패했습니다")
            self.subtitle_label.setText("일부 단계에서 오류가 발생했습니다.")
            self.current_step_label.setText("💥 실패")
        
        # 버튼 상태 변경
        self.cancel_btn.setVisible(False)
        self.close_btn.setVisible(True)
        
        # 타이머 정지
        self.timer.stop()
    
    def update_elapsed_time(self):
        """경과 시간 업데이트"""
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            hours = elapsed.seconds // 3600
            minutes = (elapsed.seconds // 60) % 60
            seconds = elapsed.seconds % 60
            
            if hours > 0:
                time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                time_str = f"{minutes:02d}:{seconds:02d}"
            
            self.elapsed_label.setText(f"경과 시간: {time_str}")
    
    def closeEvent(self, event):
        """다이얼로그 닫기 이벤트"""
        # 작업이 진행 중이면 취소 확인
        if not self.is_cancelled and any(step.status == "running" for step in self.steps):
            reply = QMessageBox.question(
                self, "작업 취소", 
                "작업이 진행 중입니다. 정말로 취소하시겠습니까?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.cancel_operation()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


class ProgressWorker(QObject):
    """백그라운드 작업을 위한 워커 클래스"""
    
    step_started = pyqtSignal(int, str)
    step_progress = pyqtSignal(int, str)
    step_completed = pyqtSignal(int, bool, str)
    finished = pyqtSignal(bool)
    error = pyqtSignal(str)
    
    def __init__(self, steps: List[ProgressStep], work_function: Callable):
        super().__init__()
        self.steps = steps
        self.work_function = work_function
        self.is_cancelled = False
    
    def run_work(self):
        """작업 실행"""
        try:
            # 작업 함수에 진행 상황 콜백 전달
            self.work_function(self)
            self.finished.emit(True)
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False)
    
    def cancel(self):
        """작업 취소"""
        self.is_cancelled = True
    
    def report_step_start(self, step_index: int):
        """단계 시작 보고"""
        if step_index < len(self.steps):
            self.step_started.emit(step_index, self.steps[step_index].name)
    
    def report_step_progress(self, step_index: int, message: str):
        """단계 진행 보고"""
        self.step_progress.emit(step_index, message)
    
    def report_step_complete(self, step_index: int, success: bool = True, message: str = ""):
        """단계 완료 보고"""
        self.step_completed.emit(step_index, success, message)


def create_progress_dialog(title: str, steps: List[ProgressStep], 
                          work_function: Callable, parent=None) -> ModernProgressDialog:
    """진행 상황 다이얼로그 생성 헬퍼 함수"""
    dialog = ModernProgressDialog(title, parent)
    dialog.set_steps(steps)
    
    # 워커 스레드 설정
    worker = ProgressWorker(steps, work_function)
    thread = QThread()
    worker.moveToThread(thread)
    
    # 시그널 연결
    worker.step_started.connect(dialog.start_step)
    worker.step_progress.connect(dialog.update_step_message)
    worker.step_completed.connect(lambda idx, success, msg: dialog.complete_step(idx, success, msg))
    worker.finished.connect(thread.quit)
    worker.error.connect(lambda err: dialog.update_step_message(dialog.current_step_index, f"오류: {err}"))
    
    dialog.cancelled.connect(worker.cancel)
    thread.started.connect(worker.run_work)
    
    # 작업 시작
    dialog.start_operation()
    thread.start()
    
    return dialog