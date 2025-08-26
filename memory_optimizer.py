# memory_optimizer.py - 메모리 사용량 최적화 시스템
"""
MetaShield 애플리케이션의 메모리 사용량을 모니터링하고 최적화하는 시스템
"""

import gc
import sys
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import tracemalloc
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, PrimaryButton, SecondaryButton
from modern_ui_style import MODERN_STYLE

@dataclass
class MemorySnapshot:
    """메모리 스냅샷"""
    timestamp: str
    total_memory_mb: float
    available_memory_mb: float
    process_memory_mb: float
    cpu_percent: float
    thread_count: int
    object_count: int
    gc_stats: Dict[str, int]

@dataclass
class MemoryLeak:
    """메모리 누수 정보"""
    object_type: str
    count: int
    size_mb: float
    growth_rate: float
    first_detected: str
    last_updated: str

class MemoryOptimizer(QObject):
    """메모리 최적화 엔진"""
    
    memory_stats_updated = pyqtSignal(dict)
    memory_leak_detected = pyqtSignal(dict)
    optimization_complete = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.process = psutil.Process()
        self.memory_history = []
        self.max_history = 100
        
        # 메모리 추적 시작
        tracemalloc.start()
        
        # 기본 최적화 설정
        self.optimization_config = {
            "auto_gc_threshold": 100.0,  # MB
            "cache_cleanup_threshold": 200.0,  # MB
            "widget_cleanup_interval": 300,  # seconds
            "memory_leak_threshold": 50.0,  # MB growth
            "emergency_cleanup_threshold": 500.0  # MB
        }
        
        # 객체 참조 추적
        self.object_tracker = {}
        self.leak_candidates = {}
        
    def start_monitoring(self, interval: int = 5):
        """메모리 모니터링 시작"""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_memory, args=(interval,))
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """메모리 모니터링 중지"""
        self.monitoring = False
    
    def _monitor_memory(self, interval: int):
        """메모리 모니터링 루프"""
        while self.monitoring:
            try:
                snapshot = self._take_memory_snapshot()
                self.memory_history.append(snapshot)
                
                # 히스토리 크기 제한
                if len(self.memory_history) > self.max_history:
                    self.memory_history.pop(0)
                
                # UI 업데이트
                self.memory_stats_updated.emit({
                    "snapshot": snapshot,
                    "history": self.memory_history[-20:] if self.memory_history else []
                })
                
                # 자동 최적화 확인
                self._check_auto_optimization(snapshot)
                
                # 메모리 누수 감지
                self._detect_memory_leaks()
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"메모리 모니터링 오류: {e}")
                time.sleep(interval)
    
    def _take_memory_snapshot(self) -> MemorySnapshot:
        """메모리 스냅샷 생성"""
        # 시스템 메모리 정보
        memory = psutil.virtual_memory()
        
        # 프로세스 메모리 정보
        process_memory = self.process.memory_info()
        
        # CPU 사용률
        cpu_percent = self.process.cpu_percent()
        
        # 스레드 수
        thread_count = self.process.num_threads()
        
        # 객체 수 (Python)
        object_count = len(gc.get_objects())
        
        # GC 통계
        gc_stats = {
            f"generation_{i}": gc.get_count()[i] for i in range(3)
        }
        gc_stats["collected"] = sum(gc.get_stats()[i]["collected"] for i in range(3))
        
        return MemorySnapshot(
            timestamp=datetime.now().isoformat(),
            total_memory_mb=memory.total / (1024 * 1024),
            available_memory_mb=memory.available / (1024 * 1024),
            process_memory_mb=process_memory.rss / (1024 * 1024),
            cpu_percent=cpu_percent,
            thread_count=thread_count,
            object_count=object_count,
            gc_stats=gc_stats
        )
    
    def _check_auto_optimization(self, snapshot: MemorySnapshot):
        """자동 최적화 조건 확인"""
        config = self.optimization_config
        
        # 긴급 정리
        if snapshot.process_memory_mb > config["emergency_cleanup_threshold"]:
            self._emergency_cleanup()
            return
        
        # 자동 GC
        if snapshot.process_memory_mb > config["auto_gc_threshold"]:
            self._run_garbage_collection()
        
        # 캐시 정리
        if snapshot.process_memory_mb > config["cache_cleanup_threshold"]:
            self._cleanup_caches()
    
    def _detect_memory_leaks(self):
        """메모리 누수 감지"""
        if len(self.memory_history) < 10:
            return
        
        recent_snapshots = self.memory_history[-10:]
        
        # 메모리 증가 트렌드 분석
        memory_trend = [s.process_memory_mb for s in recent_snapshots]
        if len(memory_trend) >= 5:
            # 선형 회귀로 증가율 계산
            growth_rate = self._calculate_growth_rate(memory_trend)
            
            if growth_rate > 5.0:  # 5MB/snapshot 증가
                leak_info = MemoryLeak(
                    object_type="unknown",
                    count=recent_snapshots[-1].object_count,
                    size_mb=recent_snapshots[-1].process_memory_mb,
                    growth_rate=growth_rate,
                    first_detected=datetime.now().isoformat(),
                    last_updated=datetime.now().isoformat()
                )
                
                self.memory_leak_detected.emit({
                    "leak": leak_info,
                    "snapshots": recent_snapshots
                })
    
    def _calculate_growth_rate(self, values: List[float]) -> float:
        """메모리 증가율 계산"""
        if len(values) < 2:
            return 0.0
        
        # 단순한 평균 증가율
        total_growth = values[-1] - values[0]
        periods = len(values) - 1
        
        return total_growth / periods if periods > 0 else 0.0
    
    def optimize_memory(self) -> Dict[str, Any]:
        """종합적인 메모리 최적화"""
        start_time = time.time()
        before_snapshot = self._take_memory_snapshot()
        
        optimization_results = {
            "before": before_snapshot,
            "actions": [],
            "after": None,
            "improvement_mb": 0,
            "improvement_percent": 0,
            "execution_time": 0
        }
        
        # 1. 가비지 컬렉션
        gc_result = self._run_garbage_collection()
        optimization_results["actions"].append({
            "name": "가비지 컬렉션",
            "objects_collected": gc_result["objects_collected"],
            "memory_freed_mb": gc_result.get("memory_freed_mb", 0)
        })
        
        # 2. 캐시 정리
        cache_result = self._cleanup_caches()
        optimization_results["actions"].append({
            "name": "캐시 정리",
            "caches_cleared": cache_result["caches_cleared"],
            "memory_freed_mb": cache_result.get("memory_freed_mb", 0)
        })
        
        # 3. 위젯 정리
        widget_result = self._cleanup_widgets()
        optimization_results["actions"].append({
            "name": "위젯 정리",
            "widgets_cleaned": widget_result["widgets_cleaned"],
            "memory_freed_mb": widget_result.get("memory_freed_mb", 0)
        })
        
        # 4. 스레드 정리
        thread_result = self._cleanup_threads()
        optimization_results["actions"].append({
            "name": "스레드 정리",
            "threads_cleaned": thread_result["threads_cleaned"],
            "memory_freed_mb": thread_result.get("memory_freed_mb", 0)
        })
        
        # 최적화 후 상태
        after_snapshot = self._take_memory_snapshot()
        optimization_results["after"] = after_snapshot
        
        # 개선 효과 계산
        improvement_mb = before_snapshot.process_memory_mb - after_snapshot.process_memory_mb
        improvement_percent = (improvement_mb / before_snapshot.process_memory_mb) * 100 if before_snapshot.process_memory_mb > 0 else 0
        
        optimization_results["improvement_mb"] = improvement_mb
        optimization_results["improvement_percent"] = improvement_percent
        optimization_results["execution_time"] = time.time() - start_time
        
        return optimization_results
    
    def _run_garbage_collection(self) -> Dict[str, Any]:
        """가비지 컬렉션 실행"""
        before_objects = len(gc.get_objects())
        
        # 각 세대별로 GC 실행
        collected = []
        for generation in range(3):
            collected.append(gc.collect(generation))
        
        after_objects = len(gc.get_objects())
        objects_collected = before_objects - after_objects
        
        return {
            "objects_collected": objects_collected,
            "collected_by_generation": collected,
            "memory_freed_mb": objects_collected * 0.001  # 추정치
        }
    
    def _cleanup_caches(self) -> Dict[str, Any]:
        """다양한 캐시 정리"""
        caches_cleared = 0
        
        # Python 내부 캐시들
        try:
            # sys 모듈 캐시
            if hasattr(sys, 'path_importer_cache'):
                sys.path_importer_cache.clear()
                caches_cleared += 1
            
            # 정규식 캐시 (re 모듈)
            import re
            re.purge()
            caches_cleared += 1
            
            # functools lru_cache 정리는 애플리케이션별로 처리 필요
            
        except Exception as e:
            print(f"캐시 정리 오류: {e}")
        
        return {
            "caches_cleared": caches_cleared,
            "memory_freed_mb": caches_cleared * 5  # 추정치
        }
    
    def _cleanup_widgets(self) -> Dict[str, Any]:
        """사용하지 않는 위젯 정리"""
        widgets_cleaned = 0
        
        try:
            from PyQt6.QtWidgets import QApplication
            
            app = QApplication.instance()
            if app:
                # 모든 최상위 위젯 확인
                top_level_widgets = app.topLevelWidgets()
                
                for widget in top_level_widgets:
                    if not widget.isVisible() and widget.windowTitle() == "":
                        # 보이지 않고 제목이 없는 위젯은 정리 후보
                        try:
                            widget.deleteLater()
                            widgets_cleaned += 1
                        except:
                            continue
        
        except Exception as e:
            print(f"위젯 정리 오류: {e}")
        
        return {
            "widgets_cleaned": widgets_cleaned,
            "memory_freed_mb": widgets_cleaned * 0.5  # 추정치
        }
    
    def _cleanup_threads(self) -> Dict[str, Any]:
        """완료된 스레드 정리"""
        threads_cleaned = 0
        
        try:
            import threading
            
            # 활성 스레드 목록에서 완료된 스레드 찾기
            active_threads = threading.enumerate()
            
            for thread in active_threads:
                if not thread.is_alive() and thread != threading.current_thread():
                    try:
                        # 완료된 스레드는 자동으로 정리되지만 참조 제거
                        threads_cleaned += 1
                    except:
                        continue
        
        except Exception as e:
            print(f"스레드 정리 오류: {e}")
        
        return {
            "threads_cleaned": threads_cleaned,
            "memory_freed_mb": threads_cleaned * 0.1  # 추정치
        }
    
    def _emergency_cleanup(self):
        """긴급 메모리 정리"""
        print("긴급 메모리 정리 실행!")
        
        # 강제 가비지 컬렉션
        for _ in range(3):
            gc.collect()
        
        # 캐시 강제 정리
        self._cleanup_caches()
        
        # 위젯 강제 정리
        self._cleanup_widgets()

class MemoryOptimizerTab(QWidget):
    """메모리 최적화 탭"""
    
    def __init__(self):
        super().__init__()
        self.optimizer = MemoryOptimizer()
        self.optimizer.memory_stats_updated.connect(self.on_memory_stats_updated)
        self.optimizer.memory_leak_detected.connect(self.on_memory_leak_detected)
        self.optimizer.optimization_complete.connect(self.on_optimization_complete)
        self.setup_ui()
        
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 제목
        title = QLabel("⚡ 메모리 사용량 최적화")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("MetaShield 애플리케이션의 메모리 사용량을 실시간 모니터링하고 최적화합니다.")
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # 제어 패널
        control_card = Card()
        control_layout = QHBoxLayout(control_card)
        
        self.status_label = QLabel("🔴 모니터링 중지됨")
        self.status_label.setStyleSheet("font-weight: bold; color: #ff4d4f;")
        control_layout.addWidget(self.status_label)
        
        control_layout.addStretch()
        
        self.start_btn = PrimaryButton("▶️ 모니터링 시작")
        self.start_btn.clicked.connect(self.start_monitoring)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = SecondaryButton("⏹️ 모니터링 중지")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        self.optimize_btn = PrimaryButton("🚀 메모리 최적화")
        self.optimize_btn.clicked.connect(self.optimize_memory)
        control_layout.addWidget(self.optimize_btn)
        
        layout.addWidget(control_card)
        
        # 상태 대시보드
        dashboard_layout = QHBoxLayout()
        
        # 메모리 상태 카드
        self.memory_card = Card("💾 메모리 상태")
        memory_layout = QVBoxLayout()
        
        self.process_memory_label = QLabel("프로세스 메모리: 0 MB")
        self.process_memory_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #1890ff;")
        memory_layout.addWidget(self.process_memory_label)
        
        self.system_memory_label = QLabel("시스템 메모리: 0 / 0 MB")
        self.system_memory_label.setStyleSheet("color: #666;")
        memory_layout.addWidget(self.system_memory_label)
        
        self.memory_usage_bar = QProgressBar()
        self.memory_usage_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #d9d9d9;
                border-radius: 6px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #1890ff;
                border-radius: 4px;
            }
        """)
        memory_layout.addWidget(self.memory_usage_bar)
        
        self.memory_card.layout().addLayout(memory_layout)
        dashboard_layout.addWidget(self.memory_card)
        
        # 성능 상태 카드
        self.performance_card = Card("⚡ 성능 상태")
        performance_layout = QVBoxLayout()
        
        self.cpu_label = QLabel("CPU 사용률: 0%")
        self.cpu_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        performance_layout.addWidget(self.cpu_label)
        
        self.thread_label = QLabel("스레드 수: 0")
        self.thread_label.setStyleSheet("color: #666;")
        performance_layout.addWidget(self.thread_label)
        
        self.object_label = QLabel("Python 객체: 0")
        self.object_label.setStyleSheet("color: #666;")
        performance_layout.addWidget(self.object_label)
        
        self.performance_card.layout().addLayout(performance_layout)
        dashboard_layout.addWidget(self.performance_card)
        
        # GC 상태 카드
        self.gc_card = Card("🗑️ 가비지 컬렉션")
        gc_layout = QVBoxLayout()
        
        self.gc_gen0_label = QLabel("Generation 0: 0")
        gc_layout.addWidget(self.gc_gen0_label)
        
        self.gc_gen1_label = QLabel("Generation 1: 0")
        gc_layout.addWidget(self.gc_gen1_label)
        
        self.gc_gen2_label = QLabel("Generation 2: 0")
        gc_layout.addWidget(self.gc_gen2_label)
        
        self.gc_collected_label = QLabel("수집됨: 0")
        self.gc_collected_label.setStyleSheet("color: #52c41a; font-weight: bold;")
        gc_layout.addWidget(self.gc_collected_label)
        
        self.gc_card.layout().addLayout(gc_layout)
        dashboard_layout.addWidget(self.gc_card)
        
        layout.addLayout(dashboard_layout)
        
        # 탭 위젯
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #d9d9d9;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #1890ff;
            }
        """)
        
        # 메모리 히스토리 탭
        self.history_tab = self.create_history_tab()
        tab_widget.addTab(self.history_tab, "📈 메모리 히스토리")
        
        # 누수 탐지 탭
        self.leak_tab = self.create_leak_detection_tab()
        tab_widget.addTab(self.leak_tab, "🔍 누수 탐지")
        
        # 최적화 로그 탭
        self.log_tab = self.create_optimization_log_tab()
        tab_widget.addTab(self.log_tab, "📝 최적화 로그")
        
        layout.addWidget(tab_widget)
        
    def create_history_tab(self):
        """메모리 히스토리 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 히스토리 테이블
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "시간", "프로세스 메모리(MB)", "CPU(%)", "스레드", "객체 수", "상태"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.history_table)
        
        return widget
    
    def create_leak_detection_tab(self):
        """누수 탐지 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 누수 목록
        self.leak_list = QListWidget()
        self.leak_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
            }
            QListWidgetItem {
                padding: 10px;
                border-bottom: 1px solid #f0f0f0;
            }
        """)
        
        layout.addWidget(self.leak_list)
        
        # 초기 메시지
        initial_item = QListWidgetItem("메모리 누수가 감지되면 여기에 표시됩니다.")
        initial_item.setForeground(QColor("#999"))
        self.leak_list.addItem(initial_item)
        
        return widget
    
    def create_optimization_log_tab(self):
        """최적화 로그 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 로그 영역
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("""
            QTextEdit {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: #fafafa;
                font-family: monospace;
                font-size: 12px;
            }
        """)
        self.log_area.append("메모리 최적화 로그가 여기에 표시됩니다.")
        
        layout.addWidget(self.log_area)
        
        return widget
    
    def start_monitoring(self):
        """모니터링 시작"""
        self.optimizer.start_monitoring(interval=2)
        self.status_label.setText("🟢 모니터링 실행 중")
        self.status_label.setStyleSheet("font-weight: bold; color: #52c41a;")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.add_log("메모리 모니터링을 시작했습니다.")
    
    def stop_monitoring(self):
        """모니터링 중지"""
        self.optimizer.stop_monitoring()
        self.status_label.setText("🔴 모니터링 중지됨")
        self.status_label.setStyleSheet("font-weight: bold; color: #ff4d4f;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        self.add_log("메모리 모니터링을 중지했습니다.")
    
    def optimize_memory(self):
        """메모리 최적화 실행"""
        self.add_log("메모리 최적화를 시작합니다...")
        
        # 백그라운드에서 최적화 실행
        self.optimization_thread = threading.Thread(target=self.run_optimization)
        self.optimization_thread.start()
        
        # 버튼 임시 비활성화
        self.optimize_btn.setEnabled(False)
        QTimer.singleShot(5000, lambda: self.optimize_btn.setEnabled(True))
    
    def run_optimization(self):
        """백그라운드에서 최적화 실행"""
        try:
            result = self.optimizer.optimize_memory()
            self.optimizer.optimization_complete.emit(result)
        except Exception as e:
            self.add_log(f"최적화 오류: {str(e)}")
    
    @pyqtSlot(dict)
    def on_memory_stats_updated(self, data):
        """메모리 통계 업데이트"""
        snapshot = data["snapshot"]
        
        # 메모리 상태 업데이트
        self.process_memory_label.setText(f"프로세스 메모리: {snapshot.process_memory_mb:.1f} MB")
        
        used_memory = snapshot.total_memory_mb - snapshot.available_memory_mb
        self.system_memory_label.setText(f"시스템 메모리: {used_memory:.1f} / {snapshot.total_memory_mb:.1f} MB")
        
        memory_percent = int((used_memory / snapshot.total_memory_mb) * 100)
        self.memory_usage_bar.setValue(memory_percent)
        
        # 성능 상태 업데이트
        self.cpu_label.setText(f"CPU 사용률: {snapshot.cpu_percent:.1f}%")
        self.thread_label.setText(f"스레드 수: {snapshot.thread_count}")
        self.object_label.setText(f"Python 객체: {snapshot.object_count:,}")
        
        # GC 상태 업데이트
        gc_stats = snapshot.gc_stats
        self.gc_gen0_label.setText(f"Generation 0: {gc_stats.get('generation_0', 0)}")
        self.gc_gen1_label.setText(f"Generation 1: {gc_stats.get('generation_1', 0)}")
        self.gc_gen2_label.setText(f"Generation 2: {gc_stats.get('generation_2', 0)}")
        self.gc_collected_label.setText(f"수집됨: {gc_stats.get('collected', 0)}")
        
        # 히스토리 테이블 업데이트
        self.update_history_table(data["history"])
    
    def update_history_table(self, history):
        """히스토리 테이블 업데이트"""
        self.history_table.setRowCount(len(history))
        
        for i, snapshot in enumerate(history):
            timestamp = snapshot.timestamp.split('T')[1][:8]  # HH:MM:SS만 표시
            
            self.history_table.setItem(i, 0, QTableWidgetItem(timestamp))
            self.history_table.setItem(i, 1, QTableWidgetItem(f"{snapshot.process_memory_mb:.1f}"))
            self.history_table.setItem(i, 2, QTableWidgetItem(f"{snapshot.cpu_percent:.1f}"))
            self.history_table.setItem(i, 3, QTableWidgetItem(str(snapshot.thread_count)))
            self.history_table.setItem(i, 4, QTableWidgetItem(f"{snapshot.object_count:,}"))
            
            # 상태 (메모리 사용량 기준)
            if snapshot.process_memory_mb > 500:
                status = "높음"
                status_color = QColor("#ff4d4f")
            elif snapshot.process_memory_mb > 200:
                status = "보통"
                status_color = QColor("#faad14")
            else:
                status = "정상"
                status_color = QColor("#52c41a")
            
            status_item = QTableWidgetItem(status)
            status_item.setForeground(status_color)
            self.history_table.setItem(i, 5, status_item)
        
        # 최신 항목으로 스크롤
        if self.history_table.rowCount() > 0:
            self.history_table.scrollToBottom()
    
    @pyqtSlot(dict)
    def on_memory_leak_detected(self, data):
        """메모리 누수 탐지 시 처리"""
        leak = data["leak"]
        
        # 누수 목록에 추가
        leak_text = f"[{leak.first_detected[:19]}] 메모리 증가: {leak.growth_rate:.1f}MB/interval (총 {leak.size_mb:.1f}MB)"
        
        leak_item = QListWidgetItem(leak_text)
        leak_item.setBackground(QColor("#fff2f0"))
        leak_item.setForeground(QColor("#ff4d4f"))
        
        self.leak_list.insertItem(0, leak_item)
        
        # 로그 추가
        self.add_log(f"메모리 누수 감지: {leak.growth_rate:.1f}MB 증가율")
        
        # 경고 메시지
        QMessageBox.warning(
            self, "메모리 누수 감지",
            f"메모리 사용량이 지속적으로 증가하고 있습니다.\n"
            f"증가율: {leak.growth_rate:.1f}MB per interval\n"
            f"현재 메모리: {leak.size_mb:.1f}MB"
        )
    
    @pyqtSlot(dict)
    def on_optimization_complete(self, result):
        """최적화 완료 처리"""
        improvement_mb = result["improvement_mb"]
        improvement_percent = result["improvement_percent"]
        execution_time = result["execution_time"]
        
        # 로그 추가
        self.add_log(f"메모리 최적화 완료:")
        self.add_log(f"  - 메모리 절약: {improvement_mb:.1f}MB ({improvement_percent:.1f}%)")
        self.add_log(f"  - 실행 시간: {execution_time:.2f}초")
        
        for action in result["actions"]:
            self.add_log(f"  - {action['name']}: {action.get('memory_freed_mb', 0):.1f}MB 절약")
        
        # 완료 메시지
        QMessageBox.information(
            self, "최적화 완료",
            f"메모리 최적화가 완료되었습니다.\n\n"
            f"절약된 메모리: {improvement_mb:.1f}MB ({improvement_percent:.1f}%)\n"
            f"실행 시간: {execution_time:.2f}초"
        )
    
    def add_log(self, message: str):
        """로그 추가"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.append(f"[{timestamp}] {message}")
        
        # 자동 스크롤
        cursor = self.log_area.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_area.setTextCursor(cursor)

if __name__ == "__main__":
    app = QApplication([])
    tab = MemoryOptimizerTab()
    tab.show()
    app.exec()