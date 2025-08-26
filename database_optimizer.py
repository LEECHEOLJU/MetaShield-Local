# database_optimizer.py - 데이터베이스 성능 최적화 시스템
"""
MetaShield의 모든 데이터베이스 성능을 최적화하는 시스템
"""

import os
import time
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, PrimaryButton, SecondaryButton
from modern_ui_style import MODERN_STYLE

@dataclass
class DatabaseInfo:
    """데이터베이스 정보"""
    name: str
    path: str
    size_mb: float
    tables_count: int
    records_count: int
    indexes_count: int
    last_optimized: str
    performance_score: float

@dataclass
class OptimizationResult:
    """최적화 결과"""
    database: str
    action: str
    before_size_mb: float
    after_size_mb: float
    records_before: int
    records_after: int
    performance_improvement: float
    execution_time_seconds: float

class DatabaseOptimizer(QObject):
    """데이터베이스 최적화 엔진"""
    
    optimization_progress = pyqtSignal(str, int)
    optimization_complete = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.databases = {
            "cve_cache_3_1.db": {
                "description": "CVE 데이터 캐시",
                "tables": ["cache", "history"],
                "cleanup_sql": [
                    "DELETE FROM cache WHERE datetime(timestamp) < datetime('now', '-30 days')",
                    "DELETE FROM history WHERE datetime(timestamp) < datetime('now', '-90 days')"
                ]
            },
            "pattern_dict.db": {
                "description": "패턴 사전 데이터",
                "tables": ["patterns", "categories"],
                "cleanup_sql": [
                    "DELETE FROM patterns WHERE datetime(created_at) < datetime('now', '-180 days') AND is_favorite = 0"
                ]
            },
            "behavior_analysis.db": {
                "description": "행위 분석 데이터",
                "tables": ["behavior_events", "threat_behaviors"],
                "cleanup_sql": [
                    "DELETE FROM behavior_events WHERE datetime(timestamp) < datetime('now', '-14 days')",
                    "DELETE FROM threat_behaviors WHERE datetime(last_seen) < datetime('now', '-30 days')"
                ]
            },
            "threat_predictions.db": {
                "description": "위협 예측 데이터",
                "tables": ["threat_predictions", "threat_patterns"],
                "cleanup_sql": [
                    "DELETE FROM threat_predictions WHERE datetime(created_at) < datetime('now', '-60 days')",
                    "DELETE FROM threat_patterns WHERE frequency < 2 AND datetime(last_seen) < datetime('now', '-30 days')"
                ]
            },
            "security_reports.db": {
                "description": "보안 리포트 데이터",
                "tables": ["security_reports"],
                "cleanup_sql": [
                    "DELETE FROM security_reports WHERE datetime(created_at) < datetime('now', '-365 days')"
                ]
            }
        }
        
    def analyze_databases(self) -> List[DatabaseInfo]:
        """데이터베이스 분석"""
        db_infos = []
        
        for db_name, db_config in self.databases.items():
            if os.path.exists(db_name):
                try:
                    info = self._analyze_single_database(db_name, db_config)
                    db_infos.append(info)
                except Exception as e:
                    print(f"데이터베이스 분석 오류 ({db_name}): {e}")
        
        return db_infos
    
    def _analyze_single_database(self, db_path: str, config: Dict) -> DatabaseInfo:
        """개별 데이터베이스 분석"""
        # 파일 크기
        size_bytes = os.path.getsize(db_path)
        size_mb = size_bytes / (1024 * 1024)
        
        # 데이터베이스 연결
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 테이블 수
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        tables_count = cursor.fetchone()[0]
        
        # 총 레코드 수
        total_records = 0
        for table in config.get("tables", []):
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                total_records += count
            except sqlite3.OperationalError:
                continue  # 테이블이 존재하지 않는 경우
        
        # 인덱스 수
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='index'")
        indexes_count = cursor.fetchone()[0]
        
        # 마지막 최적화 시간 (PRAGMA 사용)
        cursor.execute("PRAGMA user_version")
        user_version = cursor.fetchone()[0]
        last_optimized = "알 수 없음" if user_version == 0 else datetime.fromtimestamp(user_version).strftime("%Y-%m-%d %H:%M")
        
        conn.close()
        
        # 성능 점수 계산
        performance_score = self._calculate_performance_score(size_mb, total_records, indexes_count)
        
        return DatabaseInfo(
            name=db_path,
            path=db_path,
            size_mb=size_mb,
            tables_count=tables_count,
            records_count=total_records,
            indexes_count=indexes_count,
            last_optimized=last_optimized,
            performance_score=performance_score
        )
    
    def _calculate_performance_score(self, size_mb: float, records: int, indexes: int) -> float:
        """성능 점수 계산 (0-100)"""
        score = 100.0
        
        # 크기 기반 감점
        if size_mb > 100:
            score -= min(30, (size_mb - 100) / 10)
        
        # 레코드당 크기 효율성
        if records > 0:
            mb_per_1k_records = (size_mb / records) * 1000
            if mb_per_1k_records > 1:  # 1MB per 1k records는 비효율적
                score -= min(20, mb_per_1k_records * 5)
        
        # 인덱스 효율성
        if records > 1000:
            expected_indexes = max(2, records // 10000)  # 10k records당 1개 인덱스 예상
            if indexes < expected_indexes:
                score -= (expected_indexes - indexes) * 5
        
        return max(0, min(100, score))
    
    def optimize_all_databases(self) -> List[OptimizationResult]:
        """모든 데이터베이스 최적화"""
        results = []
        total_dbs = len([db for db in self.databases.keys() if os.path.exists(db)])
        
        for i, (db_name, db_config) in enumerate(self.databases.items()):
            if not os.path.exists(db_name):
                continue
            
            progress = int((i / total_dbs) * 100)
            self.optimization_progress.emit(f"최적화 중: {db_name}", progress)
            
            try:
                result = self._optimize_single_database(db_name, db_config)
                if result:
                    results.append(result)
                    
                # 약간의 지연 (UI 업데이트)
                time.sleep(0.5)
                
            except Exception as e:
                print(f"데이터베이스 최적화 오류 ({db_name}): {e}")
        
        self.optimization_progress.emit("최적화 완료!", 100)
        return results
    
    def _optimize_single_database(self, db_path: str, config: Dict) -> Optional[OptimizationResult]:
        """개별 데이터베이스 최적화"""
        start_time = time.time()
        
        # 최적화 전 상태
        before_size = os.path.getsize(db_path) / (1024 * 1024)
        before_records = self._count_total_records(db_path, config.get("tables", []))
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            # 1. 오래된 데이터 정리
            cleanup_queries = config.get("cleanup_sql", [])
            for query in cleanup_queries:
                try:
                    cursor.execute(query)
                    print(f"실행: {query}")
                except Exception as e:
                    print(f"정리 쿼리 오류: {e}")
            
            # 2. 인덱스 최적화
            self._optimize_indexes(cursor, config.get("tables", []))
            
            # 3. VACUUM (데이터베이스 압축)
            cursor.execute("VACUUM")
            
            # 4. ANALYZE (쿼리 최적화를 위한 통계 업데이트)
            cursor.execute("ANALYZE")
            
            # 5. 마지막 최적화 시간 기록
            cursor.execute(f"PRAGMA user_version = {int(time.time())}")
            
            conn.commit()
            
        finally:
            conn.close()
        
        # 최적화 후 상태
        after_size = os.path.getsize(db_path) / (1024 * 1024)
        after_records = self._count_total_records(db_path, config.get("tables", []))
        
        execution_time = time.time() - start_time
        
        # 성능 개선 계산
        size_improvement = ((before_size - after_size) / before_size * 100) if before_size > 0 else 0
        
        return OptimizationResult(
            database=db_path,
            action="전체 최적화",
            before_size_mb=before_size,
            after_size_mb=after_size,
            records_before=before_records,
            records_after=after_records,
            performance_improvement=size_improvement,
            execution_time_seconds=execution_time
        )
    
    def _optimize_indexes(self, cursor, tables: List[str]):
        """인덱스 최적화"""
        for table in tables:
            try:
                # 테이블 정보 조회
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                
                # 기본적인 인덱스 생성 (timestamp, id, 자주 검색되는 컬럼)
                index_candidates = []
                for col in columns:
                    col_name = col[1].lower()
                    if any(keyword in col_name for keyword in ["timestamp", "created_at", "updated_at", "date"]):
                        index_candidates.append(col[1])
                    elif col_name in ["id", "cve_id", "pattern_id", "report_id", "behavior_id"]:
                        index_candidates.append(col[1])
                
                # 인덱스 생성
                for col in index_candidates:
                    try:
                        index_name = f"idx_{table}_{col}"
                        cursor.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({col})")
                        print(f"인덱스 생성: {index_name}")
                    except Exception as e:
                        print(f"인덱스 생성 오류 ({table}.{col}): {e}")
                        
            except Exception as e:
                print(f"테이블 최적화 오류 ({table}): {e}")
    
    def _count_total_records(self, db_path: str, tables: List[str]) -> int:
        """총 레코드 수 계산"""
        total = 0
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    total += count
                except sqlite3.OperationalError:
                    continue
        finally:
            conn.close()
        
        return total
    
    def backup_database(self, db_path: str, backup_path: str) -> bool:
        """데이터베이스 백업"""
        try:
            # SQLite의 backup API 사용
            source = sqlite3.connect(db_path)
            backup = sqlite3.connect(backup_path)
            source.backup(backup)
            source.close()
            backup.close()
            return True
        except Exception as e:
            print(f"백업 오류: {e}")
            return False

class DatabaseOptimizerTab(QWidget):
    """데이터베이스 최적화 탭"""
    
    def __init__(self):
        super().__init__()
        self.optimizer = DatabaseOptimizer()
        self.optimizer.optimization_progress.connect(self.on_optimization_progress)
        self.optimizer.optimization_complete.connect(self.on_optimization_complete)
        self.setup_ui()
        self.refresh_database_info()
        
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 제목
        title = QLabel("🗃️ 데이터베이스 최적화")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("MetaShield의 모든 데이터베이스 성능을 분석하고 최적화합니다.")
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # 제어 패널
        control_card = Card()
        control_layout = QHBoxLayout(control_card)
        
        self.refresh_btn = PrimaryButton("🔄 새로고침")
        self.refresh_btn.clicked.connect(self.refresh_database_info)
        control_layout.addWidget(self.refresh_btn)
        
        self.optimize_btn = PrimaryButton("🚀 전체 최적화")
        self.optimize_btn.clicked.connect(self.optimize_databases)
        control_layout.addWidget(self.optimize_btn)
        
        self.backup_btn = SecondaryButton("💾 백업 생성")
        self.backup_btn.clicked.connect(self.create_backup)
        control_layout.addWidget(self.backup_btn)
        
        control_layout.addStretch()
        
        # 전체 요약
        self.summary_label = QLabel("데이터베이스 정보를 불러오는 중...")
        self.summary_label.setStyleSheet("font-weight: bold; color: #1890ff;")
        control_layout.addWidget(self.summary_label)
        
        layout.addWidget(control_card)
        
        # 진행률 표시
        self.progress_card = Card()
        progress_layout = QVBoxLayout(self.progress_card)
        
        self.progress_label = QLabel("대기 중...")
        self.progress_label.setStyleSheet("font-weight: bold;")
        progress_layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #d9d9d9;
                border-radius: 8px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #1890ff;
                border-radius: 6px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        layout.addWidget(self.progress_card)
        
        # 데이터베이스 목록
        self.db_table = QTableWidget()
        self.db_table.setColumnCount(8)
        self.db_table.setHorizontalHeaderLabels([
            "데이터베이스", "크기(MB)", "테이블", "레코드", "인덱스", "마지막 최적화", "성능점수", "상태"
        ])
        
        header = self.db_table.horizontalHeader()
        header.setStretchLastSection(True)
        
        self.db_table.setAlternatingRowColors(True)
        self.db_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.db_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #e8e8e8;
                border: 1px solid #d9d9d9;
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                background-color: #fafafa;
                padding: 10px;
                font-weight: bold;
                border: none;
                border-bottom: 2px solid #e8e8e8;
            }
        """)
        
        layout.addWidget(self.db_table)
        
        # 최적화 결과
        self.results_card = Card()
        results_layout = QVBoxLayout(self.results_card)
        
        results_title = QLabel("📊 최적화 결과")
        results_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333; margin-bottom: 10px;")
        results_layout.addWidget(results_title)
        
        self.results_area = QScrollArea()
        self.results_area.setWidgetResizable(True)
        self.results_area.setMinimumHeight(200)
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
        self.show_initial_results_message()
    
    def show_initial_results_message(self):
        """초기 결과 메시지"""
        msg = QLabel("최적화를 실행하면 결과가 여기에 표시됩니다.")
        msg.setStyleSheet("color: #999; text-align: center; padding: 50px;")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_layout.addWidget(msg)
    
    def refresh_database_info(self):
        """데이터베이스 정보 새로고침"""
        self.progress_label.setText("데이터베이스 분석 중...")
        self.progress_bar.setValue(50)
        
        # 백그라운드에서 분석
        self.analysis_thread = threading.Thread(target=self.run_analysis)
        self.analysis_thread.start()
    
    def run_analysis(self):
        """백그라운드에서 분석 실행"""
        try:
            db_infos = self.optimizer.analyze_databases()
            QTimer.singleShot(0, lambda: self.display_database_info(db_infos))
        except Exception as e:
            QTimer.singleShot(0, lambda: self.show_analysis_error(str(e)))
    
    def display_database_info(self, db_infos: List[DatabaseInfo]):
        """데이터베이스 정보 표시"""
        self.progress_label.setText("분석 완료")
        self.progress_bar.setValue(100)
        
        # 테이블 업데이트
        self.db_table.setRowCount(len(db_infos))
        
        total_size = 0
        total_records = 0
        avg_performance = 0
        
        for i, db_info in enumerate(db_infos):
            self.db_table.setItem(i, 0, QTableWidgetItem(db_info.name))
            self.db_table.setItem(i, 1, QTableWidgetItem(f"{db_info.size_mb:.2f}"))
            self.db_table.setItem(i, 2, QTableWidgetItem(str(db_info.tables_count)))
            self.db_table.setItem(i, 3, QTableWidgetItem(f"{db_info.records_count:,}"))
            self.db_table.setItem(i, 4, QTableWidgetItem(str(db_info.indexes_count)))
            self.db_table.setItem(i, 5, QTableWidgetItem(db_info.last_optimized))
            
            # 성능 점수 (색상 적용)
            score_item = QTableWidgetItem(f"{db_info.performance_score:.1f}")
            if db_info.performance_score >= 80:
                score_item.setBackground(QColor("#f6ffed"))
                score_item.setForeground(QColor("#52c41a"))
            elif db_info.performance_score >= 60:
                score_item.setBackground(QColor("#fffbe6"))
                score_item.setForeground(QColor("#faad14"))
            else:
                score_item.setBackground(QColor("#fff2f0"))
                score_item.setForeground(QColor("#ff4d4f"))
            
            self.db_table.setItem(i, 6, score_item)
            
            # 상태
            status = "좋음" if db_info.performance_score >= 80 else "보통" if db_info.performance_score >= 60 else "개선 필요"
            self.db_table.setItem(i, 7, QTableWidgetItem(status))
            
            total_size += db_info.size_mb
            total_records += db_info.records_count
            avg_performance += db_info.performance_score
        
        # 요약 정보 업데이트
        avg_performance = avg_performance / len(db_infos) if db_infos else 0
        self.summary_label.setText(
            f"전체: {len(db_infos)}개 DB, {total_size:.1f}MB, {total_records:,}개 레코드, 평균 성능: {avg_performance:.1f}점"
        )
        
        # 자동 크기 조정
        self.db_table.resizeColumnsToContents()
    
    def show_analysis_error(self, error_msg: str):
        """분석 오류 표시"""
        self.progress_label.setText(f"분석 오류: {error_msg}")
        self.progress_bar.setValue(0)
    
    def optimize_databases(self):
        """데이터베이스 최적화 실행"""
        reply = QMessageBox.question(
            self, "최적화 확인",
            "데이터베이스 최적화를 시작하시겠습니까?\n"
            "최적화 중에는 해당 데이터베이스 사용이 제한됩니다.\n\n"
            "백업 생성을 권장합니다.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # 기존 결과 초기화
        self.clear_results()
        
        # 버튼 비활성화
        self.optimize_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        
        # 백그라운드에서 최적화 실행
        self.optimization_thread = threading.Thread(target=self.run_optimization)
        self.optimization_thread.start()
    
    def run_optimization(self):
        """백그라운드에서 최적화 실행"""
        try:
            results = self.optimizer.optimize_all_databases()
            self.optimizer.optimization_complete.emit({"results": results})
        except Exception as e:
            self.optimizer.optimization_progress.emit(f"최적화 오류: {str(e)}", 0)
    
    @pyqtSlot(str, int)
    def on_optimization_progress(self, message: str, progress: int):
        """최적화 진행률 업데이트"""
        self.progress_label.setText(message)
        self.progress_bar.setValue(progress)
    
    @pyqtSlot(dict)
    def on_optimization_complete(self, data: Dict):
        """최적화 완료 처리"""
        results = data["results"]
        
        # 버튼 재활성화
        self.optimize_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        
        # 결과 표시
        self.display_optimization_results(results)
        
        # 데이터베이스 정보 새로고침
        self.refresh_database_info()
        
        # 완료 메시지
        QMessageBox.information(
            self, "최적화 완료",
            f"데이터베이스 최적화가 완료되었습니다.\n"
            f"총 {len(results)}개의 데이터베이스가 최적화되었습니다."
        )
    
    def display_optimization_results(self, results: List[OptimizationResult]):
        """최적화 결과 표시"""
        self.clear_results()
        
        if not results:
            no_results = QLabel("최적화할 데이터베이스가 없습니다.")
            no_results.setStyleSheet("color: #999; text-align: center; padding: 50px;")
            no_results.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.results_layout.addWidget(no_results)
            return
        
        for result in results:
            result_card = Card()
            result_layout = QVBoxLayout(result_card)
            
            # 제목
            title = QLabel(f"📁 {result.database}")
            title.setStyleSheet("font-size: 14px; font-weight: bold; color: #333; margin-bottom: 10px;")
            result_layout.addWidget(title)
            
            # 결과 정보
            info_layout = QGridLayout()
            
            info_layout.addWidget(QLabel("작업:"), 0, 0)
            info_layout.addWidget(QLabel(result.action), 0, 1)
            
            info_layout.addWidget(QLabel("크기 변화:"), 0, 2)
            size_change = f"{result.before_size_mb:.2f}MB → {result.after_size_mb:.2f}MB"
            if result.performance_improvement > 0:
                size_change += f" (-{result.performance_improvement:.1f}%)"
            info_layout.addWidget(QLabel(size_change), 0, 3)
            
            info_layout.addWidget(QLabel("레코드:"), 1, 0)
            records_change = f"{result.records_before:,} → {result.records_after:,}"
            info_layout.addWidget(QLabel(records_change), 1, 1)
            
            info_layout.addWidget(QLabel("소요 시간:"), 1, 2)
            info_layout.addWidget(QLabel(f"{result.execution_time_seconds:.1f}초"), 1, 3)
            
            result_layout.addLayout(info_layout)
            
            # 성능 개선 표시
            if result.performance_improvement > 0:
                improvement_label = QLabel(f"✅ {result.performance_improvement:.1f}% 크기 감소")
                improvement_label.setStyleSheet("color: #52c41a; font-weight: bold; margin-top: 5px;")
                result_layout.addWidget(improvement_label)
            
            self.results_layout.addWidget(result_card)
    
    def create_backup(self):
        """백업 생성"""
        backup_dir = QFileDialog.getExistingDirectory(self, "백업 저장 위치 선택")
        if not backup_dir:
            return
        
        backup_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        success_count = 0
        
        for db_name in self.optimizer.databases.keys():
            if os.path.exists(db_name):
                backup_name = f"{os.path.splitext(db_name)[0]}_backup_{backup_time}.db"
                backup_path = os.path.join(backup_dir, backup_name)
                
                if self.optimizer.backup_database(db_name, backup_path):
                    success_count += 1
        
        QMessageBox.information(
            self, "백업 완료",
            f"{success_count}개의 데이터베이스 백업이 생성되었습니다.\n"
            f"위치: {backup_dir}"
        )
    
    def clear_results(self):
        """결과 초기화"""
        while self.results_layout.count():
            child = self.results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

if __name__ == "__main__":
    app = QApplication([])
    tab = DatabaseOptimizerTab()
    tab.show()
    app.exec()