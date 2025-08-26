# realtime_behavior_analyzer.py - 실시간 악성코드 행위 분석 시스템
"""
실시간으로 시스템 행위를 모니터링하여 악성코드 활동을 탐지하고 분석하는 시스템
"""

import os
import time
import json
import threading
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import sqlite3
import psutil
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from config import AIConfig
from advanced_ui_components import Card, PrimaryButton, SecondaryButton
from modern_ui_style import MODERN_STYLE
import openai

@dataclass
class BehaviorEvent:
    """행위 이벤트"""
    event_type: str  # "process", "file", "network", "registry"
    timestamp: str
    process_name: str
    process_pid: int
    action: str
    target: str
    details: Dict
    risk_score: float = 0.0

@dataclass
class ThreatBehavior:
    """위협 행위 패턴"""
    behavior_id: str
    behavior_type: str
    description: str
    events: List[BehaviorEvent]
    total_risk_score: float
    severity: str
    first_seen: str
    last_seen: str

class BehaviorMonitor(QObject):
    """시스템 행위 모니터"""
    
    behavior_detected = pyqtSignal(dict)
    threat_detected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.monitoring = False
        self.events_buffer = deque(maxlen=1000)
        self.suspicious_patterns = {
            "process_injection": {
                "events": ["process_create", "memory_write"],
                "threshold": 3,
                "severity": "높음"
            },
            "credential_dump": {
                "events": ["process_create", "memory_read", "file_access"],
                "processes": ["lsass.exe", "winlogon.exe"],
                "threshold": 5,
                "severity": "심각"
            },
            "persistence_mechanism": {
                "events": ["registry_write", "file_create"],
                "targets": ["run", "runonce", "startup"],
                "threshold": 2,
                "severity": "보통"
            },
            "data_exfiltration": {
                "events": ["file_read", "network_connect"],
                "size_threshold": 10485760,  # 10MB
                "severity": "높음"
            },
            "lateral_movement": {
                "events": ["network_connect", "process_create"],
                "protocols": ["smb", "rdp", "ssh"],
                "severity": "높음"
            }
        }
        self.db_path = "behavior_analysis.db"
        self.init_database()
        
    def init_database(self):
        """데이터베이스 초기화"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS behavior_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                timestamp TEXT,
                process_name TEXT,
                process_pid INTEGER,
                action TEXT,
                target TEXT,
                details TEXT,
                risk_score REAL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_behaviors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                behavior_id TEXT UNIQUE,
                behavior_type TEXT,
                description TEXT,
                events TEXT,
                total_risk_score REAL,
                severity TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def start_monitoring(self):
        """모니터링 시작"""
        if self.monitoring:
            return
            
        self.monitoring = True
        
        # 각종 모니터링 스레드 시작
        self.process_monitor_thread = threading.Thread(target=self._monitor_processes)
        self.file_monitor_thread = threading.Thread(target=self._monitor_file_system)
        self.network_monitor_thread = threading.Thread(target=self._monitor_network)
        self.analysis_thread = threading.Thread(target=self._analyze_behaviors)
        
        self.process_monitor_thread.start()
        self.file_monitor_thread.start()
        self.network_monitor_thread.start()
        self.analysis_thread.start()
    
    def stop_monitoring(self):
        """모니터링 중지"""
        self.monitoring = False
    
    def _monitor_processes(self):
        """프로세스 모니터링"""
        seen_processes = set()
        
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
                    try:
                        proc_info = proc.info
                        if proc_info['pid'] in seen_processes:
                            continue
                            
                        seen_processes.add(proc_info['pid'])
                        
                        # 새로운 프로세스 생성 이벤트
                        event = BehaviorEvent(
                            event_type="process",
                            timestamp=datetime.now().isoformat(),
                            process_name=proc_info['name'] or "unknown",
                            process_pid=proc_info['pid'],
                            action="create",
                            target=proc_info['exe'] or "unknown",
                            details={
                                "create_time": proc_info['create_time'],
                                "executable": proc_info['exe']
                            }
                        )
                        
                        # 위험도 평가
                        event.risk_score = self._calculate_process_risk(event)
                        
                        self.events_buffer.append(event)
                        self._save_event(event)
                        
                        # 실시간 알림
                        if event.risk_score > 7.0:
                            self.behavior_detected.emit(asdict(event))
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                time.sleep(1)
                
            except Exception as e:
                print(f"프로세스 모니터링 오류: {e}")
                time.sleep(5)
    
    def _monitor_file_system(self):
        """파일 시스템 모니터링 (Windows용 간단 구현)"""
        important_dirs = [
            "C:\\Windows\\System32",
            "C:\\Users",
            "C:\\Program Files",
            "C:\\ProgramData"
        ]
        
        file_timestamps = {}
        
        while self.monitoring:
            try:
                for directory in important_dirs:
                    if not os.path.exists(directory):
                        continue
                        
                    try:
                        for root, dirs, files in os.walk(directory):
                            # 깊이 제한 (성능)
                            if root.count(os.sep) - directory.count(os.sep) > 2:
                                dirs.clear()
                                continue
                                
                            for file in files[:10]:  # 파일 수 제한
                                file_path = os.path.join(root, file)
                                try:
                                    stat = os.stat(file_path)
                                    mtime = stat.st_mtime
                                    
                                    if file_path not in file_timestamps:
                                        file_timestamps[file_path] = mtime
                                        continue
                                    
                                    if mtime > file_timestamps[file_path]:
                                        # 파일 변경 감지
                                        event = BehaviorEvent(
                                            event_type="file",
                                            timestamp=datetime.now().isoformat(),
                                            process_name="system",
                                            process_pid=0,
                                            action="modify",
                                            target=file_path,
                                            details={
                                                "size": stat.st_size,
                                                "mtime": mtime
                                            }
                                        )
                                        
                                        event.risk_score = self._calculate_file_risk(event)
                                        
                                        if event.risk_score > 5.0:
                                            self.events_buffer.append(event)
                                            self._save_event(event)
                                        
                                        file_timestamps[file_path] = mtime
                                        
                                except (OSError, PermissionError):
                                    continue
                                    
                    except (OSError, PermissionError):
                        continue
                
                time.sleep(5)  # 파일 시스템은 더 긴 간격
                
            except Exception as e:
                print(f"파일 시스템 모니터링 오류: {e}")
                time.sleep(10)
    
    def _monitor_network(self):
        """네트워크 모니터링"""
        seen_connections = set()
        
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    try:
                        conn_id = f"{conn.laddr}_{conn.raddr}_{conn.pid}"
                        if conn_id in seen_connections:
                            continue
                            
                        seen_connections.add(conn_id)
                        
                        # 새로운 네트워크 연결 이벤트
                        if conn.raddr and conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                process_name = proc.name()
                            except:
                                process_name = "unknown"
                            
                            event = BehaviorEvent(
                                event_type="network",
                                timestamp=datetime.now().isoformat(),
                                process_name=process_name,
                                process_pid=conn.pid,
                                action="connect",
                                target=f"{conn.raddr.ip}:{conn.raddr.port}",
                                details={
                                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                                    "status": conn.status
                                }
                            )
                            
                            event.risk_score = self._calculate_network_risk(event)
                            
                            if event.risk_score > 5.0:
                                self.events_buffer.append(event)
                                self._save_event(event)
                                
                    except Exception:
                        continue
                
                time.sleep(2)
                
            except Exception as e:
                print(f"네트워크 모니터링 오류: {e}")
                time.sleep(5)
    
    def _analyze_behaviors(self):
        """행위 패턴 분석"""
        while self.monitoring:
            try:
                if len(self.events_buffer) < 5:
                    time.sleep(5)
                    continue
                
                # 최근 이벤트들을 분석
                recent_events = list(self.events_buffer)[-50:]
                
                # 패턴 매칭
                for pattern_name, pattern_config in self.suspicious_patterns.items():
                    matches = self._match_pattern(recent_events, pattern_config)
                    
                    if matches:
                        threat = ThreatBehavior(
                            behavior_id=f"{pattern_name}_{int(time.time())}",
                            behavior_type=pattern_name,
                            description=f"{pattern_name} 패턴 탐지",
                            events=matches,
                            total_risk_score=sum(e.risk_score for e in matches),
                            severity=pattern_config["severity"],
                            first_seen=matches[0].timestamp,
                            last_seen=matches[-1].timestamp
                        )
                        
                        self._save_threat_behavior(threat)
                        self.threat_detected.emit(asdict(threat))
                
                time.sleep(10)
                
            except Exception as e:
                print(f"행위 분석 오류: {e}")
                time.sleep(10)
    
    def _match_pattern(self, events: List[BehaviorEvent], pattern_config: Dict) -> List[BehaviorEvent]:
        """패턴 매칭"""
        matched_events = []
        
        for event in events:
            # 기본 이벤트 타입 매칭
            if event.action in pattern_config.get("events", []):
                matched_events.append(event)
                continue
            
            # 프로세스 이름 매칭
            if "processes" in pattern_config:
                if any(proc in event.process_name.lower() for proc in pattern_config["processes"]):
                    matched_events.append(event)
                    continue
            
            # 타겟 매칭
            if "targets" in pattern_config:
                if any(target in event.target.lower() for target in pattern_config["targets"]):
                    matched_events.append(event)
                    continue
        
        # 임계값 확인
        threshold = pattern_config.get("threshold", 1)
        if len(matched_events) >= threshold:
            return matched_events
        
        return []
    
    def _calculate_process_risk(self, event: BehaviorEvent) -> float:
        """프로세스 위험도 계산"""
        risk_score = 0.0
        process_name = event.process_name.lower()
        target = event.target.lower()
        
        # 의심스러운 프로세스명
        suspicious_processes = [
            "powershell", "cmd", "wscript", "cscript", "regsvr32",
            "rundll32", "mshta", "certutil", "bitsadmin"
        ]
        
        for sus_proc in suspicious_processes:
            if sus_proc in process_name:
                risk_score += 3.0
                break
        
        # 의심스러운 경로
        suspicious_paths = [
            "\\temp\\", "\\appdata\\", "\\users\\public\\",
            "\\downloads\\", "\\desktop\\", "\\documents\\"
        ]
        
        for sus_path in suspicious_paths:
            if sus_path in target:
                risk_score += 2.0
                break
        
        # 실행 파일 확장자
        if target.endswith((".exe", ".scr", ".com", ".bat", ".ps1")):
            risk_score += 1.0
        
        return min(risk_score, 10.0)
    
    def _calculate_file_risk(self, event: BehaviorEvent) -> float:
        """파일 위험도 계산"""
        risk_score = 0.0
        target = event.target.lower()
        
        # 중요 시스템 디렉토리
        critical_dirs = [
            "\\system32\\", "\\syswow64\\", "\\windows\\",
            "\\program files\\", "\\startup\\"
        ]
        
        for crit_dir in critical_dirs:
            if crit_dir in target:
                risk_score += 4.0
                break
        
        # 의심스러운 확장자
        suspicious_extensions = [
            ".exe", ".dll", ".scr", ".com", ".bat", ".ps1", ".vbs", ".js"
        ]
        
        for ext in suspicious_extensions:
            if target.endswith(ext):
                risk_score += 2.0
                break
        
        return min(risk_score, 10.0)
    
    def _calculate_network_risk(self, event: BehaviorEvent) -> float:
        """네트워크 위험도 계산"""
        risk_score = 0.0
        target = event.target
        process_name = event.process_name.lower()
        
        # 의심스러운 포트
        suspicious_ports = [
            "4444", "5555", "6666", "7777", "8888", "9999",  # 백도어 포트
            "1337", "31337",  # 해커 포트
            "6667", "6668", "6669"  # IRC 포트
        ]
        
        for port in suspicious_ports:
            if port in target:
                risk_score += 5.0
                break
        
        # 의심스러운 프로세스의 네트워크 활동
        suspicious_processes = [
            "powershell", "cmd", "wscript", "cscript", "rundll32"
        ]
        
        for sus_proc in suspicious_processes:
            if sus_proc in process_name:
                risk_score += 3.0
                break
        
        # 비표준 포트 연결
        try:
            port = int(target.split(':')[-1])
            if port > 10000:
                risk_score += 1.0
        except:
            pass
        
        return min(risk_score, 10.0)
    
    def _save_event(self, event: BehaviorEvent):
        """이벤트 저장"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO behavior_events 
                (event_type, timestamp, process_name, process_pid, action, target, details, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_type, event.timestamp, event.process_name,
                event.process_pid, event.action, event.target,
                json.dumps(event.details), event.risk_score
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"이벤트 저장 오류: {e}")
    
    def _save_threat_behavior(self, threat: ThreatBehavior):
        """위협 행위 저장"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO threat_behaviors
                (behavior_id, behavior_type, description, events, total_risk_score, severity, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat.behavior_id, threat.behavior_type, threat.description,
                json.dumps([asdict(e) for e in threat.events]),
                threat.total_risk_score, threat.severity,
                threat.first_seen, threat.last_seen
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"위협 행위 저장 오류: {e}")

class RealtimeBehaviorTab(QWidget):
    """실시간 행위 분석 탭"""
    
    def __init__(self):
        super().__init__()
        self.monitor = BehaviorMonitor()
        self.monitor.behavior_detected.connect(self.on_behavior_detected)
        self.monitor.threat_detected.connect(self.on_threat_detected)
        self.setup_ui()
        
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 제목
        title = QLabel("🔍 실시간 악성코드 행위 분석")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("실시간으로 시스템 행위를 모니터링하여 악성코드 활동을 탐지하고 분석합니다.")
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
        
        layout.addWidget(control_card)
        
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
        
        # 실시간 이벤트 탭
        self.events_tab = self.create_events_tab()
        tab_widget.addTab(self.events_tab, "🔍 실시간 이벤트")
        
        # 위협 탐지 탭
        self.threats_tab = self.create_threats_tab()
        tab_widget.addTab(self.threats_tab, "⚠️ 위협 탐지")
        
        # 통계 탭
        self.stats_tab = self.create_stats_tab()
        tab_widget.addTab(self.stats_tab, "📊 통계")
        
        layout.addWidget(tab_widget)
    
    def create_events_tab(self):
        """실시간 이벤트 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 이벤트 테이블
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(7)
        self.events_table.setHorizontalHeaderLabels([
            "시간", "타입", "프로세스", "동작", "대상", "위험도", "상세정보"
        ])
        self.events_table.horizontalHeader().setStretchLastSection(True)
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.events_table)
        
        return widget
    
    def create_threats_tab(self):
        """위협 탐지 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 위협 목록
        self.threats_list = QListWidget()
        self.threats_list.setStyleSheet("""
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
        
        layout.addWidget(self.threats_list)
        
        return widget
    
    def create_stats_tab(self):
        """통계 탭"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 통계 정보
        stats_layout = QGridLayout()
        
        self.total_events_label = QLabel("총 이벤트: 0")
        self.total_events_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        stats_layout.addWidget(self.total_events_label, 0, 0)
        
        self.high_risk_events_label = QLabel("고위험 이벤트: 0")
        self.high_risk_events_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #ff4d4f;")
        stats_layout.addWidget(self.high_risk_events_label, 0, 1)
        
        self.threats_detected_label = QLabel("탐지된 위협: 0")
        self.threats_detected_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #fa8c16;")
        stats_layout.addWidget(self.threats_detected_label, 1, 0)
        
        self.monitoring_time_label = QLabel("모니터링 시간: 00:00:00")
        self.monitoring_time_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #52c41a;")
        stats_layout.addWidget(self.monitoring_time_label, 1, 1)
        
        layout.addLayout(stats_layout)
        layout.addStretch()
        
        return widget
    
    def start_monitoring(self):
        """모니터링 시작"""
        self.monitor.start_monitoring()
        self.status_label.setText("🟢 모니터링 실행 중")
        self.status_label.setStyleSheet("font-weight: bold; color: #52c41a;")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # 통계 업데이트 타이머
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(1000)  # 1초마다
        self.monitoring_start_time = time.time()
    
    def stop_monitoring(self):
        """모니터링 중지"""
        self.monitor.stop_monitoring()
        self.status_label.setText("🔴 모니터링 중지됨")
        self.status_label.setStyleSheet("font-weight: bold; color: #ff4d4f;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if hasattr(self, 'stats_timer'):
            self.stats_timer.stop()
    
    @pyqtSlot(dict)
    def on_behavior_detected(self, event_data):
        """행위 감지 시 호출"""
        # 테이블에 이벤트 추가
        row = self.events_table.rowCount()
        self.events_table.insertRow(row)
        
        timestamp = event_data.get('timestamp', '').split('T')
        time_str = timestamp[1][:8] if len(timestamp) > 1 else ''
        
        self.events_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.events_table.setItem(row, 1, QTableWidgetItem(event_data.get('event_type', '')))
        self.events_table.setItem(row, 2, QTableWidgetItem(event_data.get('process_name', '')))
        self.events_table.setItem(row, 3, QTableWidgetItem(event_data.get('action', '')))
        self.events_table.setItem(row, 4, QTableWidgetItem(event_data.get('target', '')))
        
        risk_score = event_data.get('risk_score', 0)
        risk_item = QTableWidgetItem(f"{risk_score:.1f}")
        
        # 위험도에 따른 색상
        if risk_score >= 8:
            risk_item.setBackground(QColor("#ff4d4f"))
            risk_item.setForeground(QColor("white"))
        elif risk_score >= 6:
            risk_item.setBackground(QColor("#fa8c16"))
            risk_item.setForeground(QColor("white"))
        elif risk_score >= 4:
            risk_item.setBackground(QColor("#faad14"))
        
        self.events_table.setItem(row, 5, risk_item)
        self.events_table.setItem(row, 6, QTableWidgetItem(str(event_data.get('details', ''))))
        
        # 자동 스크롤
        self.events_table.scrollToBottom()
    
    @pyqtSlot(dict)
    def on_threat_detected(self, threat_data):
        """위협 탐지 시 호출"""
        # 위협 목록에 추가
        threat_item = QListWidgetItem()
        
        behavior_type = threat_data.get('behavior_type', '알 수 없는 위협')
        severity = threat_data.get('severity', '보통')
        risk_score = threat_data.get('total_risk_score', 0)
        first_seen = threat_data.get('first_seen', '')
        
        time_str = first_seen.split('T')[1][:8] if 'T' in first_seen else first_seen
        
        threat_text = f"[{severity}] {behavior_type} (위험도: {risk_score:.1f}) - {time_str}"
        threat_item.setText(threat_text)
        
        # 심각도별 색상
        if severity == "심각":
            threat_item.setBackground(QColor("#ff4d4f"))
            threat_item.setForeground(QColor("white"))
        elif severity == "높음":
            threat_item.setBackground(QColor("#fa8c16"))
            threat_item.setForeground(QColor("white"))
        elif severity == "보통":
            threat_item.setBackground(QColor("#faad14"))
        
        self.threats_list.insertItem(0, threat_item)  # 맨 위에 추가
        
        # 알림
        QMessageBox.warning(self, "위협 탐지!", f"{behavior_type} 패턴이 탐지되었습니다!\n위험도: {risk_score:.1f}")
    
    def update_stats(self):
        """통계 업데이트"""
        if not hasattr(self, 'monitoring_start_time'):
            return
        
        # 모니터링 시간
        elapsed = time.time() - self.monitoring_start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        self.monitoring_time_label.setText(f"모니터링 시간: {hours:02d}:{minutes:02d}:{seconds:02d}")
        
        # 이벤트 통계
        total_events = self.events_table.rowCount()
        self.total_events_label.setText(f"총 이벤트: {total_events}")
        
        # 고위험 이벤트 카운트
        high_risk_count = 0
        for row in range(total_events):
            risk_item = self.events_table.item(row, 5)
            if risk_item and float(risk_item.text()) >= 7.0:
                high_risk_count += 1
        
        self.high_risk_events_label.setText(f"고위험 이벤트: {high_risk_count}")
        
        # 탐지된 위협
        threats_count = self.threats_list.count()
        self.threats_detected_label.setText(f"탐지된 위협: {threats_count}")

if __name__ == "__main__":
    app = QApplication([])
    tab = RealtimeBehaviorTab()
    tab.show()
    app.exec()