# ai_report_generator.py - AI 기반 자동 보안 리포트 생성 시스템
"""
다양한 보안 데이터를 종합하여 AI가 자동으로 전문적인 보안 리포트를 생성하는 시스템
"""

import os
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
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
class ReportSection:
    """리포트 섹션"""
    title: str
    content: str
    priority: int  # 1(높음) ~ 5(낮음)
    section_type: str  # "summary", "analysis", "recommendations", "technical", "appendix"
    charts: List[Dict] = None
    tables: List[Dict] = None

@dataclass
class SecurityReport:
    """보안 리포트"""
    report_id: str
    title: str
    report_type: str  # "daily", "weekly", "incident", "vulnerability", "threat_intel"
    created_at: str
    period_start: str
    period_end: str
    sections: List[ReportSection]
    executive_summary: str
    risk_level: str
    total_pages: int
    generated_by: str = "AI"

class ReportDataCollector:
    """리포트 데이터 수집기"""
    
    def __init__(self):
        self.data_sources = {
            "cve_data": self._collect_cve_data,
            "threat_intel": self._collect_threat_intel,
            "malware_analysis": self._collect_malware_data,
            "network_events": self._collect_network_events,
            "user_activity": self._collect_user_activity,
            "system_events": self._collect_system_events
        }
    
    def collect_all_data(self, start_date: str, end_date: str) -> Dict:
        """모든 데이터 수집"""
        collected_data = {
            "collection_time": datetime.now().isoformat(),
            "period_start": start_date,
            "period_end": end_date
        }
        
        for source_name, collector_func in self.data_sources.items():
            try:
                data = collector_func(start_date, end_date)
                collected_data[source_name] = data
            except Exception as e:
                print(f"데이터 수집 오류 ({source_name}): {e}")
                collected_data[source_name] = {"error": str(e), "data": []}
        
        return collected_data
    
    def _collect_cve_data(self, start_date: str, end_date: str) -> Dict:
        """CVE 데이터 수집"""
        try:
            conn = sqlite3.connect("cve_cache_3_1.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT cve_id, data FROM cve_cache 
                WHERE timestamp BETWEEN ? AND ?
            """, (start_date, end_date))
            
            results = cursor.fetchall()
            conn.close()
            
            cve_data = []
            for cve_id, data in results:
                try:
                    cve_info = json.loads(data)
                    cve_data.append({
                        "cve_id": cve_id,
                        "cvss_score": cve_info.get("baseScore", 0),
                        "severity": cve_info.get("baseSeverity", "UNKNOWN"),
                        "description": cve_info.get("description", "")[:200]
                    })
                except:
                    continue
            
            return {
                "total_count": len(cve_data),
                "by_severity": self._group_by_severity(cve_data),
                "high_risk_cves": [c for c in cve_data if c["cvss_score"] >= 7.0],
                "data": cve_data
            }
        except:
            return {"total_count": 0, "by_severity": {}, "high_risk_cves": [], "data": []}
    
    def _collect_threat_intel(self, start_date: str, end_date: str) -> Dict:
        """위협 인텔리전스 데이터 수집"""
        return {
            "indicators_count": 0,
            "threat_families": [],
            "geographical_distribution": {},
            "trending_threats": [],
            "data": []
        }
    
    def _collect_malware_data(self, start_date: str, end_date: str) -> Dict:
        """악성코드 분석 데이터 수집"""
        return {
            "total_samples": 0,
            "detected_families": [],
            "risk_distribution": {},
            "behavior_patterns": [],
            "data": []
        }
    
    def _collect_network_events(self, start_date: str, end_date: str) -> Dict:
        """네트워크 이벤트 수집"""
        try:
            conn = sqlite3.connect("behavior_analysis.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM behavior_events 
                WHERE event_type = 'network' AND timestamp BETWEEN ? AND ?
            """, (start_date, end_date))
            
            results = cursor.fetchall()
            conn.close()
            
            return {
                "total_events": len(results),
                "high_risk_events": len([r for r in results if r[7] > 7.0]),  # risk_score
                "event_types": {},
                "data": results
            }
        except:
            return {"total_events": 0, "high_risk_events": 0, "event_types": {}, "data": []}
    
    def _collect_user_activity(self, start_date: str, end_date: str) -> Dict:
        """사용자 활동 데이터 수집"""
        return {
            "total_activities": 0,
            "suspicious_activities": 0,
            "top_users": [],
            "unusual_patterns": [],
            "data": []
        }
    
    def _collect_system_events(self, start_date: str, end_date: str) -> Dict:
        """시스템 이벤트 수집"""
        try:
            conn = sqlite3.connect("behavior_analysis.db")
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM behavior_events 
                WHERE timestamp BETWEEN ? AND ?
            """, (start_date, end_date))
            
            results = cursor.fetchall()
            conn.close()
            
            return {
                "total_events": len(results),
                "critical_events": len([r for r in results if r[7] > 8.0]),
                "event_distribution": self._analyze_event_distribution(results),
                "data": results
            }
        except:
            return {"total_events": 0, "critical_events": 0, "event_distribution": {}, "data": []}
    
    def _group_by_severity(self, cve_data: List[Dict]) -> Dict:
        """심각도별 그룹화"""
        groups = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for cve in cve_data:
            severity = cve.get("severity", "UNKNOWN").upper()
            if severity in groups:
                groups[severity] += 1
        return groups
    
    def _analyze_event_distribution(self, events: List) -> Dict:
        """이벤트 분포 분석"""
        distribution = {}
        for event in events:
            event_type = event[1]  # event_type column
            distribution[event_type] = distribution.get(event_type, 0) + 1
        return distribution

class AIReportGenerator(QObject):
    """AI 기반 리포트 생성기"""
    
    report_generated = pyqtSignal(dict)
    progress_updated = pyqtSignal(str, int)
    
    def __init__(self):
        super().__init__()
        self.ai_config = AIConfig()
        self.data_collector = ReportDataCollector()
        self.reports_db = "security_reports.db"
        self.init_database()
        
        # 리포트 템플릿
        self.report_templates = {
            "daily": {
                "sections": [
                    "executive_summary", "threat_landscape", "security_events", 
                    "vulnerability_updates", "recommendations"
                ],
                "ai_prompts": {
                    "executive_summary": self._get_executive_summary_prompt,
                    "threat_landscape": self._get_threat_landscape_prompt,
                    "security_events": self._get_security_events_prompt,
                    "vulnerability_updates": self._get_vulnerability_updates_prompt,
                    "recommendations": self._get_recommendations_prompt
                }
            },
            "weekly": {
                "sections": [
                    "executive_summary", "weekly_trends", "threat_analysis",
                    "incident_review", "security_metrics", "strategic_recommendations"
                ],
                "ai_prompts": {
                    "executive_summary": self._get_weekly_summary_prompt,
                    "weekly_trends": self._get_weekly_trends_prompt,
                    "threat_analysis": self._get_threat_analysis_prompt,
                    "incident_review": self._get_incident_review_prompt,
                    "security_metrics": self._get_security_metrics_prompt,
                    "strategic_recommendations": self._get_strategic_recommendations_prompt
                }
            },
            "incident": {
                "sections": [
                    "incident_summary", "timeline", "impact_analysis",
                    "root_cause", "response_actions", "lessons_learned"
                ],
                "ai_prompts": {
                    "incident_summary": self._get_incident_summary_prompt,
                    "timeline": self._get_timeline_prompt,
                    "impact_analysis": self._get_impact_analysis_prompt,
                    "root_cause": self._get_root_cause_prompt,
                    "response_actions": self._get_response_actions_prompt,
                    "lessons_learned": self._get_lessons_learned_prompt
                }
            }
        }
    
    def init_database(self):
        """데이터베이스 초기화"""
        conn = sqlite3.connect(self.reports_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE,
                title TEXT,
                report_type TEXT,
                created_at TEXT,
                period_start TEXT,
                period_end TEXT,
                executive_summary TEXT,
                risk_level TEXT,
                sections TEXT,
                generated_by TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def generate_report(self, report_type: str, start_date: str, end_date: str, 
                       custom_title: str = None) -> SecurityReport:
        """리포트 생성"""
        if not self.ai_config.validate_config()[0]:
            raise Exception("AI 설정이 올바르지 않습니다.")
        
        report_id = f"{report_type}_{int(time.time())}"
        title = custom_title or f"{report_type.title()} Security Report"
        
        self.progress_updated.emit("데이터 수집 중...", 10)
        
        # 데이터 수집
        collected_data = self.data_collector.collect_all_data(start_date, end_date)
        
        self.progress_updated.emit("AI 분석 시작...", 30)
        
        # AI로 섹션별 분석
        sections = []
        template = self.report_templates.get(report_type, self.report_templates["daily"])
        
        total_sections = len(template["sections"])
        for i, section_name in enumerate(template["sections"]):
            progress = 30 + (50 * (i + 1) // total_sections)
            self.progress_updated.emit(f"{section_name} 분석 중...", progress)
            
            try:
                prompt_generator = template["ai_prompts"].get(section_name)
                if prompt_generator:
                    section_content = self._generate_section_with_ai(
                        section_name, prompt_generator(collected_data), collected_data
                    )
                else:
                    section_content = f"{section_name} 내용이 생성되지 않았습니다."
                
                sections.append(ReportSection(
                    title=section_name.replace('_', ' ').title(),
                    content=section_content,
                    priority=i + 1,
                    section_type=section_name
                ))
            except Exception as e:
                print(f"섹션 생성 오류 ({section_name}): {e}")
                sections.append(ReportSection(
                    title=section_name.replace('_', ' ').title(),
                    content=f"섹션 생성 중 오류가 발생했습니다: {str(e)}",
                    priority=i + 1,
                    section_type=section_name
                ))
        
        self.progress_updated.emit("리포트 완성 중...", 90)
        
        # 전체 요약 생성
        executive_summary = self._generate_executive_summary(collected_data, sections)
        risk_level = self._calculate_overall_risk(collected_data)
        
        # 리포트 객체 생성
        report = SecurityReport(
            report_id=report_id,
            title=title,
            report_type=report_type,
            created_at=datetime.now().isoformat(),
            period_start=start_date,
            period_end=end_date,
            sections=sections,
            executive_summary=executive_summary,
            risk_level=risk_level,
            total_pages=len(sections) + 2,
            generated_by="MetaShield AI"
        )
        
        # 데이터베이스에 저장
        self._save_report(report)
        
        self.progress_updated.emit("완료!", 100)
        
        return report
    
    def _generate_section_with_ai(self, section_name: str, prompt: str, data: Dict) -> str:
        """AI를 사용하여 섹션 생성"""
        try:
            client = openai.AzureOpenAI(
                azure_endpoint=self.ai_config.endpoint,
                api_key=self.ai_config.api_key,
                api_version=self.ai_config.api_version
            )
            
            response = client.chat.completions.create(
                model=self.ai_config.deployment_name,
                messages=[
                    {"role": "system", "content": "당신은 숙련된 보안 분석가이며 전문적인 보안 리포트를 작성합니다."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"AI 분석 중 오류 발생: {str(e)}"
    
    def _generate_executive_summary(self, data: Dict, sections: List[ReportSection]) -> str:
        """전체 요약 생성"""
        try:
            sections_content = "\n".join([f"- {s.title}: {s.content[:100]}..." for s in sections])
            
            prompt = f"""
다음 보안 분석 결과를 바탕으로 경영진용 요약 리포트를 작성해주세요:

분석 데이터:
{json.dumps(data, ensure_ascii=False, indent=2)[:2000]}

섹션 요약:
{sections_content}

다음 형식으로 작성해주세요:
1. 핵심 보안 현황 (3줄 이내)
2. 주요 위험 요소 (3개 항목)
3. 즉시 조치 사항 (2개 항목)
4. 전반적 보안 수준 평가

경영진이 이해하기 쉽도록 기술적 용어는 최소화하고 비즈니스 임팩트 중심으로 작성해주세요.
"""
            
            return self._generate_section_with_ai("executive_summary", prompt, data)
            
        except Exception as e:
            return f"요약 생성 중 오류 발생: {str(e)}"
    
    def _calculate_overall_risk(self, data: Dict) -> str:
        """전체 위험도 계산"""
        risk_score = 0
        
        # CVE 위험도
        cve_data = data.get("cve_data", {})
        high_risk_cves = len(cve_data.get("high_risk_cves", []))
        risk_score += min(high_risk_cves * 0.5, 3.0)
        
        # 시스템 이벤트 위험도
        system_events = data.get("system_events", {})
        critical_events = system_events.get("critical_events", 0)
        risk_score += min(critical_events * 0.3, 2.0)
        
        # 네트워크 이벤트 위험도
        network_events = data.get("network_events", {})
        high_risk_network = network_events.get("high_risk_events", 0)
        risk_score += min(high_risk_network * 0.4, 2.5)
        
        # 위험도 분류
        if risk_score >= 6:
            return "심각"
        elif risk_score >= 4:
            return "높음"
        elif risk_score >= 2:
            return "보통"
        else:
            return "낮음"
    
    def _save_report(self, report: SecurityReport):
        """리포트 저장"""
        conn = sqlite3.connect(self.reports_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO security_reports
            (report_id, title, report_type, created_at, period_start, period_end, 
             executive_summary, risk_level, sections, generated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.report_id, report.title, report.report_type, report.created_at,
            report.period_start, report.period_end, report.executive_summary,
            report.risk_level, json.dumps([asdict(s) for s in report.sections]),
            report.generated_by
        ))
        
        conn.commit()
        conn.close()
    
    # 섹션별 프롬프트 생성 메서드들
    def _get_executive_summary_prompt(self, data: Dict) -> str:
        return f"""
다음 보안 데이터를 바탕으로 일일 보안 요약을 작성해주세요:

데이터: {json.dumps(data, ensure_ascii=False, indent=2)[:1500]}

경영진용 요약으로 작성하되, 다음 항목을 포함해주세요:
- 오늘의 보안 상황 개요
- 주요 위협 및 사건
- 즉시 조치 필요 사항
- 전반적 보안 상태 평가
"""
    
    def _get_threat_landscape_prompt(self, data: Dict) -> str:
        return f"""
다음 데이터를 바탕으로 현재 위협 환경을 분석해주세요:

데이터: {json.dumps(data, ensure_ascii=False, indent=2)[:1500]}

다음 내용을 포함해주세요:
- 새로운 위협 트렌드
- 조직에 영향을 줄 수 있는 위협
- 위협 행위자 활동 현황
- 권고 대응 방안
"""
    
    def _get_security_events_prompt(self, data: Dict) -> str:
        return f"""
다음 보안 이벤트 데이터를 분석해주세요:

데이터: {json.dumps(data, ensure_ascii=False, indent=2)[:1500]}

분석 내용:
- 이벤트 발생 현황
- 패턴 및 이상 징후
- 심각도별 분류
- 대응 현황 및 권고사항
"""
    
    def _get_vulnerability_updates_prompt(self, data: Dict) -> str:
        cve_data = data.get("cve_data", {})
        return f"""
다음 취약점 정보를 분석해주세요:

CVE 데이터: {json.dumps(cve_data, ensure_ascii=False, indent=2)}

분석 내용:
- 신규 취약점 현황
- 심각도별 분류
- 조직 영향도 평가
- 패치 우선순위 권고
"""
    
    def _get_recommendations_prompt(self, data: Dict) -> str:
        return f"""
다음 종합 보안 데이터를 바탕으로 보안 개선 권고사항을 작성해주세요:

데이터: {json.dumps(data, ensure_ascii=False, indent=2)[:1500]}

권고사항:
- 즉시 조치 사항
- 단기 개선 방안
- 중장기 보안 전략
- 정책 및 프로세스 개선
"""
    
    # 주간 리포트 프롬프트들
    def _get_weekly_summary_prompt(self, data: Dict) -> str:
        return "주간 보안 요약을 작성해주세요."
    
    def _get_weekly_trends_prompt(self, data: Dict) -> str:
        return "주간 보안 트렌드를 분석해주세요."
    
    def _get_threat_analysis_prompt(self, data: Dict) -> str:
        return "주간 위협 분석을 수행해주세요."
    
    def _get_incident_review_prompt(self, data: Dict) -> str:
        return "주간 보안 사고를 검토해주세요."
    
    def _get_security_metrics_prompt(self, data: Dict) -> str:
        return "주간 보안 지표를 분석해주세요."
    
    def _get_strategic_recommendations_prompt(self, data: Dict) -> str:
        return "전략적 보안 권고사항을 제시해주세요."
    
    # 사고 리포트 프롬프트들
    def _get_incident_summary_prompt(self, data: Dict) -> str:
        return "보안 사고 요약을 작성해주세요."
    
    def _get_timeline_prompt(self, data: Dict) -> str:
        return "사고 타임라인을 구성해주세요."
    
    def _get_impact_analysis_prompt(self, data: Dict) -> str:
        return "사고 영향도를 분석해주세요."
    
    def _get_root_cause_prompt(self, data: Dict) -> str:
        return "근본 원인을 분석해주세요."
    
    def _get_response_actions_prompt(self, data: Dict) -> str:
        return "대응 조치를 정리해주세요."
    
    def _get_lessons_learned_prompt(self, data: Dict) -> str:
        return "교훈 및 개선사항을 도출해주세요."

class AIReportGeneratorTab(QWidget):
    """AI 리포트 생성 탭"""
    
    def __init__(self):
        super().__init__()
        self.report_generator = AIReportGenerator()
        self.report_generator.report_generated.connect(self.on_report_generated)
        self.report_generator.progress_updated.connect(self.on_progress_updated)
        self.setup_ui()
        
    def setup_ui(self):
        """UI 설정"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 제목
        title = QLabel("📊 AI 자동 보안 리포트 생성")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # 설명
        desc = QLabel("AI가 수집된 보안 데이터를 종합 분석하여 전문적인 보안 리포트를 자동 생성합니다.")
        desc.setStyleSheet("color: #666; margin-bottom: 20px;")
        layout.addWidget(desc)
        
        # 설정 카드
        config_card = Card()
        config_layout = QVBoxLayout(config_card)
        
        # 리포트 타입 선택
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("📋 리포트 타입:"))
        
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems(["daily", "weekly", "incident"])
        self.report_type_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 2px solid #d9d9d9;
                border-radius: 6px;
                min-width: 150px;
            }
            QComboBox:focus {
                border-color: #1890ff;
            }
        """)
        type_layout.addWidget(self.report_type_combo)
        type_layout.addStretch()
        config_layout.addLayout(type_layout)
        
        # 기간 설정
        period_layout = QHBoxLayout()
        period_layout.addWidget(QLabel("📅 분석 기간:"))
        
        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addDays(-7))
        self.start_date.setStyleSheet("padding: 8px; border: 2px solid #d9d9d9; border-radius: 6px;")
        period_layout.addWidget(self.start_date)
        
        period_layout.addWidget(QLabel("~"))
        
        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setStyleSheet("padding: 8px; border: 2px solid #d9d9d9; border-radius: 6px;")
        period_layout.addWidget(self.end_date)
        
        period_layout.addStretch()
        config_layout.addLayout(period_layout)
        
        # 제목 입력
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("📝 리포트 제목:"))
        
        self.report_title_input = QLineEdit()
        self.report_title_input.setPlaceholderText("리포트 제목을 입력하세요 (비워두면 자동 생성)")
        self.report_title_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #d9d9d9;
                border-radius: 6px;
                min-width: 300px;
            }
            QLineEdit:focus {
                border-color: #1890ff;
            }
        """)
        title_layout.addWidget(self.report_title_input)
        config_layout.addLayout(title_layout)
        
        # 생성 버튼
        button_layout = QHBoxLayout()
        
        self.generate_btn = PrimaryButton("🚀 리포트 생성")
        self.generate_btn.clicked.connect(self.generate_report)
        button_layout.addWidget(self.generate_btn)
        
        self.export_btn = SecondaryButton("📤 내보내기")
        self.export_btn.clicked.connect(self.export_report)
        self.export_btn.setEnabled(False)
        button_layout.addWidget(self.export_btn)
        
        button_layout.addStretch()
        config_layout.addLayout(button_layout)
        
        layout.addWidget(config_card)
        
        # 진행률 표시
        self.progress_card = Card()
        progress_layout = QVBoxLayout(self.progress_card)
        
        self.progress_label = QLabel("대기 중...")
        self.progress_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
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
        
        # 결과 표시 영역
        self.result_card = Card()
        result_layout = QVBoxLayout(self.result_card)
        
        result_label = QLabel("📄 생성된 리포트:")
        result_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        result_layout.addWidget(result_label)
        
        self.result_area = QScrollArea()
        self.result_area.setWidgetResizable(True)
        self.result_area.setMinimumHeight(400)
        self.result_area.setStyleSheet("""
            QScrollArea {
                border: 1px solid #d9d9d9;
                border-radius: 8px;
                background-color: white;
            }
        """)
        
        self.result_widget = QWidget()
        self.result_layout = QVBoxLayout(self.result_widget)
        self.result_area.setWidget(self.result_widget)
        
        result_layout.addWidget(self.result_area)
        layout.addWidget(self.result_card)
        
        # 초기 메시지
        self.show_initial_message()
        
    def show_initial_message(self):
        """초기 메시지 표시"""
        msg_label = QLabel("🎯 설정을 완료하고 '리포트 생성' 버튼을 클릭하세요.")
        msg_label.setStyleSheet("color: #999; text-align: center; padding: 50px;")
        msg_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result_layout.addWidget(msg_label)
    
    def generate_report(self):
        """리포트 생성"""
        report_type = self.report_type_combo.currentText()
        start_date = self.start_date.date().toString("yyyy-MM-dd")
        end_date = self.end_date.date().toString("yyyy-MM-dd")
        custom_title = self.report_title_input.text().strip() or None
        
        # 기존 결과 삭제
        self.clear_results()
        
        # 버튼 비활성화
        self.generate_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        
        # 백그라운드에서 리포트 생성
        self.generation_thread = threading.Thread(
            target=self.run_generation, 
            args=(report_type, start_date, end_date, custom_title)
        )
        self.generation_thread.start()
    
    def run_generation(self, report_type: str, start_date: str, end_date: str, custom_title: str):
        """백그라운드에서 리포트 생성"""
        try:
            report = self.report_generator.generate_report(
                report_type, start_date, end_date, custom_title
            )
            self.report_generator.report_generated.emit(asdict(report))
        except Exception as e:
            self.report_generator.progress_updated.emit(f"오류: {str(e)}", 0)
            self.generate_btn.setEnabled(True)
    
    @pyqtSlot(str, int)
    def on_progress_updated(self, message: str, progress: int):
        """진행률 업데이트"""
        self.progress_label.setText(message)
        self.progress_bar.setValue(progress)
        
        if progress == 100:
            self.generate_btn.setEnabled(True)
    
    @pyqtSlot(dict)
    def on_report_generated(self, report_data: Dict):
        """리포트 생성 완료"""
        self.current_report = report_data
        self.clear_results()
        self.display_report(report_data)
        self.export_btn.setEnabled(True)
    
    def display_report(self, report_data: Dict):
        """리포트 표시"""
        # 헤더 정보
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        
        title = QLabel(report_data["title"])
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #1890ff; margin-bottom: 10px;")
        header_layout.addWidget(title)
        
        info_layout = QGridLayout()
        info_layout.addWidget(QLabel("생성일:"), 0, 0)
        info_layout.addWidget(QLabel(report_data["created_at"][:19]), 0, 1)
        info_layout.addWidget(QLabel("분석 기간:"), 0, 2)
        info_layout.addWidget(QLabel(f"{report_data['period_start']} ~ {report_data['period_end']}"), 0, 3)
        info_layout.addWidget(QLabel("위험도:"), 1, 0)
        
        risk_label = QLabel(report_data["risk_level"])
        risk_colors = {"심각": "#ff4d4f", "높음": "#fa8c16", "보통": "#faad14", "낮음": "#52c41a"}
        risk_color = risk_colors.get(report_data["risk_level"], "#999")
        risk_label.setStyleSheet(f"color: {risk_color}; font-weight: bold;")
        info_layout.addWidget(risk_label, 1, 1)
        
        info_layout.addWidget(QLabel("페이지 수:"), 1, 2)
        info_layout.addWidget(QLabel(str(report_data["total_pages"])), 1, 3)
        
        header_layout.addLayout(info_layout)
        self.result_layout.addWidget(header_widget)
        
        # 구분선
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #d9d9d9;")
        self.result_layout.addWidget(line)
        
        # 전체 요약
        summary_widget = Card()
        summary_layout = QVBoxLayout(summary_widget)
        
        summary_title = QLabel("📋 전체 요약")
        summary_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #333; margin-bottom: 10px;")
        summary_layout.addWidget(summary_title)
        
        summary_content = QLabel(report_data["executive_summary"])
        summary_content.setWordWrap(True)
        summary_content.setStyleSheet("color: #666; line-height: 1.5;")
        summary_layout.addWidget(summary_content)
        
        self.result_layout.addWidget(summary_widget)
        
        # 각 섹션 표시
        for section in report_data["sections"]:
            section_widget = Card()
            section_layout = QVBoxLayout(section_widget)
            
            section_title = QLabel(f"📝 {section['title']}")
            section_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #333; margin-bottom: 10px;")
            section_layout.addWidget(section_title)
            
            section_content = QLabel(section["content"])
            section_content.setWordWrap(True)
            section_content.setStyleSheet("color: #666; line-height: 1.5;")
            section_layout.addWidget(section_content)
            
            self.result_layout.addWidget(section_widget)
    
    def export_report(self):
        """리포트 내보내기"""
        if not hasattr(self, 'current_report'):
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "리포트 저장", f"security_report_{int(time.time())}.txt", 
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    report = self.current_report
                    f.write(f"보안 리포트: {report['title']}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"생성일: {report['created_at'][:19]}\n")
                    f.write(f"분석 기간: {report['period_start']} ~ {report['period_end']}\n")
                    f.write(f"위험도: {report['risk_level']}\n\n")
                    
                    f.write("전체 요약\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"{report['executive_summary']}\n\n")
                    
                    for section in report['sections']:
                        f.write(f"{section['title']}\n")
                        f.write("-" * len(section['title']) + "\n")
                        f.write(f"{section['content']}\n\n")
                
                QMessageBox.information(self, "내보내기 완료", f"리포트가 저장되었습니다:\n{filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "저장 오류", f"리포트 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def clear_results(self):
        """결과 초기화"""
        while self.result_layout.count():
            child = self.result_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

if __name__ == "__main__":
    app = QApplication([])
    tab = AIReportGeneratorTab()
    tab.show()
    app.exec()