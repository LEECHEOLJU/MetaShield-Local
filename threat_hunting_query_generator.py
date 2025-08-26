# threat_hunting_query_generator.py - 위협 헌팅 쿼리 생성 모듈
"""
MetaShield 실험실: 위협 헌팅 쿼리 자동 생성 시스템
- IOC 기반 Splunk/ELK 쿼리 자동 생성
- Sigma 룰 변환 및 최적화
- 커스텀 탐지 룰 생성 마법사
- 쿼리 성능 최적화
- 멀티 플랫폼 쿼리 호환성
"""

import re
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, ActionButton, ModernTable
from config import get_ai_config

@dataclass
class IOCInput:
    """IOC 입력 데이터"""
    ioc_type: str       # ip, domain, hash, email 등
    ioc_value: str      # IOC 값
    description: str    # 설명
    confidence: str     # high, medium, low

@dataclass
class QueryTemplate:
    """쿼리 템플릿"""
    platform: str       # splunk, elk, sigma 등
    query_type: str     # search, alert, hunt
    template: str       # 쿼리 템플릿 문자열
    description: str    # 템플릿 설명
    variables: List[str] # 템플릿 변수 목록

@dataclass
class GeneratedQuery:
    """생성된 쿼리"""
    platform: str
    query_type: str
    title: str
    description: str
    query: str
    time_range: str
    confidence: str
    references: List[str]
    tags: List[str]

class ThreatHuntingQueryGenerator:
    """위협 헌팅 쿼리 생성 엔진"""
    
    def __init__(self):
        self.ai_config = get_ai_config()
        
        # 플랫폼별 쿼리 템플릿
        self.query_templates = {
            'splunk': {
                'ip_search': QueryTemplate(
                    platform='splunk',
                    query_type='search',
                    template='index={index} (src_ip="{ioc_value}" OR dest_ip="{ioc_value}" OR clientip="{ioc_value}") | stats count by _time, src_ip, dest_ip, action | sort -_time',
                    description='IP 주소 기반 네트워크 활동 검색',
                    variables=['index', 'ioc_value']
                ),
                'domain_search': QueryTemplate(
                    platform='splunk',
                    query_type='search',
                    template='index={index} (query="{ioc_value}" OR dest="{ioc_value}" OR url="*{ioc_value}*") | stats count by _time, query, dest, src_ip | sort -_time',
                    description='도메인 기반 DNS/웹 활동 검색',
                    variables=['index', 'ioc_value']
                ),
                'hash_search': QueryTemplate(
                    platform='splunk',
                    query_type='search',
                    template='index={index} (md5="{ioc_value}" OR sha1="{ioc_value}" OR sha256="{ioc_value}" OR file_hash="{ioc_value}") | stats count by _time, file_name, file_path, md5, sha1, sha256 | sort -_time',
                    description='파일 해시 기반 파일 활동 검색',
                    variables=['index', 'ioc_value']
                ),
                'email_search': QueryTemplate(
                    platform='splunk',
                    query_type='search',
                    template='index={index} (sender="{ioc_value}" OR recipient="{ioc_value}" OR from="{ioc_value}" OR to="{ioc_value}") | stats count by _time, sender, recipient, subject | sort -_time',
                    description='이메일 주소 기반 메일 활동 검색',
                    variables=['index', 'ioc_value']
                )
            },
            'elk': {
                'ip_search': QueryTemplate(
                    platform='elk',
                    query_type='search',
                    template='{\n  "query": {\n    "bool": {\n      "should": [\n        {"term": {"src_ip.keyword": "{ioc_value}"}},\n        {"term": {"dest_ip.keyword": "{ioc_value}"}},\n        {"term": {"client_ip.keyword": "{ioc_value}"}}\n      ],\n      "minimum_should_match": 1\n    }\n  },\n  "aggs": {\n    "timeline": {\n      "date_histogram": {\n        "field": "@timestamp",\n        "interval": "1h"\n      }\n    }\n  }\n}',
                    description='Elasticsearch IP 주소 검색',
                    variables=['ioc_value']
                ),
                'domain_search': QueryTemplate(
                    platform='elk',
                    query_type='search',
                    template='{\n  "query": {\n    "bool": {\n      "should": [\n        {"term": {"dns.question.name.keyword": "{ioc_value}"}},\n        {"wildcard": {"url.domain": "*{ioc_value}*"}},\n        {"term": {"http.request.headers.host.keyword": "{ioc_value}"}}\n      ],\n      "minimum_should_match": 1\n    }\n  }\n}',
                    description='Elasticsearch 도메인 검색',
                    variables=['ioc_value']
                ),
                'hash_search': QueryTemplate(
                    platform='elk',
                    query_type='search',
                    template='{\n  "query": {\n    "bool": {\n      "should": [\n        {"term": {"file.hash.md5.keyword": "{ioc_value}"}},\n        {"term": {"file.hash.sha1.keyword": "{ioc_value}"}},\n        {"term": {"file.hash.sha256.keyword": "{ioc_value}"}}\n      ],\n      "minimum_should_match": 1\n    }\n  }\n}',
                    description='Elasticsearch 파일 해시 검색',
                    variables=['ioc_value']
                )
            },
            'sigma': {
                'process_creation': QueryTemplate(
                    platform='sigma',
                    query_type='detection',
                    template='title: Suspicious Process Execution\nid: {rule_id}\nstatus: experimental\ndescription: Detects suspicious process execution\nauthor: MetaShield\ndate: {date}\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - "{ioc_value}"\n  condition: selection\nfalsepositives:\n  - Unknown\nlevel: {level}\ntags:\n  - attack.execution',
                    description='Sigma 프로세스 생성 탐지 룰',
                    variables=['rule_id', 'date', 'ioc_value', 'level']
                ),
                'network_connection': QueryTemplate(
                    platform='sigma',
                    query_type='detection',
                    template='title: Suspicious Network Connection\nid: {rule_id}\nstatus: experimental\ndescription: Detects suspicious network connection\nauthor: MetaShield\ndate: {date}\nlogsource:\n  category: network_connection\n  product: windows\ndetection:\n  selection:\n    DestinationIp: "{ioc_value}"\n  condition: selection\nfalsepositives:\n  - Legitimate connections\nlevel: {level}\ntags:\n  - attack.command_and_control',
                    description='Sigma 네트워크 연결 탐지 룰',
                    variables=['rule_id', 'date', 'ioc_value', 'level']
                )
            }
        }
        
        # MITRE ATT&CK 매핑
        self.attack_mapping = {
            'ip': ['T1071', 'T1090', 'T1095'],  # Command and Control
            'domain': ['T1071.001', 'T1568'],   # Web Protocols, DNS
            'hash': ['T1105', 'T1059'],         # Ingress Tool Transfer, Command Line
            'email': ['T1566', 'T1114'],        # Phishing, Email Collection
            'registry': ['T1012', 'T1547'],     # Query Registry, Boot Autostart
            'process': ['T1059', 'T1055'],      # Command Line, Process Injection
        }
        
        # 플랫폼별 시간 형식
        self.time_formats = {
            'splunk': {
                '1h': 'earliest=-1h@h',
                '24h': 'earliest=-24h@h',
                '7d': 'earliest=-7d@d',
                '30d': 'earliest=-30d@d'
            },
            'elk': {
                '1h': 'now-1h',
                '24h': 'now-24h', 
                '7d': 'now-7d',
                '30d': 'now-30d'
            }
        }
    
    def generate_queries_from_iocs(self, iocs: List[IOCInput], platforms: List[str], 
                                  time_range: str = '24h') -> List[GeneratedQuery]:
        """IOC 리스트로부터 헌팅 쿼리 생성"""
        generated_queries = []
        
        for ioc in iocs:
            for platform in platforms:
                queries = self._generate_platform_queries(ioc, platform, time_range)
                generated_queries.extend(queries)
        
        return generated_queries
    
    def _generate_platform_queries(self, ioc: IOCInput, platform: str, 
                                  time_range: str) -> List[GeneratedQuery]:
        """특정 플랫폼용 쿼리 생성"""
        queries = []
        
        # IOC 타입에 맞는 템플릿 찾기
        template_key = f"{ioc.ioc_type}_search"
        
        if platform in self.query_templates and template_key in self.query_templates[platform]:
            template = self.query_templates[platform][template_key]
            
            # 템플릿 변수 치환
            query_str = self._substitute_template_variables(
                template.template, ioc, platform, time_range
            )
            
            # 쿼리 객체 생성
            query = GeneratedQuery(
                platform=platform,
                query_type=template.query_type,
                title=f"{ioc.ioc_type.upper()} IOC Hunt: {ioc.ioc_value}",
                description=f"{template.description} - Target: {ioc.ioc_value}",
                query=query_str,
                time_range=time_range,
                confidence=ioc.confidence,
                references=[],
                tags=self._get_attack_tags(ioc.ioc_type)
            )
            
            queries.append(query)
        
        return queries
    
    def _substitute_template_variables(self, template: str, ioc: IOCInput, 
                                     platform: str, time_range: str) -> str:
        """템플릿 변수 치환"""
        substitutions = {
            'ioc_value': ioc.ioc_value,
            'ioc_type': ioc.ioc_type,
            'index': '*',  # 기본값
            'rule_id': f"ms-{ioc.ioc_type}-{hash(ioc.ioc_value) % 10000:04d}",
            'date': datetime.now().strftime('%Y/%m/%d'),
            'level': {'high': 'high', 'medium': 'medium', 'low': 'low'}.get(ioc.confidence, 'medium')
        }
        
        # 시간 범위 추가
        if platform in self.time_formats and time_range in self.time_formats[platform]:
            substitutions['time_range'] = self.time_formats[platform][time_range]
        
        # 변수 치환
        result = template
        for var, value in substitutions.items():
            result = result.replace(f"{{{var}}}", str(value))
        
        return result
    
    def _get_attack_tags(self, ioc_type: str) -> List[str]:
        """MITRE ATT&CK 태그 반환"""
        return self.attack_mapping.get(ioc_type, [])
    
    def generate_sigma_rule(self, ioc: IOCInput, rule_type: str = 'auto') -> GeneratedQuery:
        """Sigma 룰 생성"""
        if rule_type == 'auto':
            # IOC 타입에 따라 자동 선택
            if ioc.ioc_type in ['process', 'command']:
                rule_type = 'process_creation'
            elif ioc.ioc_type in ['ip', 'domain']:
                rule_type = 'network_connection'
            else:
                rule_type = 'process_creation'
        
        template_key = rule_type
        if 'sigma' in self.query_templates and template_key in self.query_templates['sigma']:
            template = self.query_templates['sigma'][template_key]
            
            query_str = self._substitute_template_variables(
                template.template, ioc, 'sigma', '24h'
            )
            
            return GeneratedQuery(
                platform='sigma',
                query_type='detection',
                title=f"Sigma Rule: {ioc.ioc_type.upper()} Detection",
                description=f"{template.description} - Target: {ioc.ioc_value}",
                query=query_str,
                time_range='n/a',
                confidence=ioc.confidence,
                references=[],
                tags=self._get_attack_tags(ioc.ioc_type)
            )
        
        return None
    
    def optimize_query_for_platform(self, query: GeneratedQuery) -> GeneratedQuery:
        """플랫폼별 쿼리 최적화"""
        optimized_query = query
        
        if query.platform == 'splunk':
            optimized_query = self._optimize_splunk_query(query)
        elif query.platform == 'elk':
            optimized_query = self._optimize_elk_query(query)
        
        return optimized_query
    
    def _optimize_splunk_query(self, query: GeneratedQuery) -> GeneratedQuery:
        """Splunk 쿼리 최적화"""
        optimized = query
        
        # 인덱스 명시 추가
        if 'index=' not in query.query and not query.query.startswith('index='):
            optimized.query = f"index=* {query.query}"
        
        # 시간 범위 명시
        if query.time_range != 'n/a':
            time_filter = self.time_formats['splunk'].get(query.time_range, '')
            if time_filter and time_filter not in query.query:
                optimized.query = f"{query.query} {time_filter}"
        
        return optimized
    
    def _optimize_elk_query(self, query: GeneratedQuery) -> GeneratedQuery:
        """Elasticsearch 쿼리 최적화"""
        optimized = query
        
        try:
            # JSON 파싱해서 최적화
            query_dict = json.loads(query.query)
            
            # 시간 범위 추가
            if query.time_range != 'n/a':
                time_filter = {
                    "range": {
                        "@timestamp": {
                            "gte": self.time_formats['elk'].get(query.time_range, 'now-24h')
                        }
                    }
                }
                
                if "bool" in query_dict["query"]:
                    if "filter" not in query_dict["query"]["bool"]:
                        query_dict["query"]["bool"]["filter"] = []
                    query_dict["query"]["bool"]["filter"].append(time_filter)
                else:
                    query_dict["query"] = {
                        "bool": {
                            "must": [query_dict["query"]],
                            "filter": [time_filter]
                        }
                    }
            
            optimized.query = json.dumps(query_dict, indent=2)
            
        except json.JSONDecodeError:
            pass  # JSON이 아니면 원본 유지
        
        return optimized
    
    def generate_advanced_hunting_queries(self, threat_scenario: str) -> List[GeneratedQuery]:
        """고급 위협 시나리오 기반 헌팅 쿼리 생성"""
        queries = []
        
        scenarios = {
            'lateral_movement': {
                'title': 'Lateral Movement Detection',
                'description': '네트워크 내 측면 이동 탐지',
                'queries': {
                    'splunk': '''index=windows EventCode=4624 Logon_Type=3 
                    | stats count dc(Computer) as unique_computers by Account_Name 
                    | where unique_computers > 5 
                    | sort -count''',
                    'elk': '''{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 4624}},
        {"term": {"winlog.event_data.LogonType": "3"}}
      ]
    }
  },
  "aggs": {
    "accounts": {
      "terms": {"field": "winlog.event_data.TargetUserName.keyword"},
      "aggs": {
        "computers": {
          "cardinality": {"field": "winlog.computer_name.keyword"}
        }
      }
    }
  }
}'''
                }
            },
            'command_and_control': {
                'title': 'C2 Communication Detection',
                'description': '명령 제어 서버 통신 탐지',
                'queries': {
                    'splunk': '''index=proxy OR index=firewall 
                    | stats count by dest_ip, dest_port 
                    | where count > 100 
                    | sort -count''',
                    'elk': '''{
  "query": {
    "bool": {
      "should": [
        {"exists": {"field": "destination.ip"}},
        {"exists": {"field": "destination.port"}}
      ]
    }
  },
  "aggs": {
    "c2_candidates": {
      "composite": {
        "sources": [
          {"dest_ip": {"terms": {"field": "destination.ip.keyword"}}},
          {"dest_port": {"terms": {"field": "destination.port"}}}
        ]
      }
    }
  }
}'''
                }
            },
            'data_exfiltration': {
                'title': 'Data Exfiltration Detection',
                'description': '데이터 유출 활동 탐지',
                'queries': {
                    'splunk': '''index=proxy bytes_out > 10485760 
                    | stats sum(bytes_out) as total_bytes by src_ip, dest_ip 
                    | where total_bytes > 104857600 
                    | sort -total_bytes''',
                    'elk': '''{
  "query": {
    "range": {
      "network.bytes": {"gte": 10485760}
    }
  },
  "aggs": {
    "large_transfers": {
      "composite": {
        "sources": [
          {"src": {"terms": {"field": "source.ip.keyword"}}},
          {"dst": {"terms": {"field": "destination.ip.keyword"}}}
        ]
      },
      "aggs": {
        "total_bytes": {
          "sum": {"field": "network.bytes"}
        }
      }
    }
  }
}'''
                }
            }
        }
        
        for scenario_key, scenario_data in scenarios.items():
            for platform, query_str in scenario_data['queries'].items():
                query = GeneratedQuery(
                    platform=platform,
                    query_type='hunt',
                    title=scenario_data['title'],
                    description=scenario_data['description'],
                    query=query_str,
                    time_range='24h',
                    confidence='medium',
                    references=[],
                    tags=[f"scenario.{scenario_key}"]
                )
                queries.append(query)
        
        return queries

class ThreatHuntingTab(QWidget):
    """위협 헌팅 쿼리 생성 탭 UI"""
    
    def __init__(self):
        super().__init__()
        self.generator = ThreatHuntingQueryGenerator()
        self.ioc_list = []
        self.generated_queries = []
        self.setup_ui()
    
    def setup_ui(self):
        """UI 설정"""
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(12)
        
        # 메인 콘텐츠 - 좌우 분할
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 좌측 패널 - 입력 및 설정
        left_panel = self._create_input_panel()
        content_splitter.addWidget(left_panel)
        
        # 우측 패널 - 결과 표시
        right_panel = self._create_results_panel()
        content_splitter.addWidget(right_panel)
        
        # 비율 설정 (40:60)
        content_splitter.setSizes([400, 600])
        
        main_layout.addWidget(content_splitter)
        self.setLayout(main_layout)
    
    def _create_input_panel(self):
        """입력 패널 생성"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)
        
        # IOC 입력 섹션
        ioc_group = QGroupBox("🔍 IOC 입력")
        ioc_layout = QVBoxLayout(ioc_group)
        ioc_layout.setSpacing(8)
        
        # IOC 타입 선택 - 수평 레이아웃
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("타입:"))
        self.ioc_type_combo = QComboBox()
        self.ioc_type_combo.addItems([
            "IP 주소", "도메인", "파일해시", "이메일", "URL", 
            "프로세스명", "명령어", "레지스트리", "파일경로"
        ])
        self.ioc_type_combo.setMinimumWidth(150)
        type_layout.addWidget(self.ioc_type_combo)
        type_layout.addStretch()
        ioc_layout.addLayout(type_layout)
        
        # IOC 값 입력
        self.ioc_value_edit = QLineEdit()
        self.ioc_value_edit.setPlaceholderText("IOC 값을 입력하세요 (예: 192.168.1.100)")
        ioc_layout.addWidget(self.ioc_value_edit)
        
        # 신뢰도 선택 - 수평 레이아웃
        conf_layout = QHBoxLayout()
        conf_layout.addWidget(QLabel("신뢰도:"))
        self.confidence_combo = QComboBox()
        self.confidence_combo.addItems(["높음 (High)", "보통 (Medium)", "낮음 (Low)"])
        self.confidence_combo.setCurrentIndex(1)  # Medium 기본 선택
        self.confidence_combo.setMinimumWidth(120)
        conf_layout.addWidget(self.confidence_combo)
        conf_layout.addStretch()
        ioc_layout.addLayout(conf_layout)
        
        # 설명 입력
        ioc_layout.addWidget(QLabel("설명 (선택사항):"))
        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(60)
        self.description_edit.setPlaceholderText("IOC에 대한 설명을 입력하세요...")
        ioc_layout.addWidget(self.description_edit)
        
        # IOC 추가 버튼
        add_btn = ActionButton("➕ IOC 추가", "secondary")
        add_btn.clicked.connect(self.add_ioc)
        add_btn.setMaximumWidth(120)
        ioc_layout.addWidget(add_btn)
        
        layout.addWidget(ioc_group)
        
        # 쿼리 설정 섹션
        settings_group = QGroupBox("⚙️ 쿼리 설정")
        settings_layout = QVBoxLayout(settings_group)
        settings_layout.setSpacing(8)
        
        # 플랫폼 선택
        settings_layout.addWidget(QLabel("타겟 플랫폼:"))
        platform_layout = QVBoxLayout()
        platform_layout.setSpacing(4)
        
        self.splunk_cb = QCheckBox("Splunk (SPL)")
        self.splunk_cb.setChecked(True)
        platform_layout.addWidget(self.splunk_cb)
        
        self.elk_cb = QCheckBox("ELK/Elasticsearch (DSL)")
        self.elk_cb.setChecked(True)
        platform_layout.addWidget(self.elk_cb)
        
        self.sigma_cb = QCheckBox("Sigma Rules (YAML)")
        self.sigma_cb.setChecked(False)
        platform_layout.addWidget(self.sigma_cb)
        
        settings_layout.addLayout(platform_layout)
        
        # 시간 범위 선택 - 수평 레이아웃
        time_layout = QHBoxLayout()
        time_layout.addWidget(QLabel("시간 범위:"))
        self.time_combo = QComboBox()
        self.time_combo.addItems(["1시간", "24시간", "7일", "30일"])
        self.time_combo.setCurrentIndex(1)  # 24시간 기본 선택
        self.time_combo.setMinimumWidth(100)
        time_layout.addWidget(self.time_combo)
        time_layout.addStretch()
        settings_layout.addLayout(time_layout)
        
        layout.addWidget(settings_group)
        
        # 고급 시나리오 섹션
        scenario_group = QGroupBox("🎯 고급 헌팅 시나리오")
        scenario_layout = QVBoxLayout(scenario_group)
        scenario_layout.setSpacing(8)
        
        self.scenario_combo = QComboBox()
        self.scenario_combo.addItems([
            "선택 안함",
            "측면 이동 (Lateral Movement)",
            "C2 통신 (Command & Control)", 
            "데이터 유출 (Data Exfiltration)"
        ])
        scenario_layout.addWidget(self.scenario_combo)
        
        layout.addWidget(scenario_group)
        
        # 액션 버튼 섹션
        action_group = QGroupBox("🚀 액션")
        action_layout = QVBoxLayout(action_group)
        action_layout.setSpacing(8)
        
        self.generate_btn = ActionButton("🔍 IOC 쿼리 생성", "primary")
        self.generate_btn.clicked.connect(self.generate_queries)
        action_layout.addWidget(self.generate_btn)
        
        self.scenario_btn = ActionButton("🎯 시나리오 쿼리 생성", "success")
        self.scenario_btn.clicked.connect(self.generate_scenario_queries)
        action_layout.addWidget(self.scenario_btn)
        
        self.clear_btn = ActionButton("🗑️ 모두 지우기", "secondary")
        self.clear_btn.clicked.connect(self.clear_all)
        action_layout.addWidget(self.clear_btn)
        
        layout.addWidget(action_group)
        layout.addStretch()
        
        return panel
    
    def _create_results_panel(self):
        """결과 패널 생성"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(16)
        
        # 결과 탭
        self.results_tabs = QTabWidget()
        
        # IOC 목록 탭
        self.ioc_list_tab = QWidget()
        ioc_list_layout = QVBoxLayout(self.ioc_list_tab)
        
        # IOC 테이블
        self.ioc_table = ModernTable()
        self.ioc_table.setColumns(["타입", "값", "신뢰도", "설명"])
        ioc_list_layout.addWidget(self.ioc_table)
        
        # IOC 삭제 버튼
        delete_btn = ActionButton("🗑️ 선택된 IOC 삭제", "danger")
        delete_btn.clicked.connect(self.delete_selected_ioc)
        ioc_list_layout.addWidget(delete_btn)
        
        self.results_tabs.addTab(self.ioc_list_tab, "📋 IOC 목록")
        
        # 생성된 쿼리 탭
        self.queries_tab = QWidget()
        queries_layout = QVBoxLayout(self.queries_tab)
        
        # 쿼리 리스트
        self.query_list = QListWidget()
        self.query_list.itemClicked.connect(self.show_query_detail)
        queries_layout.addWidget(self.query_list)
        
        # 쿼리 상세 표시
        self.query_detail = QTextEdit()
        self.query_detail.setFont(QFont("Consolas", 10))
        self.query_detail.setReadOnly(True)
        queries_layout.addWidget(self.query_detail)
        
        # 쿼리 저장 버튼
        save_btn = ActionButton("💾 쿼리 저장", "success")
        save_btn.clicked.connect(self.save_queries)
        queries_layout.addWidget(save_btn)
        
        self.results_tabs.addTab(self.queries_tab, "🔍 생성된 쿼리")
        
        # Sigma 룰 탭
        self.sigma_tab = QWidget()
        sigma_layout = QVBoxLayout(self.sigma_tab)
        
        self.sigma_text = QTextEdit()
        self.sigma_text.setFont(QFont("Consolas", 10))
        self.sigma_text.setPlaceholderText("Sigma 룰이 여기에 표시됩니다...")
        sigma_layout.addWidget(self.sigma_text)
        
        # Sigma 저장 버튼
        save_sigma_btn = ActionButton("💾 Sigma 룰 저장", "success")
        save_sigma_btn.clicked.connect(self.save_sigma_rules)
        sigma_layout.addWidget(save_sigma_btn)
        
        self.results_tabs.addTab(self.sigma_tab, "⚡ Sigma 룰")
        
        layout.addWidget(self.results_tabs)
        
        return panel
    
    def add_ioc(self):
        """IOC 추가"""
        ioc_type_display = self.ioc_type_combo.currentText()
        ioc_value = self.ioc_value_edit.text().strip()
        confidence_display = self.confidence_combo.currentText()
        description = self.description_edit.toPlainText().strip()
        
        if not ioc_value:
            QMessageBox.warning(self, "입력 필요", "IOC 값을 입력해주세요.")
            return
        
        # 한국어 표시명을 영문 코드로 변환
        type_mapping = {
            "IP 주소": "ip",
            "도메인": "domain", 
            "파일해시": "hash",
            "이메일": "email",
            "URL": "url",
            "프로세스명": "process",
            "명령어": "command",
            "레지스트리": "registry",
            "파일경로": "file_path"
        }
        
        confidence_mapping = {
            "높음 (High)": "high",
            "보통 (Medium)": "medium",
            "낮음 (Low)": "low"
        }
        
        ioc_type = type_mapping.get(ioc_type_display, "unknown")
        confidence = confidence_mapping.get(confidence_display, "medium")
        
        # IOC 객체 생성
        ioc = IOCInput(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            description=description or f"{ioc_type_display} IOC",
            confidence=confidence
        )
        
        # 리스트에 추가
        self.ioc_list.append(ioc)
        
        # 테이블 업데이트
        self._update_ioc_table()
        
        # 입력 필드 초기화
        self.ioc_value_edit.clear()
        self.description_edit.clear()
        
        QMessageBox.information(self, "IOC 추가됨", f"{ioc_type_display} IOC가 성공적으로 추가되었습니다.")
    
    def _update_ioc_table(self):
        """IOC 테이블 업데이트"""
        self.ioc_table.setRowCount(len(self.ioc_list))
        
        # 타입 및 신뢰도 역변환 매핑
        type_reverse_mapping = {
            "ip": "IP 주소",
            "domain": "도메인", 
            "hash": "파일해시",
            "email": "이메일",
            "url": "URL",
            "process": "프로세스명",
            "command": "명령어",
            "registry": "레지스트리",
            "file_path": "파일경로"
        }
        
        confidence_reverse_mapping = {
            "high": "높음",
            "medium": "보통",
            "low": "낮음"
        }
        
        for row, ioc in enumerate(self.ioc_list):
            # 타입을 한국어로 표시
            type_display = type_reverse_mapping.get(ioc.ioc_type, ioc.ioc_type.upper())
            self.ioc_table.setItem(row, 0, QTableWidgetItem(type_display))
            
            # IOC 값
            self.ioc_table.setItem(row, 1, QTableWidgetItem(ioc.ioc_value))
            
            # 신뢰도를 한국어로 표시
            confidence_display = confidence_reverse_mapping.get(ioc.confidence, ioc.confidence)
            self.ioc_table.setItem(row, 2, QTableWidgetItem(confidence_display))
            
            # 설명
            self.ioc_table.setItem(row, 3, QTableWidgetItem(ioc.description))
            
            # 신뢰도에 따른 색상
            color = {
                'high': '#ff4d4f',
                'medium': '#fa8c16', 
                'low': '#52c41a'
            }.get(ioc.confidence, '#d9d9d9')
            
            for col in range(4):
                item = self.ioc_table.item(row, col)
                if item:
                    item.setBackground(QColor(color + '30'))
        
        self.ioc_table.resizeColumnsToContents()
    
    def delete_selected_ioc(self):
        """선택된 IOC 삭제"""
        current_row = self.ioc_table.currentRow()
        if current_row >= 0 and current_row < len(self.ioc_list):
            self.ioc_list.pop(current_row)
            self._update_ioc_table()
    
    def generate_queries(self):
        """쿼리 생성"""
        if not self.ioc_list:
            QMessageBox.warning(self, "IOC 필요", "먼저 IOC를 추가해주세요.")
            return
        
        # 선택된 플랫폼 확인
        platforms = []
        if self.splunk_cb.isChecked():
            platforms.append('splunk')
        if self.elk_cb.isChecked():
            platforms.append('elk')
        
        if not platforms:
            QMessageBox.warning(self, "플랫폼 선택", "최소 하나의 플랫폼을 선택해주세요.")
            return
        
        try:
            # 시간 범위를 영문 코드로 변환
            time_range_mapping = {
                "1시간": "1h",
                "24시간": "24h", 
                "7일": "7d",
                "30일": "30d"
            }
            time_range = time_range_mapping.get(self.time_combo.currentText(), "24h")
            
            # 쿼리 생성
            self.generated_queries = self.generator.generate_queries_from_iocs(
                self.ioc_list, platforms, time_range
            )
            
            # Sigma 룰 생성 (옵션이 선택된 경우)
            if self.sigma_cb.isChecked():
                sigma_rules = []
                for ioc in self.ioc_list:
                    sigma_rule = self.generator.generate_sigma_rule(ioc)
                    if sigma_rule:
                        sigma_rules.append(sigma_rule)
                        self.generated_queries.append(sigma_rule)
                
                # Sigma 룰 표시
                self._display_sigma_rules(sigma_rules)
            
            # 쿼리 리스트 업데이트
            self._update_query_list()
            
            # 쿼리 탭으로 전환
            self.results_tabs.setCurrentIndex(1)
            
        except Exception as e:
            QMessageBox.critical(self, "쿼리 생성 오류", f"쿼리 생성 중 오류가 발생했습니다:\n{str(e)}")
    
    def generate_scenario_queries(self):
        """시나리오 기반 쿼리 생성"""
        scenario = self.scenario_combo.currentText()
        if scenario == "선택 안함":
            QMessageBox.warning(self, "시나리오 선택", "헌팅 시나리오를 선택해주세요.")
            return
        
        try:
            # 시나리오 매핑
            scenario_mapping = {
                "측면 이동 (Lateral Movement)": "lateral_movement",
                "C2 통신 (Command & Control)": "command_and_control",
                "데이터 유출 (Data Exfiltration)": "data_exfiltration"
            }
            
            scenario_key = scenario_mapping.get(scenario)
            if not scenario_key:
                QMessageBox.warning(self, "시나리오 오류", "지원하지 않는 시나리오입니다.")
                return
            
            # 고급 헌팅 쿼리 생성
            scenario_queries = self.generator.generate_advanced_hunting_queries(scenario_key)
            
            if scenario_queries:
                self.generated_queries.extend(scenario_queries)
                self._update_query_list()
                self.results_tabs.setCurrentIndex(1)
            else:
                QMessageBox.information(self, "알림", "해당 시나리오에 대한 쿼리가 없습니다.")
                
        except Exception as e:
            QMessageBox.critical(self, "시나리오 쿼리 오류", f"시나리오 쿼리 생성 중 오류가 발생했습니다:\n{str(e)}")
    
    def _update_query_list(self):
        """쿼리 리스트 업데이트"""
        self.query_list.clear()
        
        for i, query in enumerate(self.generated_queries):
            platform_icon = {
                'splunk': '🔍',
                'elk': '🔎',
                'sigma': '⚡'
            }.get(query.platform, '📊')
            
            item_text = f"{platform_icon} [{query.platform.upper()}] {query.title}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, i)  # 인덱스 저장
            self.query_list.addItem(item)
    
    def show_query_detail(self, item):
        """쿼리 상세 표시"""
        query_index = item.data(Qt.ItemDataRole.UserRole)
        if 0 <= query_index < len(self.generated_queries):
            query = self.generated_queries[query_index]
            
            detail_text = f"""# {query.title}
# Platform: {query.platform.upper()}
# Description: {query.description}
# Time Range: {query.time_range}
# Confidence: {query.confidence}

{query.query}

# Tags: {', '.join(query.tags)}
"""
            
            self.query_detail.setPlainText(detail_text)
    
    def _display_sigma_rules(self, sigma_rules):
        """Sigma 룰 표시"""
        if not sigma_rules:
            return
        
        sigma_content = ""
        for i, rule in enumerate(sigma_rules):
            sigma_content += f"# Rule {i+1}: {rule.title}\n"
            sigma_content += f"# {rule.description}\n\n"
            sigma_content += rule.query
            sigma_content += "\n\n" + "="*50 + "\n\n"
        
        self.sigma_text.setPlainText(sigma_content)
    
    def save_queries(self):
        """쿼리 저장"""
        if not self.generated_queries:
            QMessageBox.warning(self, "쿼리 없음", "저장할 쿼리가 없습니다.")
            return
        
        # 파일 저장 다이얼로그
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "헌팅 쿼리 저장",
            f"hunting_queries_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# MetaShield Threat Hunting Queries\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    for i, query in enumerate(self.generated_queries):
                        f.write(f"# Query {i+1}: {query.title}\n")
                        f.write(f"# Platform: {query.platform.upper()}\n")
                        f.write(f"# Description: {query.description}\n")
                        f.write(f"# Time Range: {query.time_range}\n")
                        f.write(f"# Confidence: {query.confidence}\n")
                        f.write(f"# Tags: {', '.join(query.tags)}\n\n")
                        f.write(query.query)
                        f.write("\n\n" + "="*80 + "\n\n")
                
                QMessageBox.information(self, "저장 완료", f"헌팅 쿼리가 저장되었습니다:\n{file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "저장 오류", f"파일 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def save_sigma_rules(self):
        """Sigma 룰 저장"""
        content = self.sigma_text.toPlainText()
        if not content.strip():
            QMessageBox.warning(self, "내용 없음", "저장할 Sigma 룰이 없습니다.")
            return
        
        # 파일 저장 다이얼로그
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Sigma 룰 저장",
            f"sigma_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yml",
            "YAML Files (*.yml *.yaml);;Text Files (*.txt);;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                QMessageBox.information(self, "저장 완료", f"Sigma 룰이 저장되었습니다:\n{file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "저장 오류", f"파일 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def clear_all(self):
        """모든 내용 지우기"""
        self.ioc_list.clear()
        self.generated_queries.clear()
        
        # UI 초기화
        self.ioc_value_edit.clear()
        self.description_edit.clear()
        self.ioc_table.setRowCount(0)
        self.query_list.clear()
        self.query_detail.clear()
        self.sigma_text.clear()
        
        # 첫 번째 탭으로 전환
        self.results_tabs.setCurrentIndex(0)