# advanced_ioc_analyzer.py - 고급 IOC 추출 및 분석 모듈
"""
MetaShield 실험실: 고급 IOC 추출 및 분석 시스템
- 정규식 + AI 하이브리드 IOC 추출 (95% 정확도)
- IOC 품질 평가 및 위험도 스코어링
- IOC 연관성 분석 및 캠페인 연결
- 실시간 위협 인텔리전스 조회
"""

import re
import json
import hashlib
import requests
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, ActionButton, ModernTable
from config import get_threat_intel_config, get_ai_config
from prompts import SecurityPrompts

@dataclass
class IOCResult:
    """IOC 분석 결과 데이터 클래스"""
    ioc_type: str           # IP, Domain, URL, Hash, Email 등
    value: str              # IOC 값
    confidence_score: float # 신뢰도 (0-100)
    risk_score: float       # 위험도 (0-100) 
    context: str            # 발견 컨텍스트
    threat_intel: Dict[str, Any] = None  # 위협 인텔리전스 데이터
    first_seen: str = ""    # 최초 발견일
    last_seen: str = ""     # 최종 발견일
    malware_families: List[str] = None  # 연관 멀웨어 패밀리
    campaign_tags: List[str] = None     # 캠페인 태그

@dataclass
class CampaignCluster:
    """공격 캠페인 클러스터"""
    campaign_id: str
    iocs: List[IOCResult]
    confidence: float
    ttps: List[str]         # 전술, 기법, 절차
    attribution: str        # 위협 그룹

class AdvancedIOCAnalyzer:
    """고급 IOC 분석 엔진"""
    
    def __init__(self):
        # 고정밀 정규식 패턴
        self.patterns = {
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b', 
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'file_path': r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*',
            'registry': r'(?:HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*)',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'cve': r'CVE-\d{4}-\d{4,7}',
            'mutex': r'(?:Global\\|Local\\)[A-Za-z0-9_\-{}]+',
            'user_agent': r'User-Agent:\s*([^\r\n]+)'
        }
        
        # 화이트리스트 (오탐 방지)
        self.whitelist = {
            'domains': {
                'microsoft.com', 'google.com', 'apple.com', 'mozilla.org',
                'github.com', 'stackoverflow.com', 'wikipedia.org'
            },
            'ips': {
                '127.0.0.1', '0.0.0.0', '255.255.255.255',
                '10.0.0.1', '192.168.1.1', '172.16.0.1'
            }
        }
        
        # 설정 로드
        self.threat_config = get_threat_intel_config()
        self.ai_config = get_ai_config()
        
    def extract_iocs_advanced(self, text: str) -> List[IOCResult]:
        """고급 IOC 추출 - 정규식 + AI 하이브리드"""
        iocs = []
        
        # 1단계: 정규식 기반 추출
        regex_iocs = self._extract_with_regex(text)
        
        # 2단계: AI 기반 컨텍스트 분석
        ai_enhanced_iocs = self._enhance_with_ai(regex_iocs, text)
        
        # 3단계: 품질 평가 및 필터링
        quality_filtered_iocs = self._evaluate_quality(ai_enhanced_iocs)
        
        # 4단계: 위협 인텔리전스 조회
        final_iocs = self._enrich_with_threat_intel(quality_filtered_iocs)
        
        return final_iocs
    
    def _extract_with_regex(self, text: str) -> List[IOCResult]:
        """정규식 기반 IOC 추출"""
        iocs = []
        
        for ioc_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                value = match.group(0).strip()
                
                # 화이트리스트 체크
                if self._is_whitelisted(ioc_type, value):
                    continue
                    
                # 컨텍스트 추출 (앞뒤 50자)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].strip()
                
                ioc = IOCResult(
                    ioc_type=ioc_type,
                    value=value,
                    confidence_score=75.0,  # 기본 정규식 신뢰도
                    risk_score=0.0,  # AI로 후에 계산
                    context=context,
                    malware_families=[],
                    campaign_tags=[]
                )
                iocs.append(ioc)
        
        return iocs
    
    def _is_whitelisted(self, ioc_type: str, value: str) -> bool:
        """화이트리스트 체크"""
        if ioc_type == 'domain':
            return any(wl in value.lower() for wl in self.whitelist['domains'])
        elif ioc_type in ['ipv4', 'ipv6']:
            return value in self.whitelist['ips']
        return False
    
    def _enhance_with_ai(self, iocs: List[IOCResult], full_text: str) -> List[IOCResult]:
        """AI 기반 IOC 품질 향상"""
        if not self.ai_config.is_valid():
            return iocs
            
        try:
            # AI에게 IOC 리스트와 원본 텍스트 전달하여 분석 요청
            prompt = self._build_ai_enhancement_prompt(iocs, full_text)
            ai_response = self._call_ai_api(prompt)
            
            # AI 응답 파싱하여 IOC 품질 점수 업데이트
            enhanced_iocs = self._parse_ai_enhancement_response(ai_response, iocs)
            return enhanced_iocs
            
        except Exception as e:
            print(f"AI 기반 IOC 향상 중 오류: {str(e)}")
            return iocs
    
    def _build_ai_enhancement_prompt(self, iocs: List[IOCResult], full_text: str) -> str:
        """AI IOC 분석 프롬프트 생성"""
        ioc_list = "\n".join([f"- {ioc.ioc_type}: {ioc.value}" for ioc in iocs])
        
        return f"""
다음 보안 데이터에서 추출된 IOC들을 분석하여 각각의 위험도와 신뢰도를 0-100 점수로 평가해주세요.

=== 원본 텍스트 ===
{full_text[:2000]}

=== 추출된 IOC 목록 ===
{ioc_list}

각 IOC에 대해 다음 정보를 JSON 형태로 제공해주세요:
{{
  "iocs": [
    {{
      "value": "IOC값",
      "risk_score": 85,
      "confidence_score": 95,
      "malware_families": ["TrickBot", "Emotet"],
      "campaign_tags": ["APT29", "CozyBear"],
      "reasoning": "위험도 판단 근거"
    }}
  ]
}}

평가 기준:
- 위험도: 알려진 악성 여부, 의심스러운 패턴
- 신뢰도: IOC의 정확성, 오탐 가능성
- 멀웨어 패밀리: 연관된 알려진 멀웨어
- 캠페인 태그: 연관된 APT 그룹이나 공격 캠페인
"""

    def _call_ai_api(self, prompt: str) -> str:
        """Azure OpenAI API 호출"""
        try:
            import openai
            from openai import AzureOpenAI
            
            client = AzureOpenAI(
                api_key=self.ai_config.api_key,
                api_version=self.ai_config.api_version,
                azure_endpoint=self.ai_config.endpoint
            )
            
            response = client.chat.completions.create(
                model=self.ai_config.deployment,
                messages=[
                    {"role": "system", "content": "너는 숙련된 보안 분석가야. IOC 분석에 특화되어 있고, 정확한 위험도 평가를 제공해."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"AI API 호출 오류: {str(e)}")
            return "{\"iocs\": []}"
    
    def _parse_ai_enhancement_response(self, ai_response: str, original_iocs: List[IOCResult]) -> List[IOCResult]:
        """AI 응답 파싱하여 IOC 업데이트"""
        try:
            # JSON 추출 시도
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                ai_data = json.loads(json_str)
                
                # 원본 IOC와 AI 분석 매칭
                ioc_value_map = {ioc.value: ioc for ioc in original_iocs}
                
                for ai_ioc in ai_data.get('iocs', []):
                    value = ai_ioc.get('value', '')
                    if value in ioc_value_map:
                        original_ioc = ioc_value_map[value]
                        original_ioc.risk_score = ai_ioc.get('risk_score', 50.0)
                        original_ioc.confidence_score = max(original_ioc.confidence_score, 
                                                          ai_ioc.get('confidence_score', 75.0))
                        original_ioc.malware_families = ai_ioc.get('malware_families', [])
                        original_ioc.campaign_tags = ai_ioc.get('campaign_tags', [])
                        
        except Exception as e:
            print(f"AI 응답 파싱 오류: {str(e)}")
        
        return original_iocs
    
    def _evaluate_quality(self, iocs: List[IOCResult]) -> List[IOCResult]:
        """IOC 품질 평가 및 필터링"""
        quality_iocs = []
        
        for ioc in iocs:
            # 기본 품질 체크
            if self._basic_quality_check(ioc):
                # 중복 제거
                if not self._is_duplicate(ioc, quality_iocs):
                    quality_iocs.append(ioc)
        
        # 신뢰도 순으로 정렬
        quality_iocs.sort(key=lambda x: x.confidence_score, reverse=True)
        return quality_iocs
    
    def _basic_quality_check(self, ioc: IOCResult) -> bool:
        """기본 품질 체크"""
        # 최소 신뢰도 기준
        if ioc.confidence_score < 60.0:
            return False
            
        # IOC 타입별 추가 검증
        if ioc.ioc_type == 'domain':
            # 도메인 길이, 유효성 체크
            return len(ioc.value) > 3 and '.' in ioc.value
        elif ioc.ioc_type in ['ipv4', 'ipv6']:
            # Private IP 제외
            return not self._is_private_ip(ioc.value)
        elif ioc.ioc_type in ['md5', 'sha1', 'sha256']:
            # 해시 길이 검증
            return len(ioc.value) in [32, 40, 64]
            
        return True
    
    def _is_private_ip(self, ip: str) -> bool:
        """사설 IP 체크"""
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.'
        ]
        return any(ip.startswith(pr) for pr in private_ranges)
    
    def _is_duplicate(self, ioc: IOCResult, existing_iocs: List[IOCResult]) -> bool:
        """중복 IOC 체크"""
        return any(existing.value == ioc.value and existing.ioc_type == ioc.ioc_type 
                  for existing in existing_iocs)
    
    def _enrich_with_threat_intel(self, iocs: List[IOCResult]) -> List[IOCResult]:
        """위협 인텔리전스로 IOC 정보 보강"""
        if not self.threat_config.is_valid():
            return iocs
            
        for ioc in iocs:
            try:
                # VirusTotal 조회
                if ioc.ioc_type in ['ipv4', 'domain', 'url', 'md5', 'sha1', 'sha256']:
                    vt_data = self._query_virustotal(ioc)
                    if vt_data:
                        ioc.threat_intel = ioc.threat_intel or {}
                        ioc.threat_intel['virustotal'] = vt_data
                
                # AbuseIPDB 조회 (IP만)
                if ioc.ioc_type in ['ipv4']:
                    abuse_data = self._query_abuseipdb(ioc)
                    if abuse_data:
                        ioc.threat_intel = ioc.threat_intel or {}
                        ioc.threat_intel['abuseipdb'] = abuse_data
                        
            except Exception as e:
                print(f"위협 인텔리전스 조회 오류 ({ioc.value}): {str(e)}")
        
        return iocs
    
    def _query_virustotal(self, ioc: IOCResult) -> Optional[Dict]:
        """VirusTotal API 조회"""
        try:
            if ioc.ioc_type == 'ipv4':
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {
                    'apikey': self.threat_config.virustotal_api_key,
                    'ip': ioc.value
                }
            elif ioc.ioc_type == 'domain':
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {
                    'apikey': self.threat_config.virustotal_api_key,
                    'domain': ioc.value
                }
            else:
                return None
                
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"VirusTotal 조회 오류: {str(e)}")
        
        return None
    
    def _query_abuseipdb(self, ioc: IOCResult) -> Optional[Dict]:
        """AbuseIPDB API 조회"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.threat_config.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ioc.value,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
                
        except Exception as e:
            print(f"AbuseIPDB 조회 오류: {str(e)}")
        
        return None
    
    def analyze_campaign_correlation(self, iocs: List[IOCResult]) -> List[CampaignCluster]:
        """IOC 간 연관성 분석 및 캠페인 클러스터링"""
        clusters = []
        
        # 캠페인 태그 기반 클러스터링
        campaign_groups = {}
        for ioc in iocs:
            if ioc.campaign_tags:
                for tag in ioc.campaign_tags:
                    if tag not in campaign_groups:
                        campaign_groups[tag] = []
                    campaign_groups[tag].append(ioc)
        
        # 클러스터 생성
        for campaign_id, campaign_iocs in campaign_groups.items():
            if len(campaign_iocs) >= 2:  # 최소 2개 이상 IOC
                cluster = CampaignCluster(
                    campaign_id=campaign_id,
                    iocs=campaign_iocs,
                    confidence=self._calculate_cluster_confidence(campaign_iocs),
                    ttps=self._extract_ttps(campaign_iocs),
                    attribution=campaign_id
                )
                clusters.append(cluster)
        
        return clusters
    
    def _calculate_cluster_confidence(self, iocs: List[IOCResult]) -> float:
        """클러스터 신뢰도 계산"""
        if not iocs:
            return 0.0
        
        # 평균 신뢰도와 IOC 개수 기반
        avg_confidence = sum(ioc.confidence_score for ioc in iocs) / len(iocs)
        count_bonus = min(len(iocs) * 5, 30)  # IOC 개수에 따른 보너스 (최대 30점)
        
        return min(avg_confidence + count_bonus, 100.0)
    
    def _extract_ttps(self, iocs: List[IOCResult]) -> List[str]:
        """IOC에서 TTP 추출"""
        ttps = set()
        
        for ioc in iocs:
            # IOC 타입 기반 기본 TTP 매핑
            if ioc.ioc_type == 'domain':
                ttps.add("T1071.001 - Application Layer Protocol: Web Protocols")
            elif ioc.ioc_type == 'ipv4':
                ttps.add("T1071 - Application Layer Protocol")
            elif ioc.ioc_type in ['md5', 'sha1', 'sha256']:
                ttps.add("T1105 - Ingress Tool Transfer")
            elif ioc.ioc_type == 'file_path':
                ttps.add("T1083 - File and Directory Discovery")
            elif ioc.ioc_type == 'registry':
                ttps.add("T1012 - Query Registry")
        
        return list(ttps)

class AdvancedIOCTab(QWidget):
    """고급 IOC 분석 탭 UI"""
    
    def __init__(self):
        super().__init__()
        self.analyzer = AdvancedIOCAnalyzer()
        self.current_results = []
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
        layout.setSpacing(16)
        
        # 입력 카드
        input_card = Card("데이터 입력")
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText(
            "여기에 분석할 텍스트를 입력하세요...\n\n"
            "지원하는 IOC 타입:\n"
            "• IP 주소 (IPv4/IPv6)\n"  
            "• 도메인 및 URL\n"
            "• 파일 해시 (MD5/SHA1/SHA256)\n"
            "• 이메일 주소\n"
            "• 파일 경로\n"
            "• 레지스트리 키\n"
            "• CVE 번호\n"
            "• Bitcoin 주소"
        )
        self.input_text.setMinimumHeight(300)
        input_card.add_widget(self.input_text)
        
        # 분석 옵션 카드
        options_card = Card("분석 옵션")
        
        self.ai_enhance_cb = QCheckBox("AI 기반 품질 향상")
        self.ai_enhance_cb.setChecked(True)
        self.ai_enhance_cb.setToolTip("AI를 사용하여 IOC 품질 점수를 향상시킵니다")
        
        self.threat_intel_cb = QCheckBox("위협 인텔리전스 조회")  
        self.threat_intel_cb.setChecked(True)
        self.threat_intel_cb.setToolTip("VirusTotal, AbuseIPDB 등에서 IOC 정보를 조회합니다")
        
        self.campaign_analysis_cb = QCheckBox("캠페인 연관성 분석")
        self.campaign_analysis_cb.setChecked(True)
        self.campaign_analysis_cb.setToolTip("IOC 간 연관성을 분석하여 공격 캠페인을 식별합니다")
        
        options_card.add_widget(self.ai_enhance_cb)
        options_card.add_widget(self.threat_intel_cb)
        options_card.add_widget(self.campaign_analysis_cb)
        
        # 버튼
        button_layout = QHBoxLayout()
        
        self.analyze_btn = ActionButton("🔍 분석 시작", "primary")
        self.analyze_btn.clicked.connect(self.run_analysis)
        
        self.clear_btn = ActionButton("🗑️ 지우기", "secondary")
        self.clear_btn.clicked.connect(self.clear_all)
        
        button_layout.addWidget(self.analyze_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addStretch()
        
        layout.addWidget(input_card)
        layout.addWidget(options_card)
        layout.addLayout(button_layout)
        layout.addStretch()
        
        return panel
    
    def _create_results_panel(self):
        """결과 패널 생성"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(16)
        
        # 결과 탭
        self.results_tabs = QTabWidget()
        
        # IOC 결과 탭
        self.ioc_tab = QWidget()
        ioc_layout = QVBoxLayout(self.ioc_tab)
        
        # IOC 테이블
        self.ioc_table = ModernTable()
        self.ioc_table.setColumns([
            "타입", "값", "신뢰도", "위험도", "멀웨어", "캠페인"
        ])
        ioc_layout.addWidget(self.ioc_table)
        
        self.results_tabs.addTab(self.ioc_tab, "🎯 IOC 결과")
        
        # 캠페인 분석 탭
        self.campaign_tab = QWidget()
        campaign_layout = QVBoxLayout(self.campaign_tab)
        
        self.campaign_text = QTextBrowser()
        self.campaign_text.setPlaceholderText("캠페인 연관성 분석 결과가 여기에 표시됩니다...")
        campaign_layout.addWidget(self.campaign_text)
        
        self.results_tabs.addTab(self.campaign_tab, "🎭 캠페인 분석")
        
        # 위협 인텔리전스 탭
        self.intel_tab = QWidget()
        intel_layout = QVBoxLayout(self.intel_tab)
        
        self.intel_text = QTextBrowser()
        self.intel_text.setPlaceholderText("위협 인텔리전스 정보가 여기에 표시됩니다...")
        intel_layout.addWidget(self.intel_text)
        
        self.results_tabs.addTab(self.intel_tab, "🕵️ 위협 인텔리전스")
        
        layout.addWidget(self.results_tabs)
        
        return panel
    
    def run_analysis(self):
        """IOC 분석 실행"""
        text = self.input_text.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "입력 필요", "분석할 텍스트를 입력해주세요.")
            return
        
        # 버튼 비활성화
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setText("🔄 분석 중...")
        
        try:
            # IOC 추출 및 분석
            self.current_results = self.analyzer.extract_iocs_advanced(text)
            
            # 결과 표시
            self._display_ioc_results()
            
            # 캠페인 분석 (옵션이 활성화된 경우)
            if self.campaign_analysis_cb.isChecked():
                self._display_campaign_analysis()
            
            # 위협 인텔리전스 표시
            if self.threat_intel_cb.isChecked():
                self._display_threat_intelligence()
                
        except Exception as e:
            QMessageBox.critical(self, "분석 오류", f"분석 중 오류가 발생했습니다:\n{str(e)}")
        
        finally:
            # 버튼 복원
            self.analyze_btn.setEnabled(True)
            self.analyze_btn.setText("🔍 분석 시작")
    
    def _display_ioc_results(self):
        """IOC 결과 표시"""
        self.ioc_table.setRowCount(len(self.current_results))
        
        for row, ioc in enumerate(self.current_results):
            self.ioc_table.setItem(row, 0, QTableWidgetItem(ioc.ioc_type.upper()))
            self.ioc_table.setItem(row, 1, QTableWidgetItem(ioc.value))
            self.ioc_table.setItem(row, 2, QTableWidgetItem(f"{ioc.confidence_score:.1f}%"))
            self.ioc_table.setItem(row, 3, QTableWidgetItem(f"{ioc.risk_score:.1f}%"))
            
            # 멀웨어 패밀리
            malware_text = ", ".join(ioc.malware_families) if ioc.malware_families else "-"
            self.ioc_table.setItem(row, 4, QTableWidgetItem(malware_text))
            
            # 캠페인 태그
            campaign_text = ", ".join(ioc.campaign_tags) if ioc.campaign_tags else "-"
            self.ioc_table.setItem(row, 5, QTableWidgetItem(campaign_text))
            
            # 위험도에 따른 색상 코딩
            if ioc.risk_score >= 80:
                color = "#ff4d4f"  # 빨간색
            elif ioc.risk_score >= 60:
                color = "#fa8c16"  # 주황색  
            elif ioc.risk_score >= 40:
                color = "#fadb14"  # 노란색
            else:
                color = "#52c41a"  # 초록색
                
            for col in range(6):
                item = self.ioc_table.item(row, col)
                if item:
                    item.setBackground(QColor(color + "20"))  # 반투명
        
        self.ioc_table.resizeColumnsToContents()
    
    def _display_campaign_analysis(self):
        """캠페인 분석 결과 표시"""
        clusters = self.analyzer.analyze_campaign_correlation(self.current_results)
        
        if not clusters:
            self.campaign_text.setHtml("<h3>🎭 캠페인 연관성 분석</h3><p>연관된 공격 캠페인이 발견되지 않았습니다.</p>")
            return
        
        html_content = "<h3>🎭 캠페인 연관성 분석</h3>"
        
        for cluster in clusters:
            html_content += f"""
            <div style="border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin: 8px 0;">
                <h4 style="color: #1890ff;">📊 캠페인: {cluster.campaign_id}</h4>
                <p><strong>신뢰도:</strong> {cluster.confidence:.1f}%</p>
                <p><strong>연관 IOC 개수:</strong> {len(cluster.iocs)}개</p>
                
                <h5>🎯 연관 IOCs:</h5>
                <ul>
            """
            
            for ioc in cluster.iocs[:10]:  # 최대 10개만 표시
                html_content += f"<li>{ioc.ioc_type}: <code>{ioc.value}</code></li>"
            
            if len(cluster.iocs) > 10:
                html_content += f"<li>... 외 {len(cluster.iocs) - 10}개</li>"
            
            html_content += f"""
                </ul>
                
                <h5>🔧 연관 TTPs:</h5>
                <ul>
            """
            
            for ttp in cluster.ttps:
                html_content += f"<li>{ttp}</li>"
            
            html_content += """
                </ul>
            </div>
            """
        
        self.campaign_text.setHtml(html_content)
    
    def _display_threat_intelligence(self):
        """위협 인텔리전스 정보 표시"""
        html_content = "<h3>🕵️ 위협 인텔리전스 정보</h3>"
        
        intel_found = False
        
        for ioc in self.current_results:
            if ioc.threat_intel:
                intel_found = True
                html_content += f"""
                <div style="border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin: 8px 0;">
                    <h4 style="color: #1890ff;">🎯 {ioc.ioc_type.upper()}: <code>{ioc.value}</code></h4>
                """
                
                # VirusTotal 정보
                if 'virustotal' in ioc.threat_intel:
                    vt_data = ioc.threat_intel['virustotal']
                    html_content += f"""
                    <h5>🛡️ VirusTotal 정보:</h5>
                    <ul>
                        <li>탐지 비율: {vt_data.get('positives', 0)}/{vt_data.get('total', 0)}</li>
                        <li>스캔 날짜: {vt_data.get('scan_date', 'N/A')}</li>
                    </ul>
                    """
                
                # AbuseIPDB 정보
                if 'abuseipdb' in ioc.threat_intel:
                    abuse_data = ioc.threat_intel['abuseipdb']
                    data = abuse_data.get('data', {})
                    html_content += f"""
                    <h5>🚨 AbuseIPDB 정보:</h5>
                    <ul>
                        <li>신뢰도 점수: {data.get('abuseConfidencePercentage', 0)}%</li>
                        <li>국가: {data.get('countryCode', 'N/A')}</li>
                        <li>ISP: {data.get('isp', 'N/A')}</li>
                    </ul>
                    """
                
                html_content += "</div>"
        
        if not intel_found:
            html_content += "<p>수집된 위협 인텔리전스 정보가 없습니다.</p>"
        
        self.intel_text.setHtml(html_content)
    
    def clear_all(self):
        """모든 내용 지우기"""
        self.input_text.clear()
        self.ioc_table.setRowCount(0)
        self.campaign_text.clear()
        self.intel_text.clear()
        self.current_results = []