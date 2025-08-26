# yara_rule_generator.py - YARA 룰 자동 생성 모듈
"""
MetaShield 실험실: YARA 룰 자동 생성 시스템
- 멀웨어 샘플 기반 YARA 룰 자동 생성
- AI 기반 패턴 식별 및 룰 최적화
- YARA 룰 테스트 및 검증 환경
- 룰 성능 및 오탐률 평가
"""

import os
import re
import json
import hashlib
import binascii
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from advanced_ui_components import Card, ActionButton, ModernTable
from config import get_ai_config
from prompts import SecurityPrompts

@dataclass
class YaraPattern:
    """YARA 패턴 데이터 클래스"""
    pattern_type: str       # strings, hex, condition 등
    pattern_value: str      # 패턴 값
    confidence: float       # 신뢰도 (0-100)
    description: str        # 패턴 설명
    position: str = "any"   # at, in 등 위치 조건
    modifier: str = ""      # nocase, wide, ascii 등 수정자

@dataclass
class YaraRule:
    """YARA 룰 데이터 클래스"""
    rule_name: str
    description: str
    author: str
    date: str
    version: str
    patterns: List[YaraPattern]
    conditions: List[str]
    tags: List[str] = None
    references: List[str] = None
    malware_family: str = ""
    severity: str = "medium"  # low, medium, high, critical

class YaraRuleGenerator:
    """YARA 룰 자동 생성 엔진"""
    
    def __init__(self):
        self.ai_config = get_ai_config()
        
        # 기본 패턴 템플릿
        self.pattern_templates = {
            'pe_header': [
                {'pattern': 'MZ', 'type': 'hex', 'description': 'PE Header'},
                {'pattern': 'This program cannot be run in DOS mode', 'type': 'string', 'description': 'DOS Stub'}
            ],
            'suspicious_strings': [
                {'pattern': 'cmd.exe', 'type': 'string', 'description': 'Command execution'},
                {'pattern': 'powershell', 'type': 'string', 'description': 'PowerShell execution'},
                {'pattern': 'WScript.Shell', 'type': 'string', 'description': 'Script execution'},
                {'pattern': 'CreateProcess', 'type': 'string', 'description': 'Process creation'}
            ],
            'network_indicators': [
                {'pattern': 'HTTP/1.1', 'type': 'string', 'description': 'HTTP communication'},
                {'pattern': 'Mozilla/', 'type': 'string', 'description': 'User-Agent string'},
                {'pattern': 'POST ', 'type': 'string', 'description': 'HTTP POST request'}
            ],
            'crypto_patterns': [
                {'pattern': 'CryptAcquireContext', 'type': 'string', 'description': 'Crypto API'},
                {'pattern': 'CryptEncrypt', 'type': 'string', 'description': 'Encryption'},
                {'pattern': 'CryptDecrypt', 'type': 'string', 'description': 'Decryption'}
            ]
        }
        
        # 멀웨어 패밀리별 특징
        self.malware_signatures = {
            'ransomware': {
                'strings': ['encrypted', 'decrypt', 'bitcoin', 'ransom', 'recover'],
                'apis': ['CryptGenRandom', 'CryptAcquireContext', 'FindFirstFile'],
                'extensions': ['.locked', '.encrypted', '.crypt']
            },
            'trojan': {
                'strings': ['backdoor', 'keylog', 'steal', 'credential'],
                'apis': ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAlloc'],
                'behaviors': ['process_injection', 'registry_modification']
            },
            'downloader': {
                'strings': ['download', 'execute', 'update', 'install'],
                'apis': ['URLDownloadToFile', 'WinExec', 'CreateProcess'],
                'network': ['http://', 'https://', 'ftp://']
            }
        }
    
    def analyze_file_content(self, file_path: str) -> Dict[str, Any]:
        """파일 내용 분석"""
        analysis_result = {
            'file_size': 0,
            'file_type': 'unknown',
            'entropy': 0.0,
            'strings': [],
            'hex_patterns': [],
            'pe_info': None,
            'suspicious_indicators': []
        }
        
        try:
            if not os.path.exists(file_path):
                return analysis_result
                
            # 파일 크기
            analysis_result['file_size'] = os.path.getsize(file_path)
            
            # 파일 내용 읽기
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # 파일 타입 확인
            analysis_result['file_type'] = self._detect_file_type(content)
            
            # 엔트로피 계산
            analysis_result['entropy'] = self._calculate_entropy(content)
            
            # 문자열 추출
            analysis_result['strings'] = self._extract_strings(content)
            
            # 16진수 패턴 추출
            analysis_result['hex_patterns'] = self._extract_hex_patterns(content)
            
            # PE 파일 분석 (해당되는 경우)
            if analysis_result['file_type'] == 'PE':
                analysis_result['pe_info'] = self._analyze_pe_file(content)
            
            # 의심스러운 지표 탐지
            analysis_result['suspicious_indicators'] = self._detect_suspicious_indicators(
                analysis_result['strings'], content
            )
            
        except Exception as e:
            print(f"파일 분석 오류: {str(e)}")
        
        return analysis_result
    
    def _detect_file_type(self, content: bytes) -> str:
        """파일 타입 탐지"""
        if content.startswith(b'MZ'):
            return 'PE'
        elif content.startswith(b'\x7fELF'):
            return 'ELF'
        elif content.startswith(b'PK'):
            return 'ZIP/JAR'
        elif content.startswith(b'%PDF'):
            return 'PDF'
        else:
            return 'UNKNOWN'
    
    def _calculate_entropy(self, content: bytes) -> float:
        """엔트로피 계산"""
        if not content:
            return 0.0
        
        import math
        
        # 바이트 빈도 계산
        byte_counts = [0] * 256
        for byte in content:
            byte_counts[byte] += 1
        
        # 엔트로피 계산
        entropy = 0.0
        content_len = len(content)
        
        for count in byte_counts:
            if count > 0:
                probability = count / content_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_strings(self, content: bytes) -> List[str]:
        """의미있는 문자열 추출"""
        strings = []
        
        # ASCII 문자열 추출 (최소 길이 4)
        ascii_pattern = rb'[\x20-\x7E]{4,}'
        matches = re.findall(ascii_pattern, content)
        
        for match in matches:
            try:
                string_val = match.decode('ascii')
                if len(string_val) >= 4:
                    strings.append(string_val)
            except:
                continue
        
        # 중복 제거 및 정렬
        strings = list(set(strings))
        strings.sort(key=len, reverse=True)
        
        return strings[:100]  # 상위 100개만
    
    def _extract_hex_patterns(self, content: bytes) -> List[str]:
        """특징적인 16진수 패턴 추출"""
        patterns = []
        
        # 4바이트 단위로 패턴 추출
        for i in range(0, min(len(content), 1024), 4):  # 첫 1KB만 분석
            if i + 4 <= len(content):
                hex_chunk = content[i:i+4].hex().upper()
                
                # 특징적인 패턴인지 확인
                if self._is_interesting_hex_pattern(hex_chunk):
                    patterns.append(hex_chunk)
        
        return list(set(patterns))[:20]  # 상위 20개만
    
    def _is_interesting_hex_pattern(self, hex_pattern: str) -> bool:
        """흥미로운 16진수 패턴인지 확인"""
        # 모두 같은 값이면 제외
        if len(set(hex_pattern)) == 1:
            return False
        
        # 순차적 패턴이면 제외
        if hex_pattern in ['01234567', '89ABCDEF']:
            return False
        
        # 일반적인 패턴이면 제외
        common_patterns = ['00000000', 'FFFFFFFF', 'CCCCCCCC']
        if hex_pattern in common_patterns:
            return False
        
        return True
    
    def _analyze_pe_file(self, content: bytes) -> Dict[str, Any]:
        """PE 파일 분석"""
        pe_info = {
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'characteristics': []
        }
        
        try:
            # 간단한 PE 헤더 파싱 (pefile 없이)
            # DOS 헤더에서 PE 헤더 위치 찾기
            if len(content) < 64:
                return pe_info
                
            pe_offset = int.from_bytes(content[60:64], 'little')
            
            if pe_offset >= len(content) - 4:
                return pe_info
            
            # PE 시그니처 확인
            if content[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return pe_info
            
            pe_info['valid_pe'] = True
            
            # 섹션 정보 간단 추출 (실제 구현에서는 pefile 사용 권장)
            # 여기서는 기본적인 정보만 추출
            
        except Exception as e:
            print(f"PE 분석 오류: {str(e)}")
        
        return pe_info
    
    def _detect_suspicious_indicators(self, strings: List[str], content: bytes) -> List[Dict[str, str]]:
        """의심스러운 지표 탐지"""
        indicators = []
        
        # 문자열 기반 탐지
        for string in strings:
            string_lower = string.lower()
            
            # 암호화/복호화 관련
            if any(keyword in string_lower for keyword in ['encrypt', 'decrypt', 'cipher', 'crypto']):
                indicators.append({
                    'type': 'crypto',
                    'value': string,
                    'description': 'Cryptographic activity'
                })
            
            # 네트워크 관련
            if any(keyword in string_lower for keyword in ['http://', 'https://', 'ftp://']):
                indicators.append({
                    'type': 'network',
                    'value': string,
                    'description': 'Network communication'
                })
            
            # 시스템 조작
            if any(keyword in string_lower for keyword in ['registry', 'service', 'process']):
                indicators.append({
                    'type': 'system',
                    'value': string,
                    'description': 'System manipulation'
                })
            
            # 데이터 수집
            if any(keyword in string_lower for keyword in ['keylog', 'screenshot', 'clipboard']):
                indicators.append({
                    'type': 'collection',
                    'value': string,
                    'description': 'Data collection'
                })
        
        return indicators[:50]  # 상위 50개만
    
    def generate_yara_rule(self, file_analysis: Dict[str, Any], rule_name: str = "", 
                          malware_family: str = "") -> YaraRule:
        """YARA 룰 생성"""
        
        # 룰 이름 생성
        if not rule_name:
            rule_name = f"rule_{hashlib.md5(str(file_analysis).encode()).hexdigest()[:8]}"
        
        # 패턴 생성
        patterns = self._generate_patterns(file_analysis)
        
        # 조건 생성
        conditions = self._generate_conditions(patterns, file_analysis)
        
        # 태그 생성
        tags = self._generate_tags(file_analysis, malware_family)
        
        # YARA 룰 객체 생성
        yara_rule = YaraRule(
            rule_name=rule_name,
            description=f"Auto-generated YARA rule for {malware_family or 'unknown'} malware",
            author="MetaShield Auto-Generator",
            date=datetime.now().strftime("%Y-%m-%d"),
            version="1.0",
            patterns=patterns,
            conditions=conditions,
            tags=tags,
            malware_family=malware_family,
            severity=self._assess_severity(file_analysis)
        )
        
        return yara_rule
    
    def _generate_patterns(self, analysis: Dict[str, Any]) -> List[YaraPattern]:
        """패턴 생성"""
        patterns = []
        
        # 문자열 패턴
        for i, string_val in enumerate(analysis.get('strings', [])[:10]):  # 상위 10개
            if len(string_val) >= 6 and self._is_good_string_pattern(string_val):
                pattern = YaraPattern(
                    pattern_type='string',
                    pattern_value=string_val,
                    confidence=self._calculate_string_confidence(string_val),
                    description=f'Characteristic string {i+1}',
                    modifier='ascii'
                )
                patterns.append(pattern)
        
        # 16진수 패턴
        for i, hex_pattern in enumerate(analysis.get('hex_patterns', [])[:5]):  # 상위 5개
            pattern = YaraPattern(
                pattern_type='hex',
                pattern_value=hex_pattern,
                confidence=75.0,
                description=f'Characteristic hex pattern {i+1}'
            )
            patterns.append(pattern)
        
        # 파일 크기 패턴
        file_size = analysis.get('file_size', 0)
        if file_size > 0:
            size_range = self._get_size_range(file_size)
            pattern = YaraPattern(
                pattern_type='condition',
                pattern_value=f'filesize > {size_range[0]} and filesize < {size_range[1]}',
                confidence=60.0,
                description='File size constraint'
            )
            patterns.append(pattern)
        
        # 엔트로피 패턴 (높은 엔트로피는 패킹/암호화 의심)
        entropy = analysis.get('entropy', 0.0)
        if entropy > 7.0:  # 높은 엔트로피
            pattern = YaraPattern(
                pattern_type='condition',
                pattern_value='math.entropy(0, filesize) > 7.0',
                confidence=70.0,
                description='High entropy (possibly packed/encrypted)'
            )
            patterns.append(pattern)
        
        return patterns
    
    def _is_good_string_pattern(self, string_val: str) -> bool:
        """좋은 문자열 패턴인지 확인"""
        # 너무 일반적인 문자열 제외
        common_strings = {
            'microsoft', 'windows', 'system', 'program', 'version',
            'copyright', 'all rights reserved', 'error', 'warning'
        }
        
        if string_val.lower() in common_strings:
            return False
        
        # 특수문자만 있는 문자열 제외
        if not any(c.isalnum() for c in string_val):
            return False
        
        # 반복 문자열 제외
        if len(set(string_val)) < 3:
            return False
        
        return True
    
    def _calculate_string_confidence(self, string_val: str) -> float:
        """문자열 신뢰도 계산"""
        confidence = 50.0
        
        # 길이에 따른 보너스
        if len(string_val) > 20:
            confidence += 20.0
        elif len(string_val) > 10:
            confidence += 10.0
        
        # 의심스러운 키워드 보너스
        suspicious_keywords = [
            'backdoor', 'keylog', 'steal', 'crack', 'hack',
            'encrypt', 'decrypt', 'ransom', 'bitcoin'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in string_val.lower():
                confidence += 15.0
                break
        
        return min(confidence, 95.0)
    
    def _get_size_range(self, file_size: int) -> Tuple[int, int]:
        """파일 크기 범위 계산"""
        # ±20% 범위
        margin = int(file_size * 0.2)
        return (file_size - margin, file_size + margin)
    
    def _generate_conditions(self, patterns: List[YaraPattern], analysis: Dict[str, Any]) -> List[str]:
        """조건 생성"""
        conditions = []
        
        string_patterns = [p for p in patterns if p.pattern_type == 'string']
        hex_patterns = [p for p in patterns if p.pattern_type == 'hex']
        
        # 기본 조건: 적어도 몇 개의 패턴이 매칭되어야 함
        if string_patterns and hex_patterns:
            conditions.append(f"({len(string_patterns)} of ($string*)) and ({len(hex_patterns)} of ($hex*))")
        elif string_patterns:
            threshold = min(len(string_patterns), 3)
            conditions.append(f"{threshold} of ($string*)")
        elif hex_patterns:
            threshold = min(len(hex_patterns), 2)
            conditions.append(f"{threshold} of ($hex*)")
        
        # 파일 타입 조건
        file_type = analysis.get('file_type', 'UNKNOWN')
        if file_type == 'PE':
            conditions.append("uint16(0) == 0x5A4D")  # MZ header
        
        return conditions
    
    def _generate_tags(self, analysis: Dict[str, Any], malware_family: str = "") -> List[str]:
        """태그 생성"""
        tags = []
        
        # 파일 타입 태그
        file_type = analysis.get('file_type', 'UNKNOWN')
        if file_type != 'UNKNOWN':
            tags.append(file_type.lower())
        
        # 멀웨어 패밀리 태그
        if malware_family:
            tags.append(malware_family.lower())
        
        # 의심 활동 기반 태그
        indicators = analysis.get('suspicious_indicators', [])
        indicator_types = set(ind['type'] for ind in indicators)
        tags.extend(indicator_types)
        
        # 엔트로피 기반 태그
        entropy = analysis.get('entropy', 0.0)
        if entropy > 7.0:
            tags.append('packed')
        
        return list(set(tags))  # 중복 제거
    
    def _assess_severity(self, analysis: Dict[str, Any]) -> str:
        """심각도 평가"""
        score = 0
        
        # 의심 지표 개수
        indicators = analysis.get('suspicious_indicators', [])
        score += len(indicators) * 2
        
        # 엔트로피
        entropy = analysis.get('entropy', 0.0)
        if entropy > 7.5:
            score += 15
        elif entropy > 7.0:
            score += 10
        
        # 파일 크기 (매우 작거나 큰 파일)
        file_size = analysis.get('file_size', 0)
        if file_size < 1024 or file_size > 10*1024*1024:  # 1KB 미만 또는 10MB 초과
            score += 5
        
        # 심각도 결정
        if score >= 30:
            return 'critical'
        elif score >= 20:
            return 'high'
        elif score >= 10:
            return 'medium'
        else:
            return 'low'
    
    def format_yara_rule(self, yara_rule: YaraRule) -> str:
        """YARA 룰을 텍스트 형식으로 포맷"""
        
        # 헤더
        lines = [
            f"/*",
            f" * Rule: {yara_rule.rule_name}",
            f" * Description: {yara_rule.description}",
            f" * Author: {yara_rule.author}",
            f" * Date: {yara_rule.date}",
            f" * Version: {yara_rule.version}",
            f" * Malware Family: {yara_rule.malware_family or 'Unknown'}",
            f" * Severity: {yara_rule.severity}",
            f" */",
            f""
        ]
        
        # Import 섹션
        lines.extend([
            "import \"pe\"",
            "import \"math\"",
            ""
        ])
        
        # 룰 시작
        tags_str = ""
        if yara_rule.tags:
            tags_str = f" : {' '.join(yara_rule.tags)}"
        
        lines.append(f"rule {yara_rule.rule_name}{tags_str} {{")
        
        # Meta 섹션
        lines.extend([
            "    meta:",
            f"        description = \"{yara_rule.description}\"",
            f"        author = \"{yara_rule.author}\"",
            f"        date = \"{yara_rule.date}\"",
            f"        version = \"{yara_rule.version}\"",
            f"        severity = \"{yara_rule.severity}\""
        ])
        
        if yara_rule.malware_family:
            lines.append(f"        family = \"{yara_rule.malware_family}\"")
        
        # Strings 섹션
        lines.append("")
        lines.append("    strings:")
        
        string_counter = 1
        hex_counter = 1
        
        for pattern in yara_rule.patterns:
            if pattern.pattern_type == 'string':
                modifier = f" {pattern.modifier}" if pattern.modifier else ""
                lines.append(f"        $string{string_counter} = \"{pattern.pattern_value}\"{modifier}")
                string_counter += 1
            elif pattern.pattern_type == 'hex':
                hex_value = ' '.join([pattern.pattern_value[i:i+2] for i in range(0, len(pattern.pattern_value), 2)])
                lines.append(f"        $hex{hex_counter} = {{ {hex_value} }}")
                hex_counter += 1
        
        # Condition 섹션
        lines.append("")
        lines.append("    condition:")
        for condition in yara_rule.conditions:
            lines.append(f"        {condition}")
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def optimize_rule_with_ai(self, yara_rule: YaraRule, file_analysis: Dict[str, Any]) -> YaraRule:
        """AI를 사용하여 YARA 룰 최적화"""
        if not self.ai_config.is_valid():
            return yara_rule
        
        try:
            # AI 최적화 프롬프트 생성
            prompt = self._build_ai_optimization_prompt(yara_rule, file_analysis)
            
            # AI API 호출
            ai_response = self._call_ai_api(prompt)
            
            # AI 응답 파싱하여 룰 개선
            optimized_rule = self._parse_ai_optimization_response(ai_response, yara_rule)
            
            return optimized_rule
            
        except Exception as e:
            print(f"AI 기반 룰 최적화 오류: {str(e)}")
            return yara_rule
    
    def _build_ai_optimization_prompt(self, yara_rule: YaraRule, analysis: Dict[str, Any]) -> str:
        """AI 최적화 프롬프트 생성"""
        rule_text = self.format_yara_rule(yara_rule)
        
        return f"""
다음 YARA 룰을 분석하여 최적화 제안을 해주세요.

=== 현재 YARA 룰 ===
{rule_text}

=== 파일 분석 정보 ===
파일 타입: {analysis.get('file_type', 'Unknown')}
파일 크기: {analysis.get('file_size', 0)} bytes
엔트로피: {analysis.get('entropy', 0.0):.2f}
문자열 개수: {len(analysis.get('strings', []))}
의심 지표: {len(analysis.get('suspicious_indicators', []))}

다음 사항을 검토하여 JSON 형식으로 개선 제안을 해주세요:

1. 오탐 가능성이 높은 패턴 식별
2. 더 특징적인 패턴 제안
3. 조건문 개선 방안
4. 성능 최적화 방안
5. 룰 전체적인 품질 평가

응답 형식:
{{
  "optimization_suggestions": [
    {{
      "type": "pattern_improvement",
      "original": "원본 패턴",
      "suggested": "개선된 패턴",
      "reason": "개선 이유"
    }}
  ],
  "false_positive_risks": [
    {{
      "pattern": "위험한 패턴",
      "risk_level": "high/medium/low",
      "mitigation": "완화 방안"
    }}
  ],
  "overall_quality": {{
    "score": 85,
    "strengths": ["강점1", "강점2"],
    "weaknesses": ["약점1", "약점2"]
  }}
}}

YARA 룰 작성 전문가 관점에서 실무에서 사용 가능한 고품질 룰로 만들어주세요.
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
                    {"role": "system", "content": "너는 YARA 룰 작성 전문가야. 멀웨어 분석과 탐지 룰 최적화에 특화되어 있어."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"AI API 호출 오류: {str(e)}")
            return "{\"optimization_suggestions\": []}"
    
    def _parse_ai_optimization_response(self, ai_response: str, original_rule: YaraRule) -> YaraRule:
        """AI 최적화 응답 파싱"""
        try:
            # JSON 추출
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                ai_data = json.loads(json_str)
                
                # 최적화 제안 적용 (여기서는 기본적인 구현만)
                optimized_rule = original_rule
                
                # 패턴 개선 적용
                for suggestion in ai_data.get('optimization_suggestions', []):
                    if suggestion.get('type') == 'pattern_improvement':
                        self._apply_pattern_optimization(optimized_rule, suggestion)
                
                return optimized_rule
                
        except Exception as e:
            print(f"AI 최적화 응답 파싱 오류: {str(e)}")
        
        return original_rule
    
    def _apply_pattern_optimization(self, rule: YaraRule, suggestion: Dict[str, str]):
        """패턴 최적화 적용"""
        original = suggestion.get('original', '')
        suggested = suggestion.get('suggested', '')
        
        if not original or not suggested:
            return
        
        # 패턴 찾아서 교체
        for pattern in rule.patterns:
            if pattern.pattern_value == original:
                pattern.pattern_value = suggested
                pattern.confidence += 10.0  # 최적화된 패턴은 신뢰도 증가
                break

class YaraGeneratorTab(QWidget):
    """YARA 룰 생성 탭 UI"""
    
    def __init__(self):
        super().__init__()
        self.generator = YaraRuleGenerator()
        self.current_rule = None
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
        
        # 파일 선택 카드
        file_card = Card("파일 선택")
        
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("분석할 파일 경로를 선택하세요...")
        self.file_path_edit.setReadOnly(True)
        
        self.browse_btn = ActionButton("📁 찾아보기", "secondary")
        self.browse_btn.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(self.browse_btn)
        
        file_card.add_layout(file_layout)
        
        # 룰 설정 카드
        settings_card = Card("룰 설정")
        
        # 룰 이름
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("룰 이름:"))
        self.rule_name_edit = QLineEdit()
        self.rule_name_edit.setPlaceholderText("자동 생성됨")
        name_layout.addWidget(self.rule_name_edit)
        settings_card.add_layout(name_layout)
        
        # 멀웨어 패밀리
        family_layout = QHBoxLayout()
        family_layout.addWidget(QLabel("멀웨어 패밀리:"))
        self.family_combo = QComboBox()
        self.family_combo.addItems([
            "Unknown", "Ransomware", "Trojan", "Downloader", 
            "Backdoor", "Keylogger", "Adware", "Rootkit"
        ])
        family_layout.addWidget(self.family_combo)
        settings_card.add_layout(family_layout)
        
        # 생성 옵션
        options_card = Card("생성 옵션")
        
        self.ai_optimize_cb = QCheckBox("AI 기반 룰 최적화")
        self.ai_optimize_cb.setChecked(True)
        self.ai_optimize_cb.setToolTip("AI를 사용하여 생성된 룰을 최적화합니다")
        
        self.include_metadata_cb = QCheckBox("상세 메타데이터 포함")
        self.include_metadata_cb.setChecked(True)
        
        self.performance_mode_cb = QCheckBox("성능 최적화 모드")
        self.performance_mode_cb.setChecked(False)
        self.performance_mode_cb.setToolTip("더 빠른 매칭을 위해 룰을 최적화합니다")
        
        options_card.add_widget(self.ai_optimize_cb)
        options_card.add_widget(self.include_metadata_cb)
        options_card.add_widget(self.performance_mode_cb)
        
        # 버튼
        button_layout = QHBoxLayout()
        
        self.analyze_btn = ActionButton("🔍 파일 분석", "primary")
        self.analyze_btn.clicked.connect(self.analyze_file)
        
        self.generate_btn = ActionButton("🎯 룰 생성", "success")
        self.generate_btn.clicked.connect(self.generate_rule)
        self.generate_btn.setEnabled(False)
        
        self.clear_btn = ActionButton("🗑️ 지우기", "secondary")
        self.clear_btn.clicked.connect(self.clear_all)
        
        button_layout.addWidget(self.analyze_btn)
        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addStretch()
        
        layout.addWidget(file_card)
        layout.addWidget(settings_card)
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
        
        # 파일 분석 결과 탭
        self.analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(self.analysis_tab)
        
        self.analysis_text = QTextBrowser()
        self.analysis_text.setPlaceholderText("파일 분석 결과가 여기에 표시됩니다...")
        analysis_layout.addWidget(self.analysis_text)
        
        self.results_tabs.addTab(self.analysis_tab, "📊 파일 분석")
        
        # YARA 룰 탭
        self.rule_tab = QWidget()
        rule_layout = QVBoxLayout(self.rule_tab)
        
        # 룰 텍스트 영역
        self.rule_text = QTextEdit()
        self.rule_text.setPlaceholderText("생성된 YARA 룰이 여기에 표시됩니다...")
        self.rule_text.setFont(QFont("Consolas", 10))  # 모노스페이스 폰트
        rule_layout.addWidget(self.rule_text)
        
        # 룰 저장 버튼
        save_layout = QHBoxLayout()
        self.save_rule_btn = ActionButton("💾 룰 저장", "success")
        self.save_rule_btn.clicked.connect(self.save_rule)
        self.save_rule_btn.setEnabled(False)
        
        self.test_rule_btn = ActionButton("🧪 룰 테스트", "secondary")  
        self.test_rule_btn.clicked.connect(self.test_rule)
        self.test_rule_btn.setEnabled(False)
        
        save_layout.addWidget(self.save_rule_btn)
        save_layout.addWidget(self.test_rule_btn)
        save_layout.addStretch()
        
        rule_layout.addLayout(save_layout)
        
        self.results_tabs.addTab(self.rule_tab, "📝 YARA 룰")
        
        # 최적화 결과 탭
        self.optimization_tab = QWidget()
        opt_layout = QVBoxLayout(self.optimization_tab)
        
        self.optimization_text = QTextBrowser()
        self.optimization_text.setPlaceholderText("AI 최적화 결과가 여기에 표시됩니다...")
        opt_layout.addWidget(self.optimization_text)
        
        self.results_tabs.addTab(self.optimization_tab, "🧠 AI 최적화")
        
        layout.addWidget(self.results_tabs)
        
        return panel
    
    def browse_file(self):
        """파일 선택"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "분석할 파일 선택",
            "",
            "All Files (*.*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
            self.generate_btn.setEnabled(False)  # 새 파일 선택시 룰 생성 비활성화
    
    def analyze_file(self):
        """파일 분석"""
        file_path = self.file_path_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "파일 선택 필요", "분석할 파일을 먼저 선택해주세요.")
            return
        
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "파일 없음", "선택한 파일이 존재하지 않습니다.")
            return
        
        # 버튼 비활성화
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setText("🔄 분석 중...")
        
        try:
            # 파일 분석 실행
            self.file_analysis = self.generator.analyze_file_content(file_path)
            
            # 분석 결과 표시
            self._display_analysis_results()
            
            # 룰 생성 버튼 활성화
            self.generate_btn.setEnabled(True)
            
        except Exception as e:
            QMessageBox.critical(self, "분석 오류", f"파일 분석 중 오류가 발생했습니다:\n{str(e)}")
        
        finally:
            # 버튼 복원
            self.analyze_btn.setEnabled(True)
            self.analyze_btn.setText("🔍 파일 분석")
    
    def _display_analysis_results(self):
        """분석 결과 표시"""
        analysis = self.file_analysis
        
        html_content = "<h3>📊 파일 분석 결과</h3>"
        
        # 기본 정보
        html_content += f"""
        <div style="border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin: 8px 0;">
            <h4 style="color: #1890ff;">📁 기본 정보</h4>
            <ul>
                <li><strong>파일 크기:</strong> {analysis.get('file_size', 0):,} bytes</li>
                <li><strong>파일 타입:</strong> {analysis.get('file_type', 'Unknown')}</li>
                <li><strong>엔트로피:</strong> {analysis.get('entropy', 0.0):.2f}</li>
            </ul>
        </div>
        """
        
        # 추출된 문자열
        strings = analysis.get('strings', [])
        if strings:
            html_content += f"""
            <div style="border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin: 8px 0;">
                <h4 style="color: #1890ff;">🔤 추출된 문자열 (상위 10개)</h4>
                <ul>
            """
            
            for string_val in strings[:10]:
                escaped_string = string_val.replace('<', '&lt;').replace('>', '&gt;')
                html_content += f"<li><code>{escaped_string}</code></li>"
            
            html_content += f"""
                </ul>
                <p><small>총 {len(strings)}개 문자열 추출됨</small></p>
            </div>
            """
        
        # 16진수 패턴
        hex_patterns = analysis.get('hex_patterns', [])
        if hex_patterns:
            html_content += f"""
            <div style="border: 1px solid #d9d9d9; border-radius: 6px; padding: 12px; margin: 8px 0;">
                <h4 style="color: #1890ff;">🔢 16진수 패턴</h4>
                <ul>
            """
            
            for pattern in hex_patterns[:10]:
                html_content += f"<li><code>{pattern}</code></li>"
            
            html_content += """
                </ul>
            </div>
            """
        
        # 의심 지표
        indicators = analysis.get('suspicious_indicators', [])
        if indicators:
            html_content += f"""
            <div style="border: 1px solid #ffcccc; border-radius: 6px; padding: 12px; margin: 8px 0;">
                <h4 style="color: #ff4d4f;">🚨 의심 지표</h4>
                <ul>
            """
            
            for indicator in indicators[:10]:
                html_content += f"""
                <li>
                    <strong>{indicator['type'].upper()}:</strong> 
                    <code>{indicator['value']}</code>
                    <br><small>{indicator['description']}</small>
                </li>
                """
            
            html_content += f"""
                </ul>
                <p><small>총 {len(indicators)}개 의심 지표 탐지됨</small></p>
            </div>
            """
        
        self.analysis_text.setHtml(html_content)
    
    def generate_rule(self):
        """YARA 룰 생성"""
        if not hasattr(self, 'file_analysis'):
            QMessageBox.warning(self, "분석 필요", "먼저 파일을 분석해주세요.")
            return
        
        # 버튼 비활성화
        self.generate_btn.setEnabled(False)
        self.generate_btn.setText("🔄 생성 중...")
        
        try:
            # 설정 가져오기
            rule_name = self.rule_name_edit.text().strip()
            malware_family = self.family_combo.currentText()
            if malware_family == "Unknown":
                malware_family = ""
            
            # YARA 룰 생성
            self.current_rule = self.generator.generate_yara_rule(
                self.file_analysis, rule_name, malware_family
            )
            
            # AI 최적화 (옵션이 활성화된 경우)
            if self.ai_optimize_cb.isChecked():
                optimized_rule = self.generator.optimize_rule_with_ai(
                    self.current_rule, self.file_analysis
                )
                self.current_rule = optimized_rule
            
            # 룰 텍스트 생성 및 표시
            rule_text = self.generator.format_yara_rule(self.current_rule)
            self.rule_text.setPlainText(rule_text)
            
            # 버튼 활성화
            self.save_rule_btn.setEnabled(True)
            self.test_rule_btn.setEnabled(True)
            
            # 룰 탭으로 전환
            self.results_tabs.setCurrentIndex(1)
            
        except Exception as e:
            QMessageBox.critical(self, "생성 오류", f"YARA 룰 생성 중 오류가 발생했습니다:\n{str(e)}")
        
        finally:
            # 버튼 복원
            self.generate_btn.setEnabled(True)
            self.generate_btn.setText("🎯 룰 생성")
    
    def save_rule(self):
        """YARA 룰 저장"""
        if not self.current_rule:
            QMessageBox.warning(self, "룰 없음", "저장할 YARA 룰이 없습니다.")
            return
        
        # 파일 저장 다이얼로그
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "YARA 룰 저장",
            f"{self.current_rule.rule_name}.yar",
            "YARA Rules (*.yar);;All Files (*.*)"
        )
        
        if file_path:
            try:
                rule_text = self.rule_text.toPlainText()
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(rule_text)
                
                QMessageBox.information(self, "저장 완료", f"YARA 룰이 저장되었습니다:\n{file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "저장 오류", f"파일 저장 중 오류가 발생했습니다:\n{str(e)}")
    
    def test_rule(self):
        """YARA 룰 테스트"""
        QMessageBox.information(
            self, 
            "개발 예정", 
            "YARA 룰 테스트 기능은 추후 버전에서 구현될 예정입니다.\n\n"
            "현재는 생성된 룰을 저장한 후 별도 YARA 엔진으로 테스트해주세요."
        )
    
    def clear_all(self):
        """모든 내용 지우기"""
        self.file_path_edit.clear()
        self.rule_name_edit.clear()
        self.family_combo.setCurrentIndex(0)
        self.analysis_text.clear()
        self.rule_text.clear()
        self.optimization_text.clear()
        
        self.generate_btn.setEnabled(False)
        self.save_rule_btn.setEnabled(False)
        self.test_rule_btn.setEnabled(False)
        
        if hasattr(self, 'file_analysis'):
            delattr(self, 'file_analysis')
        
        self.current_rule = None