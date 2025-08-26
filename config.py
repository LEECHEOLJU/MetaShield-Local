# config.py - 보안 설정 관리
"""
MetaShield 애플리케이션의 보안 설정 및 환경 변수 관리
API 키와 같은 민감한 정보를 안전하게 관리합니다.
"""

import os
from dataclasses import dataclass
from typing import Optional, Tuple
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

@dataclass
class AIConfig:
    """Azure OpenAI API 설정"""
    endpoint: str = "https://cj-openai.openai.azure.com/"
    api_key: str = ""
    deployment: str = "cj-sec-analyst-gpt"
    api_version: str = "2024-12-01-preview"
    
    def __post_init__(self):
        """환경변수에서 API 키 로드"""
        if not self.api_key:
            self.api_key = os.getenv('AZURE_OPENAI_API_KEY', '')
        if not self.endpoint:
            self.endpoint = os.getenv('AZURE_OPENAI_ENDPOINT', self.endpoint)
        if not self.deployment:
            self.deployment = os.getenv('AZURE_OPENAI_DEPLOYMENT', self.deployment)
        if not self.api_version:
            self.api_version = os.getenv('AZURE_OPENAI_API_VERSION', self.api_version)
    
    def is_valid(self) -> bool:
        """API 설정 유효성 검사"""
        return bool(self.endpoint and self.api_key and self.deployment)

@dataclass
class DatabaseConfig:
    """데이터베이스 설정"""
    cve_db_path: str = "cve_cache_3_1.db"
    pattern_db_path: str = "pattern_dict.db"
    
    def get_full_path(self, db_name: str) -> str:
        """현재 디렉토리 기준 DB 경로 반환"""
        import os
        current_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(current_dir, db_name)

@dataclass
class ThreatIntelConfig:
    """위협 인텔리전스 API 설정"""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    
    def __post_init__(self):
        """환경변수에서 API 키 로드"""
        if not self.virustotal_api_key:
            self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        if not self.abuseipdb_api_key:
            self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY', '')
    
    def is_valid(self) -> bool:
        """위협 인텔리전스 설정 유효성 검사"""
        return bool(self.virustotal_api_key and len(self.virustotal_api_key) > 20 and 
                   self.abuseipdb_api_key and len(self.abuseipdb_api_key) > 20)

@dataclass
class JiraConfig:
    """JIRA API 설정"""
    url: str = "https://mcsoc.atlassian.net"
    api_user: str = ""
    api_token: str = ""
    
    def __post_init__(self):
        """환경변수에서 JIRA API 정보 로드"""
        if not self.api_user:
            self.api_user = os.getenv('JIRA_API_USER', '')
        if not self.api_token:
            self.api_token = os.getenv('JIRA_API_TOKEN', '')
        if not self.url:
            self.url = os.getenv('JIRA_URL', self.url)
    
    def is_valid(self) -> bool:
        """JIRA API 설정 유효성 검사"""
        return bool(self.url and self.api_user and self.api_token and len(self.api_token) > 20)

@dataclass
class UIConfig:
    """UI 설정"""
    window_min_width: int = 1200
    window_min_height: int = 800
    default_window_width: int = 1600
    default_window_height: int = 900
    
    # 최적화된 마진 설정
    tab_margin: int = 8  # 기존 24에서 8로 최적화
    card_padding: int = 16  # 기존 24에서 16으로 최적화 
    button_spacing: int = 8  # 기존 12에서 8로 최적화
    section_spacing: int = 12  # 기존 24에서 12로 최적화

# 전역 설정 인스턴스
ai_config = AIConfig()
db_config = DatabaseConfig() 
threat_intel_config = ThreatIntelConfig()
jira_config = JiraConfig()
ui_config = UIConfig()

def get_ai_config() -> AIConfig:
    """AI 설정 반환"""
    return ai_config

def get_db_config() -> DatabaseConfig:
    """데이터베이스 설정 반환"""
    return db_config

def get_threat_intel_config() -> ThreatIntelConfig:
    """위협 인텔리전스 설정 반환"""
    return threat_intel_config

def get_jira_config() -> JiraConfig:
    """JIRA 설정 반환"""
    return jira_config

def get_ui_config() -> UIConfig:
    """UI 설정 반환"""
    return ui_config

def validate_config() -> Tuple[bool, str]:
    """전체 설정 유효성 검사"""
    if not ai_config.is_valid():
        return False, "AI 설정이 유효하지 않습니다. API 키를 확인해주세요."
    
    return True, "설정이 정상입니다."

# 환경변수 설정 가이드
ENV_SETUP_GUIDE = """
🔐 API 키 보안 설정 가이드

방법 1: .env 파일 사용 (추천)
프로젝트 루트에 .env 파일 생성:

AZURE_OPENAI_API_KEY=your_api_key_here
AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=your-deployment-name
AZURE_OPENAI_API_VERSION=2024-12-01-preview
VIRUSTOTAL_API_KEY=your_vt_api_key_here
ABUSEIPDB_API_KEY=your_abuse_api_key_here
JIRA_URL=https://your-company.atlassian.net/rest/api/2/search
JIRA_API_USER=your_email@company.com
JIRA_API_TOKEN=your_jira_api_token_here

방법 2: 시스템 환경변수 설정 (Windows)
cmd에서 실행:
set AZURE_OPENAI_API_KEY=your_api_key_here
set VIRUSTOTAL_API_KEY=your_vt_api_key_here
set ABUSEIPDB_API_KEY=your_abuse_api_key_here
set JIRA_API_USER=your_email@company.com
set JIRA_API_TOKEN=your_jira_api_token_here

⚠️ 중요: .env 파일을 .gitignore에 추가하여 버전관리에서 제외하세요!
"""

if __name__ == "__main__":
    # 설정 테스트
    print("=== MetaShield 설정 확인 ===")
    print(f"AI 설정: {ai_config}")
    print(f"DB 설정: {db_config}")
    print(f"UI 설정: {ui_config}")
    
    is_valid, message = validate_config()
    print(f"설정 유효성: {message}")