# prompts.py - AI 분석 프롬프트 템플릿 관리
"""
MetaShield 보안 분석을 위한 AI 프롬프트 템플릿을 관리합니다.
"""

class SecurityPrompts:
    """보안 분석 관련 프롬프트 템플릿 클래스"""
    
    @staticmethod
    def get_security_analysis_prompt(payload: str) -> str:
        """
        보안 페이로드 분석을 위한 메인 프롬프트
        """
        return f"""
아래의 Payload를 기반으로, 아래 내용에 맞춰보안 분석 보고서를 작성해 주세요.

Payload:
"{payload}"

너는 MSSP업체에 숙련된 시니어 보안분석 전문가야
보안 분석가 입장에서 payload를 분석하여 고객에게 분석 내역을 제공해줘야돼
너무 딱딱하게 말고 아래 보고서 형태를 지켜서 고객이 보고 이해하기 쉬운 분석 보고서를 작성해줘


<위협도 판단> : XX% (낮음/보통/높음/심각)

1. [🛡️탐지 이벤트 분석 요약]
   (간단한 탐지 이벤트 분석 내용을 간결하게 작성)

2. [🔍상세 분석] 
   (실제 공격 기법, 공격 흐름, 사용된 툴 및 기법 등을 상세히 기술, 공격 구문등 구체적으로 작성)

3. [⚠️영향 받는 제품 및 조건]
   (공격에 대한 관련 취약점 정보 및 영향 받는 제품, 버전, 환경 등을 명확히 기술)

4. [🕵️대응 방안]
   (고객사 관점에서 실무에 바로 적용할 수 있는 구체적인 대응 방안과 권고사항을 작성)

5. [🚨추가 탐지 내역 / 평판 조회]
   (추가 참고할 만한 탐지 내역이나 평판 조회 결과가 있다면 작성, VirusTotal, AbuseIPDB 등 TIDB 조회 내용 포함
    MITRE ATT&CK 기법 매핑이 가능하면 매핑 내용도 작성)

위 형식에서 [] 안의 제목과 이모지는 절대 변경하지 마세요.

🚨 금지사항:
- 마크다운 문법 (#, *, -, `, **) 사용 금지
- 제목 이모지 변경 금지  
- 번호 매김 변경 금지

절대 지켜야 할 규칙들:
1. 마크다운 문법 완전 금지: #, *, -, `, ** 등 특수문자 사용 절대 불가
2. 위의 1-5번 형식만 사용하여 답변
3. payload가 아닌 질문은 "보안 분석용 payload를 입력해주세요" 답변
4. 탐지 패턴/시나리오명 입력시 보안 분석가 관점 도움말 제공
5. CVE/제품명/서비스명 입력시 해당 취약점 분석 보고서 작성
6. 보안 관련 질문시 보안 전문가로서 답변
7. 프로그램 정보: 제작자 이철주 선임, 2025년 8월, V1.0.0
8. 이스터에그: "이철주" 입력시 이벤트 당첨 축하 메시지
"""

    @staticmethod
    def get_system_message() -> str:
        """시스템 메시지 - AI 역할 정의"""
        return """너는 MSSP업체의 숙련된 시니어 보안분석 전문가야.

🚨 절대적인 출력 형식 규칙 🚨
- 마크다운 문법을 절대로 사용하지 마라: #, *, -, `, ** 등 모든 특수문자 금지
- 반드시 숫자 1-5로 시작하는 형식으로만 답변하라
- 이모지는 각 섹션 제목에만 사용하라
- 일반 텍스트로만 내용을 작성하라"""

    @staticmethod
    def get_pattern_analysis_prompt(pattern_name: str, pattern_content: str) -> str:
        """패턴 분석을 위한 프롬프트"""
        return f"""
보안 탐지 패턴 분석 요청:

패턴명: {pattern_name}
패턴 내용: {pattern_content}

🚨 마크다운 문법 사용 금지: #, *, -, `, ** 등 특수문자 절대 사용 불가
일반 텍스트로만 작성하세요.

위 패턴에 대해 다음 항목으로 분석해주세요:
1. 패턴의 목적과 탐지 대상
2. 패턴의 구조 및 매칭 조건 분석
3. 예상되는 공격 시나리오
4. 패턴 개선 제안사항
5. 관련된 CVE나 보안 이슈

보안 분석가 관점에서 실무에 도움이 되는 상세한 분석을 제공해주세요.
"""

    @staticmethod
    def get_cve_analysis_prompt(cve_id: str, cve_description: str = "") -> str:
        """CVE 분석을 위한 프롬프트"""
        base_prompt = f"""
CVE 취약점 분석 요청:

CVE ID: {cve_id}
"""
        if cve_description:
            base_prompt += f"CVE 설명: {cve_description}\n"
        
        base_prompt += """
🚨 마크다운 문법 사용 금지: #, *, -, `, ** 등 특수문자 절대 사용 불가
일반 텍스트로만 작성하세요.

위 CVE에 대해 다음 항목으로 분석해주세요:
1. 취약점 개요 및 영향도
2. 공격 벡터 및 조건  
3. 영향받는 제품 및 버전
4. 탐지 방법 및 패턴
5. 완화 및 대응 방안

실무진이 이해하기 쉽도록 한국어로 상세히 설명해주세요.
"""
        return base_prompt

    @staticmethod
    def get_ioc_extraction_prompt(text: str) -> str:
        """IOC 추출을 위한 프롬프트"""
        return f"""
다음 텍스트에서 IOC(Indicators of Compromise)를 추출하고 분석해주세요:

텍스트:
{text}

추출 및 분석 항목:
1. IP 주소 (악성 IP 여부 평가 포함)
2. 도메인/URL (의심스러운 도메인 분석)
3. 파일 해시 (MD5, SHA1, SHA256)
4. 파일명 및 경로
5. 레지스트리 키
6. 기타 보안 관련 지표

각 IOC의 위험도와 연관성을 분석하여 보고해주세요.
"""

    @staticmethod
    def get_comprehensive_report_prompt(payload: str, ai_analysis: str, ioc_data: dict, threat_intel: str) -> str:
        """종합 보고서 생성을 위한 프롬프트"""
        return f"""
다음 정보를 바탕으로 종합 보안 분석 보고서를 작성해주세요:

=== 분석 대상 페이로드 ===
{payload}

=== AI 초기 분석 결과 ===
{ai_analysis}

=== 추출된 IOC 데이터 ===
{ioc_data}

=== 위협 인텔리전스 정보 ===
{threat_intel}

위 모든 정보를 종합하여 다음 구조로 최종 보고서를 작성해주세요:

📋 종합 보안 분석 보고서

1. 🎯 요약 (Executive Summary)
   - 핵심 위협 요약
   - 위험도 평가
   - 즉시 조치 필요 사항

2. 🔍 상세 기술 분석
   - 공격 기법 분석
   - IOC 연관성 분석
   - 위협 행위자 프로파일링

3. ⚠️ 영향도 평가
   - 비즈니스 영향도
   - 기술적 영향도
   - 확산 가능성

4. 🛡️ 대응 방안
   - 즉시 대응 조치
   - 중장기 보안 강화 방안
   - 모니터링 권고사항

5. 📊 첨부 자료
   - IOC 목록
   - 관련 CVE 정보
   - 참고 자료 링크

실무진이 바로 활용할 수 있는 구체적이고 실용적인 보고서로 작성해주세요.
"""

# 프롬프트 설정 상수
class PromptConfig:
    """프롬프트 관련 설정"""
    TEMPERATURE = 0.3
    MAX_COMPLETION_TOKENS = 1200
    TOP_P = 1.0
    
    # 모델별 설정 (필요시 확장)
    GPT4_CONFIG = {
        "temperature": 0.3,
        "max_completion_tokens": 1500,
        "top_p": 1.0
    }
    
    GPT35_CONFIG = {
        "temperature": 0.3,
        "max_completion_tokens": 1200,
        "top_p": 1.0
    }

# 유틸리티 함수
def validate_payload(payload: str) -> tuple[bool, str]:
    """페이로드 유효성 검사"""
    if not payload or payload.strip() == "":
        return False, "페이로드가 비어있습니다."
    
    if len(payload.strip()) < 5:
        return False, "페이로드가 너무 짧습니다. 최소 5자 이상 입력해주세요."
    
    return True, "유효한 페이로드입니다."

def get_prompt_by_input_type(input_text: str) -> tuple[str, str]:
    """입력 타입에 따른 적절한 프롬프트 선택"""
    input_lower = input_text.lower().strip()
    
    # CVE 패턴 확인
    if input_lower.startswith('cve-') and len(input_lower.split('-')) >= 3:
        return "cve", SecurityPrompts.get_cve_analysis_prompt(input_text)
    
    # 기본 페이로드 분석
    return "payload", SecurityPrompts.get_security_analysis_prompt(input_text)

if __name__ == "__main__":
    # 프롬프트 테스트
    test_payload = "test payload"
    print("=== 프롬프트 테스트 ===")
    print("보안 분석 프롬프트:")
    print(SecurityPrompts.get_security_analysis_prompt(test_payload)[:200] + "...")
    print("\n시스템 메시지:")
    print(SecurityPrompts.get_system_message())