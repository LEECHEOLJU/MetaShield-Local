import json
import re
from datetime import datetime
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextBrowser, QPushButton, QHBoxLayout, QMessageBox
from PyQt6.QtCore import Qt

class ComprehensiveReportGenerator:
    """종합 보고서 생성 클래스"""
    
    def __init__(self, parent=None):
        self.parent = parent
        self.report_data = {}
        
    def extract_cve_codes(self, text):
        """텍스트에서 CVE 코드 추출"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, text, re.IGNORECASE)
        return list(set(cves))  # 중복 제거
    
    def get_cve_details_from_cache(self, cve_id):
        """캐시에서 CVE 상세정보 가져오기"""
        try:
            from nvd_cve_checker_Pro import DBManager
            db = DBManager()
            data = db.get_cache(cve_id)
            if data:
                return self.parse_cve_for_report(cve_id, data)
            return None
        except Exception as e:
            print(f"CVE 캐시 조회 오류: {e}")
            return None
    
    def parse_cve_for_report(self, cve_id, data):
        """CVE 데이터를 보고서용으로 파싱"""
        try:
            desc = next((d["value"] for d in data.get("descriptions", []) if d["lang"] == "en"), "설명 없음")
            score = data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            vector = data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("vectorString", "")
            cwe = next((w["description"][0]["value"] for w in data.get("weaknesses", []) if w["description"]), "N/A")
            
            severity = "Critical" if float(score) >= 9 else "High" if float(score) >= 7 else "Medium" if float(score) >= 4 else "Low"
            
            return {
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": score,
                "severity": severity,
                "vector": vector,
                "cwe": cwe
            }
        except:
            return None
    
    def generate_comprehensive_report(self, payload, ai_analysis, ioc_data, threat_intel_data):
        """종합 보고서 생성"""
        
        # 1. AI 분석에서 CVE 추출
        cve_codes = self.extract_cve_codes(ai_analysis)
        
        # 2. CVE 상세정보 수집
        cve_details = []
        for cve in cve_codes:
            details = self.get_cve_details_from_cache(cve)
            if details:
                cve_details.append(details)
        
        # 3. 종합 데이터 구성
        comprehensive_data = {
            "payload": payload[:500],  # 페이로드 일부만
            "ai_analysis": ai_analysis,
            "cve_details": cve_details,
            "ioc_data": ioc_data,
            "threat_intel": threat_intel_data,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 4. Azure OpenAI로 최종 보고서 생성
        final_report = self.generate_final_report_with_ai(comprehensive_data)
        
        return final_report
    
    def generate_final_report_with_ai(self, data):
        """Azure OpenAI를 사용한 최종 보고서 생성"""
        
        # CVE 정보 포맷팅
        cve_list = []
        cve_detail_section = ""
        if data["cve_details"]:
            for cve in data["cve_details"]:
                cve_list.append(f"{cve['cve_id']} (CVSS {cve['cvss_score']})")
                cve_detail_section += f"""
▸ {cve['cve_id']}
  - CVSS Score: {cve['cvss_score']} ({cve['severity']})
  - CWE: {cve['cwe']}
  - 설명: {cve['description'][:150]}...
"""
        
        # IOC 상세 정보 포맷팅
        ioc_detail = ""
        if data['ioc_data'].get('ips'):
            ioc_detail += f"\n▸ IP 주소: {', '.join(data['ioc_data']['ips'][:5])}"
        if data['ioc_data'].get('domains'):
            ioc_detail += f"\n▸ 도메인: {', '.join(data['ioc_data']['domains'][:5])}"
        if data['ioc_data'].get('urls'):
            ioc_detail += f"\n▸ URL: {', '.join(data['ioc_data']['urls'][:3])}"
        
        # 위협 인텔리전스 파싱 (HTML에서 주요 정보 추출)
        threat_intel_summary = self.parse_threat_intel(data.get('threat_intel', ''))
        
        prompt = f"""
너는 관제업체(MSSP)의 시니어 보안 분석가이며, 고객사 담당자에게 보안 위협 보고서를 제공하는 역할을 맡고 있습니다.
아래 데이터를 바탕으로 "고객사 담당자용 보안 위협 종합 보고서"를 작성해줘.

[원본 Payload 일부]
{data['payload'][:300]}

[1차 AI 분석 결과]
{data['ai_analysis'][:800]}

[탐지된 CVE 취약점 상세]
{cve_detail_section if cve_detail_section else "특정 CVE 미탐지"}

[IOC 추출 결과]
- IP: {len(data['ioc_data'].get('ips', []))}개
- 도메인: {len(data['ioc_data'].get('domains', []))}개
- URL: {len(data['ioc_data'].get('urls', []))}개
- 해시: {len(data['ioc_data'].get('hashes', []))}개
{ioc_detail}

[위협 인텔리전스 조회 결과]
{threat_intel_summary}

다음 형식으로 고객사 담당자용 보고서를 작성해줘:

🚨 보안 위협 탐지 보고서

📊 탐지 현황 요약
발생일시: {data['timestamp']}
관제업체: 메타넷티플랫폼
고객사: [고객사명]

▶ 위협 개요
- 공격 유형: (예: RCE, SQL Injection 등)
- 탐지 패턴: (탐지 시그니처/패턴명)
- 위험도: ⚠️ Critical / High / Medium / Low
- 공격 출발지: (IP/국가)
- 대상 시스템: (고객사 시스템)

▶ 탐지 지표 (IOC)
- 악성 IP: {len(data['ioc_data'].get('ips', []))}개 탐지
- 악성 도메인: {len(data['ioc_data'].get('domains', []))}개 탐지  
- 악성 URL: {len(data['ioc_data'].get('urls', []))}개 탐지
- 파일 해시: {len(data['ioc_data'].get('hashes', []))}개 탐지

▶ 관련 취약점
{', '.join(cve_list) if cve_list else '특정 CVE 미확인'}

▶ 위협 인텔리전스 결과
    - VirusTotal: (악성 판정 비율)
    - AbuseIPDB: (신뢰도 점수)
    - 평판 조회: (결과 요약)

---

🔍 상세 분석

1. 공격 분석
    - 공격 시나리오 및 동작 원리
    - 사용된 공격 기법 (MITRE ATT&CK 매핑)
    - 공격자 의도 및 목적

2. 영향도 평가
    - 현재 피해 상황
    - 잠재적 위험성
    - 확산 가능성

3. 기술적 세부사항
    - Payload 분석
    - 네트워크 행위 분석
    - 시스템 영향 분석

---

✅ 대응 권고사항

즉시 조치사항
    1. (구체적 차단 조치)
    2. (격리 및 모니터링)
    3. (증거 보전)

단기 개선사항 (1주 내)
    1. (패치 적용)
    2. (정책 업데이트)
    3. (추가 점검)

중장기 개선사항
    1. (보안 체계 강화)
    2. (프로세스 개선)

---

**본 보고서는 관제 시점 기준이며, 추가 분석에 따라 내용이 업데이트될 수 있습니다.
문의사항: Metanet SOC Center (02-000-0000)
-------

보고서는 고객사 담당자가 신속하게 상황을 파악하고 대응할 수 있도록 명확하고 실무적으로 작성해줘.
통계와 수치를 우선 제시하고, 이후 상세 분석을 제공해줘.
"""
        
        try:
            from openai import AzureOpenAI
            from config import get_ai_config
            
            # Azure OpenAI 설정 (config.py에서 로드)
            ai_config = get_ai_config()
            if not ai_config.is_valid():
                return "❌ AI 설정이 유효하지 않습니다. .env 파일의 AZURE_OPENAI_API_KEY를 확인해주세요."
            
            client = AzureOpenAI(
                api_key=ai_config.api_key,
                api_version=ai_config.api_version,
                azure_endpoint=ai_config.endpoint,
            )
            
            response = client.chat.completions.create(
                model=ai_config.deployment,
                messages=[
                    {"role": "system", "content": "당신은 관제업체(MSSP)의 시니어 보안 분석가입니다. 고객사에 명확하고 실무적인 보고서를 작성합니다."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_completion_tokens=2000,
                top_p=1.0,
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            # AI 실패시 기본 템플릿 반환
            return self.generate_fallback_report(data)
        
    def parse_threat_intel(self, threat_intel_html):
        """위협 인텔리전스 HTML에서 주요 정보 추출"""
        import re
        
        summary = "위협 인텔리전스 조회 결과:\n"
        
        # VirusTotal 정보 추출
        vt_match = re.search(r'VirusTotal[^<]*?(\d+)개 위험', threat_intel_html)
        if vt_match:
            summary += f"- VirusTotal: {vt_match.group(1)}개 엔진에서 악성 탐지\n"
        
        # AbuseIPDB 정보 추출
        abuse_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)[^<]*?(안전|주의|위험)[^<]*?(\d+)%', threat_intel_html)
        if abuse_matches:
            for ip, risk, confidence in abuse_matches[:3]:  # 최대 3개만
                summary += f"- {ip}: {risk} (신뢰도 {confidence}%)\n"
        
        if "조회 결과 없음" in threat_intel_html or not threat_intel_html:
            summary = "위협 인텔리전스 조회 결과: 데이터 없음"
        
        return summary
    
    def generate_fallback_report(self, data):
        """AI 실패시 기본 보고서 템플릿"""
        
        report = f"""
# 🔒 종합 보안 분석 보고서

**생성 시각:** {data['timestamp']}

## 1. 📊 위협 요약
보안 이벤트가 탐지되어 종합 분석을 수행하였습니다.

## 2. 🎯 공격 분석
### 기본 분석 내용
{data['ai_analysis'][:500]}

## 3. 🛡️ 기술적 상세 분석
### 탐지된 CVE 취약점
"""
        
        if data["cve_details"]:
            for cve in data["cve_details"]:
                report += f"""
- **{cve['cve_id']}**
  - CVSS Score: {cve['cvss_score']} ({cve['severity']})
  - CWE: {cve['cwe']}
"""
        else:
            report += "\n- 특정 CVE 취약점이 탐지되지 않았습니다.\n"
        
        report += f"""

### IOC (Indicators of Compromise)
- IP 주소: {len(data['ioc_data'].get('ips', []))}개 탐지
- 도메인: {len(data['ioc_data'].get('domains', []))}개 탐지
- URL: {len(data['ioc_data'].get('urls', []))}개 탐지
- 해시값: {len(data['ioc_data'].get('hashes', []))}개 탐지

## 4. 📈 위험도 평가
상세 위험도 평가가 필요합니다.

## 5. ✅ 대응 방안
- 탐지된 IOC에 대한 차단 정책 적용
- 관련 시스템 모니터링 강화
- 추가 분석 수행

## 6. 📋 권고사항
- 보안 정책 검토 및 업데이트
- 직원 보안 교육 강화
- 정기적인 취약점 점검 수행
"""
        
        return report


class ComprehensiveReportDialog(QDialog):
    """종합 보고서 표시 다이얼로그"""
    
    def __init__(self, report_content, parent=None):
        super().__init__(parent)
        self.setWindowTitle("📊 종합 보안 분석 보고서")
        self.setGeometry(200, 100, 1000, 700)
        
        layout = QVBoxLayout()
        
        # 보고서 표시 브라우저
        self.browser = QTextBrowser()
        self.browser.setPlainText(report_content)
        layout.addWidget(self.browser)
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.copy_btn = QPushButton("📋 복사")
        self.copy_btn.clicked.connect(self.copy_report)
        
        self.save_btn = QPushButton("💾 저장")
        self.save_btn.clicked.connect(self.save_report)
        
        self.close_btn = QPushButton("닫기")
        self.close_btn.clicked.connect(self.close)
        
        button_layout.addWidget(self.copy_btn)
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        self.report_content = report_content
    
    def copy_report(self):
        """보고서 복사"""
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.report_content)
        QMessageBox.information(self, "복사 완료", "보고서가 클립보드에 복사되었습니다.")
    
    def save_report(self):
        """보고서 저장"""
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "보고서 저장", 
            f"보안분석보고서_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            "Markdown Files (*.md);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.report_content)
                QMessageBox.information(self, "저장 완료", f"보고서가 저장되었습니다:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "저장 오류", f"파일 저장 중 오류 발생:\n{str(e)}")