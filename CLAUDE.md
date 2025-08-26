# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
MetaShield is a comprehensive security analysis platform built with PyQt5, providing CVE vulnerability search, AI-powered security analysis, pattern analysis repository, and threat intelligence capabilities for security professionals.

## Development Commands

### Running the Application
```bash
python MetaShield_main.py
```

### Dependencies
The project uses Python 3.7+ with the following key libraries:
- PyQt5 for GUI framework
- requests for HTTP API communication
- sqlite3 for local database
- openai for Azure OpenAI API client
- pandas for data manipulation
- matplotlib for visualization
- deep_translator for translation services

### Database Files
- `cve_cache_3_1.db` - SQLite database for CVE data caching
- `pattern_dict.db` - SQLite database for pattern analysis storage

## Architecture Overview

### Core Application Structure
- **MetaShield_main.py** (699 lines) - Main application window with 4 tabs and AI analysis functionality
- **nvd_cve_checker_Pro.py** (800+ lines) - CVE vulnerability search and NVD API integration
- **pattern_dict_tab.py** (600+ lines) - Pattern analysis repository with JIRA integration
- **comprehensive_report.py** (376 lines) - Comprehensive security report generation

### UI System
- **modern_ui_style.py** - Centralized CSS-like styling system with modern color palette (#1890ff accent, #fafafa background)
- **advanced_ui_components.py** - Reusable UI components (Card, PrimaryButton, SearchInput, ModernTable, etc.)

### Configuration & Security
- **config.py** - Centralized configuration management with environment variable support
- **prompts.py** - AI prompt templates for security analysis
- **guide_tab.py** - User documentation and usage guides

## Key API Integrations

### Azure OpenAI Configuration
```python
# Configuration loaded from environment variables
AIConfig:
  endpoint: "https://cj-openai.openai.azure.com/"
  deployment: "cj-sec-analyst-gpt"
  api_version: "2024-12-01-preview"
```

### External APIs
- **NVD API** - CVE vulnerability data retrieval
- **VirusTotal API** - File/IP reputation checking
- **AbuseIPDB API** - IP reputation analysis
- **JIRA API** - Security event ticket integration

## Security Best Practices
- All API keys are managed through environment variables via config.py
- No hardcoded secrets in source code
- Secure configuration validation in AIConfig, ThreatIntelConfig, JiraConfig classes
- Database uses local SQLite for caching sensitive security data

## Main Application Features

### 1. CVE Vulnerability Search (취약점 검색)
- Multi-CVE input support with newline separation
- Real-time NVD API queries with local caching
- CVSS scoring and impact analysis
- Excel/CSV export functionality

### 2. Pattern Analysis (패턴 분석)
- Security detection pattern template management
- AI-powered analysis report generation
- JIRA ticket import and categorization
- Search, favorites, and rating system

### 3. AI Security Analysis (AI 분석)
- Azure OpenAI-powered payload analysis
- IOC extraction (IP, domain, URL, file hash)
- Threat intelligence queries
- Real-time analysis progress display

### 4. User Guide (가이드)
- Comprehensive usage documentation
- Security analysis best practices
- Report writing guidelines

## UI Layout Requirements

### Recent UI Improvement Tasks
Based on CLAUDE.md user requirements:

1. **CVE Search Tab Improvements**:
   - CVE input field: 1/3 of screen width
   - Remove favorites and session history features
   - Expand archive section vertically
   - Reduce search results table height
   - Expand vulnerability detail information area vertically

2. **Pattern Analysis Tab Layout**:
   - Move "새로작성" and "AI 초안" buttons to bottom work area
   - Reduce button sizes
   - Significantly expand analysis content area vertically

3. **AI Analysis Tab Complete Restructure**:
   - Split screen horizontally in half
   - Left: Large payload input area
   - Right: Large analysis results area
   - Top: Tab-style analysis options (IOC extraction, intelligence extraction)
   - Add comprehensive report generation button

## Code Style Guidelines
- Follow existing Korean localization throughout the interface
- Use modern_ui_style.py constants for consistent styling
- Leverage advanced_ui_components.py for UI elements
- Maintain separation of concerns between UI and business logic
- Follow dataclass pattern for configuration classes

## Database Schema Notes
```sql
-- CVE Cache
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    data TEXT,  -- JSON format CVE data
    timestamp TEXT
)

-- Pattern Analysis
CREATE TABLE patterns (
    id INTEGER PRIMARY KEY,
    name TEXT,           -- Detection name
    description TEXT,    -- Analysis content
    category TEXT,       -- Classification
    severity TEXT,       -- Severity level
    is_favorite INTEGER, -- Favorite flag
    created_at TEXT
)
```

## Important File Locations
- Configuration: `config.py:19-30` (AIConfig class)
- Main window setup: `MetaShield_main.py:16-50`
- CVE search logic: `nvd_cve_checker_Pro.py`
- AI analysis: `MetaShield_main.py` (ModernAnalysisTab class)
- UI components: `advanced_ui_components.py`
- Styling: `modern_ui_style.py`