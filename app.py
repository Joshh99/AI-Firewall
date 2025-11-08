import streamlit as st
import re
import os
import requests
import time
from datetime import datetime
from dotenv import load_dotenv 

load_dotenv()

# Add this after your imports
@st.cache_data(show_spinner=False)
def test_api_connections():
    """Test if APIs are reachable"""
    try:
        # Test OpenRouter
        OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")
        if OPENROUTER_KEY:
            return "✅ APIs configured"
        else:
            return "❌ OPENROUTER_API_KEY missing"
    except Exception as e:
        return f"❌ API test failed: {str(e)}"
    
# Page configuration
st.set_page_config(
    page_title="AI Firewall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'issues' not in st.session_state:
    st.session_state.issues = []
if 'sanitized_prompt' not in st.session_state:
    st.session_state.sanitized_prompt = ""
if 'llm_response' not in st.session_state:
    st.session_state.llm_response = ""
if 'risk_level' not in st.session_state:
    st.session_state.risk_level = ""
if 'scan_complete' not in st.session_state:
    st.session_state.scan_complete = False
if 'blocked' not in st.session_state:
    st.session_state.blocked = False

# Detection functions
def detect_pii(prompt):
    """Detect PII in the prompt with proper redaction tracking"""
    issues = []
    redaction_map = []  # Track replacements to maintain positions
    
    # SSN Detection
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    for match in re.finditer(ssn_pattern, prompt):
        issues.append({
            'Type': 'SSN',
            'Snippet': match.group(),
            'Reason': 'Social Security Number detected',
            'Severity': 'HIGH',
            'start': match.start(),
            'end': match.end()
        })
        redaction_map.append({
            'start': match.start(),
            'end': match.end(),
            'replacement': '***[REDACTED: SSN]***'
        })
    
    # Email Detection
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for match in re.finditer(email_pattern, prompt):
        issues.append({
            'Type': 'EMAIL',
            'Snippet': match.group(),
            'Reason': 'Email address detected',
            'Severity': 'MEDIUM',
            'start': match.start(),
            'end': match.end()
        })
        redaction_map.append({
            'start': match.start(),
            'end': match.end(), 
            'replacement': '***[REDACTED: EMAIL]***'
        })
    
    # Phone Detection
    phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    for match in re.finditer(phone_pattern, prompt):
        issues.append({
            'Type': 'PHONE', 
            'Snippet': match.group(),
            'Reason': 'Phone number detected',
            'Severity': 'MEDIUM',
            'start': match.start(),
            'end': match.end()
        })
        redaction_map.append({
            'start': match.start(),
            'end': match.end(),
            'replacement': '***[REDACTED: PHONE]***'
        })
    
    # Credit Card Detection  
    card_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    for match in re.finditer(card_pattern, prompt):
        issues.append({
            'Type': 'CREDIT_CARD',
            'Snippet': match.group(),
            'Reason': 'Credit card number detected',
            'Severity': 'HIGH',
            'start': match.start(),
            'end': match.end()
        })
        redaction_map.append({
            'start': match.start(),
            'end': match.end(),
            'replacement': '***[REDACTED: CREDIT_CARD]***'
        })
    
    # Apply redactions in reverse order to maintain positions
    sanitized = prompt
    for redact in sorted(redaction_map, key=lambda x: x['start'], reverse=True):
        sanitized = (sanitized[:redact['start']] + 
                    redact['replacement'] + 
                    sanitized[redact['end']:])
    
    return issues, sanitized

def detect_secrets(prompt):
    """Simple but effective secrets detection"""
    issues = []
    
    # Secret keywords with context
    secret_keywords = [
        'api key', 'api_key', 'apikey', 'API_KEY',
        'password', 'passwd', 'pwd', 
        'token', 'access_token', 'bearer token',
        'secret', 'confidential', 'private key',
        'credential', 'login', 'auth'
    ]
    
    # Look for keywords followed by assignment patterns
    for keyword in secret_keywords:
        # Pattern: keyword followed by =, :, or space then some value
        pattern = r'\b' + re.escape(keyword) + r'\s*[:=]\s*[\'"`]?([^\s\'"`]{3,})[\'"`]?'
        for match in re.finditer(pattern, prompt, re.IGNORECASE):
            issues.append({
                'Type': 'SECRET',
                'Snippet': match.group(),
                'Reason': f'Secret assignment detected: {keyword}',
                'Severity': 'HIGH',
                'start': match.start(),
                'end': match.end()
            })
    
    # Also detect standalone secret-like strings
    standalone_patterns = [
        r'\b(sk-|pk-|AKIA|ghp_)[a-zA-Z0-9_\-]{10,}',
        r'\b[0-9a-fA-F]{32}\b',  # MD5-like
        r'\b[a-zA-Z0-9_\-]{20,50}\b'  # Long random strings
    ]
    
    # Common false positives to exclude
    false_positives = [
        'http', 'https', 'www.', '.com', '.org', '.net',
        'example', 'test', 'demo', 'sample'
    ]
    
    for pattern in standalone_patterns:
        for match in re.finditer(pattern, prompt):
            snippet = match.group()
            # Skip obvious false positives
            if not any(fp in snippet.lower() for fp in false_positives):
                issues.append({
                    'Type': 'SECRET',
                    'Snippet': snippet,
                    'Reason': 'Potential credential/secret string detected',
                    'Severity': 'MEDIUM',  # Lower severity for standalone strings
                    'start': match.start(),
                    'end': match.end()
                })
    
    return issues

def detect_toxic_content(prompt):
    """Detect toxic or harmful content"""
    issues = []
    toxic_keywords = ['kill', 'hate', 'attack', 'violence', 'murder', 'destroy']
    
    for keyword in toxic_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', prompt, re.IGNORECASE):
            issues.append({
                'Type': 'TOXIC',
                'Snippet': keyword,
                'Reason': f'Potentially harmful content detected',
                'Severity': 'HIGH'
            })
    
    return issues

def calculate_risk_level(issues):
    """Calculate overall risk level"""
    if not issues:
        return "NONE"
    
    high_count = sum(1 for i in issues if i['Severity'] == 'HIGH')
    medium_count = sum(1 for i in issues if i['Severity'] == 'MEDIUM')
    
    if high_count >= 2:
        return "HIGH"
    elif high_count >= 1:
        return "MEDIUM"
    elif medium_count >= 2:
        return "MEDIUM"
    elif medium_count >= 1:
        return "LOW"
    return "LOW"

def redact_prompt(text, issues):
    """Apply redactions to the prompt based on detected issues"""
    if not issues:
        return text
    
    # Sort issues by start position (reverse for safe replacement)
    redaction_map = []
    for issue in issues:
        if 'start' in issue and 'end' in issue:
            redaction_map.append({
                'start': issue['start'],
                'end': issue['end'],
                'replacement': f"***[REDACTED: {issue['Type']}]***"
            })
    
    # Apply redactions in reverse order
    sanitized = text
    for redact in sorted(redaction_map, key=lambda x: x['start'], reverse=True):
        sanitized = (sanitized[:redact['start']] + 
                    redact['replacement'] + 
                    sanitized[redact['end']:])
    
    return sanitized

def scan_prompt(prompt, detect_pii_enabled, detect_secrets_enabled, detect_toxic_enabled):
    """Main scanning function with proper redaction"""
    all_issues = []
    
    # Run enabled detections
    if detect_pii_enabled:
        pii_issues, _ = detect_pii(prompt)  # We'll handle redaction separately
        all_issues.extend(pii_issues)
    
    if detect_secrets_enabled:
        secret_issues = detect_secrets(prompt)
        all_issues.extend(secret_issues)
    
    if detect_toxic_enabled:
        toxic_issues = detect_toxic_content(prompt)
        all_issues.extend(toxic_issues)
    
    # Apply redaction to original prompt
    sanitized = redact_prompt(prompt, all_issues)
    risk_level = calculate_risk_level(all_issues)
    
    return all_issues, sanitized, risk_level

# Add this temporary debug function
def debug_secrets_detection():
    st.sidebar.subheader("🔍 Secrets Debug")
    test_cases = [
        "My API key is sk-abc123",
        "password = hunter2", 
        "token: ghp_xyz789",
        "api_key=1234567890",
        "Here's my secret: confidential info"
    ]
    
    for test in test_cases:
        if st.sidebar.button(f"Test: {test[:20]}..."):
            issues = detect_secrets(test)
            st.sidebar.write(f"Input: {test}")
            st.sidebar.write(f"Found {len(issues)} issues: {issues}")

def call_llm(sanitized_prompt, model_id):
    """Real LLM API call to OpenRouter"""
    try:
        OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")
        if not OPENROUTER_KEY:
            return "❌ Error: OPENROUTER_API_KEY not found in environment variables"
        
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://your-site.com",  # Required by OpenRouter
                "X-Title": "AI Firewall"  # Required by OpenRouter
            },
            json={
                "model": model_id,
                "messages": [
                    {
                        "role": "user", 
                        "content": sanitized_prompt
                    }
                ],
                "max_tokens": 500
            },
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            return f"❌ API Error: {response.status_code} - {response.text}"
            
    except Exception as e:
        return f"❌ Connection Error: {str(e)}"

def log_to_airia(original_prompt, sanitized_prompt, issues, model_used, response=None, blocked=False):
    """Real Airia logging"""
    try:
        from airia_logger import AiriaLogger
        logger = AiriaLogger()
        
        log_result = logger.log_interaction(
            user_input=original_prompt,
            sanitized_input=sanitized_prompt,
            detected_issues=issues,
            model_used=model_used,
            llm_response=response,
            was_blocked=blocked
        )
        
        return f"✅ Logged to Airia: {log_result}"
    except Exception as e:
        return f"❌ Airia Logging Failed: {str(e)}"

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Model selection
    model_option = st.selectbox(
        "LLM Model",
        ["openai/gpt-4o-mini", "openai/gpt-4o", "anthropic/claude-3-sonnet"],
        help="Select which LLM to use for generation"
    )
    
    st.divider()
    
    # Detection toggles
    st.subheader("Detection Settings")
    detect_pii_enabled = st.checkbox("PII Detection", value=True, help="Detect SSN, email, phone, credit cards")
    detect_secrets_enabled = st.checkbox("Secrets Detection", value=True, help="Detect API keys, passwords, tokens")
    detect_toxic_enabled = st.checkbox("Toxic Content", value=True, help="Detect harmful language")

        
    st.divider()
    
    # Quick Stats
    if st.session_state.scan_complete:
        st.subheader("📊 Scan Results")
        col1, col2 = st.columns(2)
        col1.metric("Issues", len(st.session_state.issues))
        col2.metric("Risk", st.session_state.risk_level)
        
        st.divider()
    
    # Demo prompts
    st.subheader("🧪 Example Prompts")
    if st.button("Clean Prompt", use_container_width=True):
        st.session_state.example_prompt = "Explain how transformer models work in NLP"
    if st.button("PII Example", use_container_width=True):
        st.session_state.example_prompt = "My SSN is 123-45-6789, email is john@example.com, and phone is 555-123-4567"
    if st.button("Secrets Example", use_container_width=True):
        st.session_state.example_prompt = "Here's my API key: sk-abc123 and password: hunter2. This is confidential."
    if st.button("Mixed Example", use_container_width=True):
        st.session_state.example_prompt = "SSN: 987-65-4321, email: admin@company.com, API token: ghp_xyz789, card: 4532-1234-5678-9010"
    
    st.divider()
    
    # About section
    st.subheader("ℹ️ About")
    st.info("""
    **AI Firewall** protects LLM applications by:
    
    - Detecting sensitive data (PII)
    - Identifying secrets & credentials  
    - Flagging toxic content
    - Logging to Airia for audit
    
    Built for Nova Hackathon 2025
    """)

    st.divider()
    st.caption(f"Status: {test_api_connections()}")

    # Temporary test section - add this before your main content
    if st.sidebar.checkbox("🧪 Enable Debug Mode", False):
        st.sidebar.subheader("Detection Testing")
        test_prompt = st.sidebar.text_area("Test Prompt", 
                                        "My SSN is 123-45-6789 and API key is sk-abc123")
        if st.sidebar.button("Test Detection"):
            issues, sanitized, risk = scan_prompt(test_prompt, True, True, True)
            st.sidebar.write("Issues:", issues)
            st.sidebar.write("Sanitized:", sanitized)
            st.sidebar.write("Risk:", risk)
    if st.sidebar.checkbox("🔍 Enable Secrets Debug", False):
        debug_secrets_detection()

# Main content
st.title("🛡️ AI Firewall")
st.markdown("**Real-time LLM Security & Governance** | Powered by Airia")
st.divider()

# Input section
st.subheader("📝 Enter Your Prompt")

# Handle example prompt loading
if 'example_prompt' in st.session_state:
    user_input = st.text_area(
        label="Prompt Input",
        value=st.session_state.example_prompt,
        height=150,
        placeholder="Type your prompt here...",
        label_visibility="collapsed"
    )
    del st.session_state.example_prompt
else:
    user_input = st.text_area(
        label="Prompt Input",
        height=150,
        placeholder="Type your prompt here... (Try including an SSN like 123-45-6789 or email)",
        label_visibility="collapsed"
    )

# Character count
if user_input:
    st.caption(f"Characters: {len(user_input)}")

st.divider()

# Action buttons
col1, col2, col3 = st.columns([2, 2, 1])

with col1:
    scan_button = st.button(
        "🔍 Scan Only", 
        type="primary",
        use_container_width=True
    )

with col2:
    scan_send_button = st.button(
        "🚀 Scan + Send to LLM",
        type="secondary",
        use_container_width=True
    )

with col3:
    if st.button("🗑️ Clear", use_container_width=True):
        st.session_state.issues = []
        st.session_state.sanitized_prompt = ""
        st.session_state.llm_response = ""
        st.session_state.risk_level = ""
        st.session_state.scan_complete = False
        st.session_state.blocked = False
        st.rerun()

# Handle Scan Only
if scan_button:
    if not user_input.strip():
        st.warning("⚠️ Please enter a prompt first!")
    else:
        with st.spinner("🔍 Scanning prompt..."):
            issues, sanitized, risk = scan_prompt(
                user_input, 
                detect_pii_enabled, 
                detect_secrets_enabled, 
                detect_toxic_enabled
            )
            
            st.session_state.issues = issues
            st.session_state.sanitized_prompt = sanitized
            st.session_state.risk_level = risk
            st.session_state.scan_complete = True
            st.session_state.llm_response = ""
            st.session_state.blocked = False
            
            # Log to Airia
            log_result = log_to_airia(user_input, sanitized, issues, model_option)
            st.toast(log_result)
            
        st.rerun()

# Handle Scan + Send
if scan_send_button:
    if not user_input.strip():
        st.warning("⚠️ Please enter a prompt first!")
    else:
        with st.spinner("🔍 Scanning prompt..."):
            issues, sanitized, risk = scan_prompt(
                user_input, 
                detect_pii_enabled, 
                detect_secrets_enabled, 
                detect_toxic_enabled
            )
            
            st.session_state.issues = issues
            st.session_state.sanitized_prompt = sanitized
            st.session_state.risk_level = risk
            st.session_state.scan_complete = True
            
            # Block if high risk
            if risk == "HIGH":
                st.session_state.blocked = True
                st.session_state.llm_response = ""
                log_result = log_to_airia(user_input, sanitized, issues, model_option, blocked=True)
                st.toast(log_result)
            else:
                st.session_state.blocked = False
                # Call REAL LLM
                with st.spinner("🤖 Generating response..."):
                    response = call_llm(sanitized, model_option)  # Real API call
                    st.session_state.llm_response = response
                    log_result = log_to_airia(user_input, sanitized, issues, model_option, response)
                    st.toast(log_result)
                    
        st.rerun()

# Results section
if st.session_state.scan_complete:
    st.divider()
    
    # Risk badge
    num_issues = len(st.session_state.issues)
    
    if st.session_state.blocked:
        st.error(f"🚫 **REQUEST BLOCKED** - High risk detected with {num_issues} critical issues")
    elif st.session_state.risk_level == "HIGH":
        st.error(f"🚨 **HIGH RISK** - {num_issues} issues detected")
    elif st.session_state.risk_level == "MEDIUM":
        st.warning(f"⚠️ **MEDIUM RISK** - {num_issues} issues detected")
    elif st.session_state.risk_level == "LOW":
        st.info(f"ℹ️ **LOW RISK** - {num_issues} issue(s) detected")
    else:
        st.success("✅ **NO ISSUES** - Prompt is safe!")
    
    # Issues table
    if st.session_state.issues:
        with st.expander("⚠️ Issues Detected", expanded=True):
            st.table(st.session_state.issues)
    
    # Sanitized prompt
    with st.expander("🔒 Sanitized Prompt", expanded=True):
        st.text_area(
            label="Sanitized",
            value=st.session_state.sanitized_prompt,
            height=150,
            disabled=True,
            label_visibility="collapsed"
        )
        st.caption("Sensitive data has been redacted for safe LLM processing")
    
    # LLM Response
    if st.session_state.llm_response:
        with st.expander("🤖 LLM Response", expanded=True):
            st.markdown(st.session_state.llm_response)
            st.caption(f"Generated at {datetime.now().strftime('%H:%M:%S')} | Logged to Airia")
    
    # Footer note
    st.divider()
    st.caption("🔐 All interactions are logged to Airia for security audit and governance")

