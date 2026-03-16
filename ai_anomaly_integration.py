import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier
import numpy as np
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
# Common ports considered "normal" for most hosts
normal_ports = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 8080]

def detect_anomalies(open_ports_list):
    if not open_ports_list:
        print("No open ports to analyze.")
        return

    # Build feature set: port number + whether it's a known common port
    data = []
    for port, banner in open_ports_list:
        is_common = 1 if port in normal_ports else 0
        data.append([port, is_common])

    df = pd.DataFrame(data, columns=['port', 'is_common'])

    # Train Isolation Forest
    model = IsolationForest(contamination=0.2, random_state=42)
    df['anomaly'] = model.fit_predict(df[['port', 'is_common']])
    # -1 = anomaly, 1 = normal

    print("\n" + "=" * 60)
    print("AI ANOMALY ANALYSIS")
    print("=" * 60)

    for _, row in df.iterrows():
        port = int(row['port'])
        banner = open_ports_list[df.index.get_loc(_)][1]
        status = "⚠️  ANOMALOUS" if row['anomaly'] == -1 else "✅ Normal"
        print(f"Port {port:5} | {status} | Banner: {banner}")

    return df

# --- 2. Risk Scoring via Decision Tree ---
# Training data: [port, is_encrypted, is_commonly_exploited] → risk (0=Low, 1=Med, 2=High)
X_train = [
    [22, 1, 0],    # SSH - Low
    [80, 0, 1],    # HTTP - Medium
    [443, 1, 0],   # HTTPS - Low
    [21, 0, 1],    # FTP - High
    [23, 0, 1],    # Telnet - High
    [3389, 0, 1],  # RDP - High
    [3306, 0, 1],  # MySQL - High
    [445, 0, 1],   # SMB - High
    [8080, 0, 1],  # HTTP-Alt - Medium
    [53, 0, 0],    # DNS - Low
]
y_train = [0, 1, 0, 2, 2, 2, 2, 2, 1, 0]

risk_model = DecisionTreeClassifier()
risk_model.fit(X_train, y_train)

risk_labels = {0: "🟢 LOW", 1: "🟡 MEDIUM", 2: "🔴 HIGH"}
encrypted_ports = [22, 443, 465, 993, 995, 8443]
exploited_ports = [21, 23, 80, 445, 3306, 3389, 8080, 1433]

def score_risk(open_ports_list):
    print("\n" + "=" * 60)
    print("AI RISK ASSESSMENT")
    print("=" * 60)
    
    for port, banner in open_ports_list:
        is_enc = 1 if port in encrypted_ports else 0
        is_exp = 1 if port in exploited_ports else 0
        prediction = risk_model.predict([[port, is_enc, is_exp]])[0]
        risk = risk_labels[prediction]
        print(f"Port {port:5} | Risk: {risk} | Banner: {banner}")

# --- 3. Generative AI Report via Ollama ---
def generate_ai_report(target, open_ports_list):
    if not OLLAMA_AVAILABLE:
        print("\n[!] The 'ollama' Python package is not installed.")
        print("[!] Install it using: pip install ollama")
        return

    print("\n" + "=" * 60)
    print("AI SECURITY ANALYST REPORT (Ollama llama3)")
    print("=" * 60)
    print("Generating report... (This may take a moment)")

    port_summary = "\n".join([f"Port {p}: {b}" for p, b in open_ports_list])
    
    prompt = f"""
    You are a cybersecurity analyst. Below are open ports found on target {target}.
    Analyze them and provide:
    1. A brief risk assessment
    2. Which ports are most dangerous and why
    3. Recommended immediate actions

    Open Ports:
    {port_summary}
    """

    try:
        response = ollama.chat(
            model='llama3',
            messages=[{'role': 'user', 'content': prompt}]
        )
        print("\n" + response['message']['content'])
    except Exception as e:
        print(f"\n[!] Error communicating with Ollama: {e}")
        print("[!] Ensure you have run: ollama pull llama3")
        print("[!] And ensure the Ollama application is running in the background.")

# --- Master Execution Function ---
def analyze_scan_results(target, open_ports_list):
    if not open_ports_list:
        return
        
    detect_anomalies(open_ports_list)
    score_risk(open_ports_list)
    generate_ai_report(target, open_ports_list)
