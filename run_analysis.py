#############################################################################################################################
#############################################################################################################################
################################                    Author: MarkCyber                      ##################################
################################               https://github.com/markcyber                ##################################
#############################################################################################################################
#############################################################################################################################
import os
import h2o
import random
import json
import glob
import uuid
import yaml
import smtplib
import ssl
import markdown
import xgboost as xgb
from h2o.automl import H2OAutoML
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# --- Helper Function for CVE Parsing ---
def parse_cve_data(cve_items):
    """Parses CVE items from the NVD JSON feed, prioritizing CVSS scores."""
    records = []
    for item in cve_items:
        cve = item.get('cve', {})
        cve_id = cve.get('id', '')
        description = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), '')
        metrics = cve.get('metrics', {})
        base_score, severity, attack_vector, version = None, None, None, None
        for v_key, v_name in [('cvssMetricV31', '3.1'), ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0')]:
            if v_key in metrics:
                metric_data = metrics[v_key][0].get('cvssData', {})
                base_score = metric_data.get('baseScore')
                severity = metric_data.get('baseSeverity') if 'baseSeverity' in metric_data else metric_data.get('severity')
                attack_vector = metric_data.get('attackVector')
                version = v_name
                break
        records.append({
            'cve_id': cve_id, 'description': description,
            'base_score': float(base_score) if base_score is not None else 0.0,
            'severity': str(severity).title() if severity else 'Unknown',
            'attack_vector': attack_vector, 'cvss_version': version
        })
    return pd.DataFrame(records)

# --- Pipeline Functions ---

def load_configuration(config_path='config.yaml'):
    """Loads settings from the YAML config file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found at: {config_path}")
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    print("Config loaded successfully.")
    return config

def load_cve_data(config):
    """Loads and parses all NVD JSON files."""
    data_dir = config['paths']['nvd_data_dir']
    json_files = glob.glob(os.path.join(data_dir, 'nvdcve-*.json'))
    all_cve_items = []
    print(f"Found {len(json_files)} NVD JSON files to process...")
    for file_path in json_files:
        print(f"  - Loading {os.path.basename(file_path)}")
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_data = json.load(f)
            all_cve_items.extend(cve_data.get('vulnerabilities', []))
    df_cve = parse_cve_data(all_cve_items)
    print(f"Successfully Loaded and parsed a total of {len(df_cve)} CVEs.")
    return df_cve

def simulate_data(df_cve, config):
    """Simulates assets, logs, and enriches with ExploitDB."""
    # Load ExploitDB CVEs
    try:
        exploitdb_path = config['paths']['exploitdb_csv']
        df_exploitdb_sim = pd.read_csv(exploitdb_path)
        df_exploitdb_sim['cve_id'] = df_exploitdb_sim['codes'].str.extract(r'(CVE-\d{4}-\d{4,})')
        df_exploitdb_sim.dropna(subset=['cve_id'], inplace=True)
        exploitable_cves_list = df_exploitdb_sim['cve_id'].unique().tolist()
        exploitable_cves_list = list(set(exploitable_cves_list) & set(df_cve['cve_id']))
        print(f"Loaded {len(exploitable_cves_list)} exploitable CVEs for simulation.")
    except FileNotFoundError:
        exploitable_cves_list = []
        print("ExploitDB file not found, simulation will not include exploitable CVEs.")

    # Simulate Assets
    num_assets = config['simulation']['num_assets']
    num_cve_samples = config['simulation']['num_cve_samples']
    asset_ids = [f"A{i:03}" for i in range(num_assets)]
    sample_cves = df_cve['cve_id'].dropna().sample(min(num_cve_samples, len(df_cve)), random_state=42).tolist()
    asset_records = []
    for i, asset in enumerate(asset_ids):
        assigned_cves = random.sample(sample_cves, k=random.randint(1, 4))
        if exploitable_cves_list:
            assigned_cves.append(random.choice(exploitable_cves_list))
        for cve in assigned_cves:
            asset_records.append({'asset_id': asset, 'hostname': f"host{i:03}.mil", 'owner': f"owner{random.randint(1, 10)}", 'cve_id': cve})
    df_assets = pd.DataFrame(asset_records)

    # Simulate Internet Exposure
    exposure_records = [{'asset_id': asset_id, 'exposed_to_internet': random.choice([True, False])} for asset_id in asset_ids]
    df_exposure = pd.DataFrame(exposure_records)
    df_assets['exposed_to_internet'] = df_assets['asset_id'].map(dict(zip(df_exposure['asset_id'], df_exposure['exposed_to_internet'])))

    # Simulate Logs
    log_events = []
    for _, row in df_assets.iterrows():
        if random.random() < 0.2:
            is_exploit = False
            cve_details = df_cve[df_cve['cve_id'] == row['cve_id']]
            if not cve_details.empty and row['exposed_to_internet'] and cve_details.iloc[0]['base_score'] > 7.0:
                if random.random() < 0.5:
                    is_exploit = True
            event_type = 'exploit_attempt' if is_exploit else random.choice(['scan', 'unauthorized_access', 'dos'])
            log_events.append({'timestamp': datetime.now() - timedelta(days=random.randint(0, 30)), 'asset_id': row['asset_id'], 'cve_id': row['cve_id'], 'event_type': event_type, 'source_ip': f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"})
    df_logs = pd.DataFrame(log_events)
    df_logs.to_csv(config['paths']['log_output'], index=False)
    print(f" Generated {len(df_logs)} mock log events.")
    return df_assets, df_logs, exploitable_cves_list

def train_model(df_assets, df_logs, df_cve, exploitable_cves_list, config):
    """Prepares data and trains the H2O AutoML model."""
    exploit_logs = df_logs[df_logs['event_type'] == 'exploit_attempt'][['asset_id', 'cve_id']].drop_duplicates()
    exploit_logs['is_exploited'] = 1
    df_model = df_assets.merge(df_cve, on='cve_id', how='left')
    df_model = df_model.merge(exploit_logs, on=['asset_id', 'cve_id'], how='left')
    df_model['is_exploited'] = df_model['is_exploited'].fillna(0).astype(int)
    df_model['description_len'] = df_model['description'].str.len()
    df_model['num_cves_on_asset'] = df_model.groupby('asset_id')['cve_id'].transform('count')
    df_model['has_public_exploit'] = df_model['cve_id'].isin(exploitable_cves_list)

    col_types = {'severity': 'enum', 'attack_vector': 'enum', 'cvss_version': 'enum', 'owner': 'enum', 'has_public_exploit': 'enum', 'exposed_to_internet': 'enum'}
    hf = h2o.H2OFrame(df_model, column_types=col_types)
    target = 'is_exploited'
    hf[target] = hf[target].asfactor()
    predictors = ['base_score', 'severity', 'attack_vector', 'cvss_version', 'exposed_to_internet', 'owner', 'description_len', 'num_cves_on_asset', 'has_public_exploit']
    train, test = hf.split_frame(ratios=[0.8], seed=42)
    project_name = f"CVE_Exploit_Prediction_{uuid.uuid4().hex[:8]}"
    aml = H2OAutoML(
    max_runtime_secs=180, seed=1, sort_metric="AUC",
    project_name=project_name, nfolds=0, balance_classes=True,
    include_algos=["XGBoost", "GBM", "GLM", "DRF", "DeepLearning"] # <-- Add this line
    )
    print(f"\nTraining model with project name: {project_name}")
    aml.train(x=predictors, y=target, training_frame=train, validation_frame=test)
    print("\n--- H2O AutoML Leaderboard ---")
    print(aml.leaderboard.head(rows=10))
    best_model = aml.leader
    model_path = h2o.save_model(best_model, path=config['paths']['model_dir'], force=True)
    print(f"\n Best model saved to: {model_path}")
    return best_model, df_model, hf

def generate_report(best_model, df_model, hf, config):
    """Generates predictions, attack paths, the report, and sends email."""
    # Make Predictions
    print("\n--- Generating predictions for all assets ---")
    predictions = best_model.predict(hf)
    df_model['predicted_exploit_likelihood'] = predictions['p1'].as_data_frame(use_multi_thread=True)
    print("Predictions generated successfully.")
    
    # Find Attack Paths
    def find_attack_paths(df_group):
        initial_access = df_group[(df_group['attack_vector'] == 'NETWORK') & (df_group['has_public_exploit'])]
        priv_escalation = df_group[(df_group['attack_vector'] == 'LOCAL') & (df_group['base_score'] >= 7.0)]
        if not initial_access.empty and not priv_escalation.empty:
            ia_cve = initial_access.iloc[0]['cve_id']
            pe_cve = priv_escalation.iloc[0]['cve_id']
            return f"Initial Access via {ia_cve}, then Privilege Escalation via {pe_cve}."
        return "No simple path detected."
    attack_paths = df_model.groupby('asset_id').apply(find_attack_paths, include_groups=False)
    df_model['attack_path'] = df_model['asset_id'].map(attack_paths)
    
    # Define Report Helper Functions
    def map_risk_level(score):
        if score >= 0.90: return "Critical"
        elif score >= 0.70: return "High"
        elif score >= 0.40: return "Medium"
        else: return "Low"
    def generate_risk_explanation(row):
        reasons = []
        if row['has_public_exploit']: reasons.append("has a known public exploit")
        if row['exposed_to_internet']: reasons.append("is on an internet-exposed asset")
        if row['base_score'] >= 9.0: reasons.append("has a critical CVSS base score")
        if not reasons: return "Risk driven by other learned patterns."
        return "High risk because it " + " and ".join(reasons) + "."
    def generate_remediation(row):
        actions = ["Patch system to remediate this CVE."]
        if row['has_public_exploit']: actions[0] = "Patch IMMEDIATELY as a public exploit is available."
        if row['exposed_to_internet']: actions.append("If patching is delayed, restrict network access.")
        return " ".join(actions)

    # --- NEW: Get Variable Importance from the best model ---
    varimp_df = best_model.varimp(use_pandas=True)
    varimp_table = varimp_df[['variable', 'percentage']].to_markdown(index=False)

    # Prepare Data for Report
    df_priority_list = df_model.sort_values('predicted_exploit_likelihood', ascending=False)
    df_priority_list['AI_Risk_Level'] = df_priority_list['predicted_exploit_likelihood'].apply(map_risk_level)
    df_priority_list['Explanation'] = df_priority_list.apply(generate_risk_explanation, axis=1)
    df_priority_list['Remediation'] = df_priority_list.apply(generate_remediation, axis=1)
    top_10_risky = df_priority_list.head(10)
    initial_access_vulns = df_model[(df_model['attack_vector'] == 'NETWORK') & (df_model['has_public_exploit'])][['hostname', 'cve_id', 'base_score']].drop_duplicates()
    priv_esc_vulns = df_model[(df_model['attack_vector'] == 'LOCAL') & (df_model['base_score'] >= 7.0)][['hostname', 'cve_id', 'base_score']].drop_duplicates()
    
    # Create and Save Visualization
    top_5_hosts = df_model.groupby('hostname')['predicted_exploit_likelihood'].sum().nlargest(5)
    plt.figure(figsize=(10, 6)); sns.barplot(x=top_5_hosts.values, y=top_5_hosts.index, hue=top_5_hosts.index, palette='viridis', legend=False)
    plt.title('Top 5 Riskiest Hosts', fontsize=14); plt.xlabel('Sum of Predicted Exploit Likelihood'); plt.ylabel('Hostname'); plt.tight_layout()
    plot_path = config['paths']['plot_output']
    plt.savefig(plot_path); print(f"--- Visualization saved to: {plot_path} ---")

    # Build Markdown Report
    top_10_md_list = ""
    for index, row in top_10_risky.iterrows():
        top_10_md_list += f"\n**{row['hostname']} - {row['cve_id']}**\n  - **AI Risk Level:** {row['AI_Risk_Level']}\n  - **Explanation:** {row['Explanation']}\n  - **Recommended Action:** {row['Remediation']}\n"
    report_md = f"""# CVE Risk Report\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n## Executive Summary\n* **Total Assets:** {df_model['asset_id'].nunique()}\n* **Total Vulns:** {len(df_model)}\n* **Critical Vulns:** {len(df_model[df_model['severity'] == 'Critical'])}\n* **Assets with Public Exploits:** {df_model[df_model['has_public_exploit'] == True]['asset_id'].nunique()}\n\n---\n##  Top 5 Riskiest Hosts\n![Top 5 Riskiest Hosts]({os.path.basename(plot_path)})\n\n---\n## Top 10 Highest-Risk Vulns\n{top_10_md_list}\n---\n## What the AI Learned (Feature Importance)\nThis table shows the factors the model found most influential in predicting risk.\n\n{varimp_table}\n\n---\n## Initial Access\n{initial_access_vulns.to_markdown(index=False) if not initial_access_vulns.empty else 'None found.'}\n\n---\n## Privilege Escalation\n{priv_esc_vulns.to_markdown(index=False) if not priv_esc_vulns.empty else 'None found.'}"""
    report_path = config['paths']['report_output']
    with open(report_path, "w") as f:
        f.write(report_md)
    print(f"--- Markdown report saved to: {report_path} ---")

        # Send Email
    email_cfg = config['email']

    # Check if email sending is enabled
    if not email_cfg.get('enabled', True):
        print("\n--- Email skipped: Disabled in config.yaml. ---")
        return

    sender_email = email_cfg['sender']
    receiver_email = email_cfg['recipient']
    gmail_app_password = email_cfg['password']

    if "your_email" in sender_email or "YOUR_APP_PASSWORD" in gmail_app_password:
        print("\n--- Email skipped: Placeholders not filled in config.yaml. ---")
        return

    msg = MIMEMultipart(); msg['Subject'] = f"Daily CVE Risk Report - {datetime.now().strftime('%Y-%m-%d')}"; msg['From'] = sender_email; msg['To'] = receiver_email
    msg.attach(MIMEText(markdown.markdown(report_md), 'html'))
    with open(plot_path, 'rb') as fp:
        img = MIMEImage(fp.read()); img.add_header('Content-Disposition', 'attachment', filename=os.path.basename(plot_path)); msg.attach(img)
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, gmail_app_password); server.sendmail(sender_email, receiver_email, msg.as_string())
        print("--- Email report sent successfully! ---")
    except Exception as e:
        print(f"\n--- Email sending failed: {e} ---")

def main():
    """Main function to run the entire pipeline."""
    # Initialize H2O
    h2o.init(max_mem_size="4G", nthreads=-1)
    
    # Create necessary directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)

    # Run the pipeline
    config = load_configuration()
    df_cve = load_cve_data(config)
    df_assets, df_logs, exploitable_cves = simulate_data(df_cve, config)
    best_model, df_model, hf = train_model(df_assets, df_logs, df_cve, exploitable_cves, config)
    generate_report(best_model, df_model, hf, config)

    # Shutdown H2O
    h2o.cluster().shutdown()
    print("\n--- Pipeline complete. H2O cluster shut down. ---")

if __name__ == "__main__":
    main()
