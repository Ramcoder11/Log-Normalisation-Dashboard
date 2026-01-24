# normalize.py
import pandas as pd

def normalize_raw(df_raw: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize raw dataset to canonical schema for Risk Exposure Platform.
    Canonical schema:
    asset_id, asset_type, vulnerability_id, severity,
    threat_likelihood, business_impact, last_detected, owner, normalized_risk
    """

    df = pd.DataFrame()

    # Map raw columns to canonical fields
    df['asset_id'] = df_raw.get('device_name') or df_raw.get('hostname') or df_raw.get('asset_id')
    df['asset_type'] = df_raw.get('device_type') or df_raw.get('asset_type')
    df['vulnerability_id'] = df_raw.get('cve') or df_raw.get('vulnerability_id')
    df['severity'] = pd.to_numeric(df_raw.get('cvss_score') or df_raw.get('severity'), errors='coerce').fillna(0).astype(int)
    df['threat_likelihood'] = pd.to_numeric(df_raw.get('exploit_prob') or df_raw.get('threat_likelihood'), errors='coerce').fillna(1).astype(int)
    df['business_impact'] = pd.to_numeric(df_raw.get('impact') or df_raw.get('business_impact'), errors='coerce').fillna(1).astype(int)
    df['last_detected'] = pd.to_datetime(df_raw.get('detected_time') or df_raw.get('last_detected'), errors='coerce', utc=True)
    df['owner'] = df_raw.get('responsible_team') or df_raw.get('owner')
    
    # Placeholder for risk scoring
    df['normalized_risk'] = 0.0

    # Optional: reorder columns
    canonical_cols = [
        'asset_id', 'asset_type', 'vulnerability_id', 'severity',
        'threat_likelihood', 'business_impact', 'last_detected', 'owner', 'normalized_risk'
    ]
    df = df[canonical_cols]

    return df

if __name__ == '__main__':
    # Load your CSV file
    try:
        df_raw = pd.read_csv('evtx_data.csv')  # <-- CSV file
        df_normalized = normalize_raw(df_raw)
        print("Normalized Dataset:")
        print(df_normalized.head())
        df_normalized.to_csv('normalized_output.csv', index=False)
        print("Normalized CSV exported as 'normalized_output.csv'")
    except FileNotFoundError:
        print("CSV file 'evtx_data.csv' not found. Place it in the same folder.")
