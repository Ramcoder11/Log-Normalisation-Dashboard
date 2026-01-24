import pandas as pd
import sys

# ==========================================================
# Smart column resolver (canonical → fuzzy → default)
# ==========================================================

def smart_get(df, canonical, keywords, default):
    if canonical in df.columns:
        return df[canonical]

    for col in df.columns:
        col_l = col.lower()
        for kw in keywords:
            if kw in col_l:
                return df[col]

    return pd.Series([default] * len(df), index=df.index)


# ==========================================================
# Detect input type
# ==========================================================

def detect_mode(df):
    """
    Detect whether input is:
    - RAW logs
    - ENRICHED / RISK dataset
    """
    enriched_indicators = {
        'risk_score', 'likelihood', 'business_impact', 'severity_score'
    }

    if enriched_indicators.intersection(set(df.columns)):
        return 'ENRICHED'
    return 'RAW'


# ==========================================================
# Normalization Logic
# ==========================================================

def normalize_evtx(df_raw: pd.DataFrame) -> pd.DataFrame:

    if df_raw is None or df_raw.empty:
        return pd.DataFrame()

    mode = detect_mode(df_raw)
    print(f"🔍 Detected input mode: {mode}")

    df = pd.DataFrame(index=df_raw.index)

    # ---------------------------
    # Asset
    # ---------------------------
    df['asset_id'] = (
        smart_get(
            df_raw,
            canonical='asset_id',
            keywords=['asset', 'host', 'computer', 'machine'],
            default='UNKNOWN'
        )
        .astype(str)
        .fillna('UNKNOWN')
    )

    df['asset_type'] = smart_get(
        df_raw,
        canonical='asset_type',
        keywords=['asset_type', 'source', 'platform'],
        default='generic_event'
    )

    # ---------------------------
    # Vulnerability / Event ID
    # ---------------------------
    df['vulnerability_id'] = (
        smart_get(
            df_raw,
            canonical='vuln_id',
            keywords=['vuln', 'event', 'rule', 'signature'],
            default='N/A'
        )
        .astype(str)
        .fillna('N/A')
    )

    # ---------------------------
    # Severity
    # ---------------------------
    sev_raw = smart_get(
        df_raw,
        canonical='severity',
        keywords=['severity', 'priority', 'level'],
        default=1
    )

    sev_num = pd.to_numeric(sev_raw, errors='coerce')

    if sev_num.isna().all():
        sev_map = {
            'info': 1,
            'information': 1,
            'warning': 3,
            'error': 6,
            'critical': 9,
            'fatal': 9
        }
        sev_num = sev_raw.astype(str).str.lower().map(sev_map)

    df['severity'] = sev_num.fillna(1).clip(1, 10).astype(int)

    # ---------------------------
    # Timestamp
    # ---------------------------
    df['last_detected'] = pd.to_datetime(
        smart_get(
            df_raw,
            canonical='timestamp',
            keywords=['time', 'date', 'utc', 'created'],
            default=None
        ),
        errors='coerce',
        utc=True
    )

    # ---------------------------
    # Owner / User (may not exist)
    # ---------------------------
    df['owner'] = (
        smart_get(
            df_raw,
            canonical='owner',
            keywords=['user', 'account', 'subject', 'login'],
            default='UNKNOWN'
        )
        .astype(str)
        .fillna('UNKNOWN')
    )

    # ==========================================================
    # Threat likelihood
    # ==========================================================
    if mode == 'ENRICHED':
        df['threat_likelihood'] = (
            pd.to_numeric(
                smart_get(
                    df_raw,
                    canonical='likelihood',
                    keywords=['likelihood', 'probability'],
                    default=1
                ),
                errors='coerce'
            )
            .fillna(1)
            .clip(1, 5)
            .astype(int)
        )
    else:
        event_freq = (
            df.groupby('vulnerability_id')['vulnerability_id']
            .transform('count')
        )

        df['threat_likelihood'] = (
            pd.qcut(
                event_freq.rank(method='first'),
                5,
                labels=[1, 2, 3, 4, 5]
            )
            .astype(int)
        )

    # ==========================================================
    # Business impact
    # ==========================================================
    if mode == 'ENRICHED':
        df['business_impact'] = (
            pd.to_numeric(
                smart_get(
                    df_raw,
                    canonical='business_impact',
                    keywords=['impact', 'criticality'],
                    default=1
                ),
                errors='coerce'
            )
            .fillna(1)
            .clip(1, 5)
            .astype(int)
        )
    else:
        df['business_impact'] = (
            (df['asset_id'] != 'UNKNOWN').astype(int) * 2 +
            (df['owner'] != 'UNKNOWN').astype(int) * 2 + 1
        ).clip(1, 5)

    # ==========================================================
    # Risk calculation
    # ==========================================================
    df['raw_risk'] = (
        df['severity'] *
        df['threat_likelihood'] *
        df['business_impact']
    )

    min_risk = df['raw_risk'].min()
    max_risk = df['raw_risk'].max()

    if max_risk > min_risk:
        df['normalized_risk'] = (
            (df['raw_risk'] - min_risk) /
            (max_risk - min_risk)
        ).round(4)
    else:
        df['normalized_risk'] = 0.0

    # ==========================================================
    # Confidence score
    # ==========================================================
    df['confidence'] = (
        (df['asset_id'] != 'UNKNOWN').astype(int) +
        (df['owner'] != 'UNKNOWN').astype(int) +
        df['last_detected'].notna().astype(int)
    ) / 3

    # ==========================================================
    # Final schema
    # ==========================================================
    return df[[
        'asset_id',
        'asset_type',
        'vulnerability_id',
        'severity',
        'threat_likelihood',
        'business_impact',
        'last_detected',
        'owner',
        'normalized_risk',
        'confidence'
    ]]


# ==========================================================
# Main Execution
# ==========================================================
if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("Usage: python Updated_Normalisation.py <input_csv>")
        raise SystemExit(1)

    input_file = sys.argv[1]

    try:
        df_raw = pd.read_csv(input_file, low_memory=False)
    except FileNotFoundError:
        print(f"❌ ERROR: {input_file} not found")
        raise SystemExit(1)

    print(f"Loaded input file: {input_file}")

    print("Input Columns Detected:")
    print(df_raw.columns.tolist())

    df_norm = normalize_evtx(df_raw)

    print("\n Normalized Output (first 10 rows):")
    print(df_norm.head(10))

    print("\n Risk Summary:")
    print(df_norm['normalized_risk'].describe())

    print("\n Confidence Summary:")
    print(df_norm['confidence'].describe())

    df_norm.to_csv('normalized_output.csv', index=False)
    print("\n Exported as normalized_output.csv")
