
import json
from pathlib import Path

import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parent

WINDOWS_LOGS = ROOT / "data" / "normalized_auth.jsonl"
WINDOWS_ALERTS = ROOT / "reports" / "windows_alerts.json"
ML_ALERTS = ROOT / "reports" / "ml_alerts.json"
SCORED_SESSIONS = ROOT / "reports" / "scored_sessions.json"

st.set_page_config(
    page_title="Mini SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Mini SOC — Security Operations Dashboard")
st.caption(
    "Windows authentication monitoring | Rule-based detection | "
    "Offline ML intrusion predictions"
)


# --------------------------------------------------
# Data loading
# --------------------------------------------------

@st.cache_data(ttl=10)
def load_jsonl(path):
    if not path.exists():
        return pd.DataFrame()

    records = []

    with path.open(encoding="utf-8-sig") as file:
        for line in file:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    return pd.DataFrame(records)


@st.cache_data(ttl=10)
def load_json(path):
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return {}


def get_records(data, preferred_key):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return data.get(preferred_key, data.get("alerts", []))

    return []


auth_df = load_jsonl(WINDOWS_LOGS)

windows_alerts = get_records(
    load_json(WINDOWS_ALERTS), "alerts"
)

scored_data = load_json(SCORED_SESSIONS)
ml_alert_data = load_json(ML_ALERTS)

# Prefer the latest inference report.
ml_results = get_records(scored_data, "results")

if not ml_results:
    ml_results = get_records(ml_alert_data, "alerts")


# --------------------------------------------------
# Prepare Windows event data
# --------------------------------------------------

if not auth_df.empty:
    if "timestamp" in auth_df.columns:
        auth_df["timestamp"] = pd.to_datetime(
            auth_df["timestamp"],
            utc=True,
            errors="coerce",
        )

    for column in ["target_user", "source_ip", "logon_type"]:
        if column in auth_df.columns:
            auth_df[column] = (
                auth_df[column].fillna("Unknown").astype(str)
            )


# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Select section",
    [
        "Overview",
        "Windows Authentication",
        "Security Alerts",
        "ML Detection",
    ],
)

st.sidebar.divider()
st.sidebar.subheader("Data source status")

st.sidebar.write(
    "Windows logs:",
    "🟢 Loaded" if not auth_df.empty else "🔴 Not available",
)

st.sidebar.write(
    "Windows alerts:",
    "🟢 Available" if windows_alerts else "⚪ No alerts",
)

st.sidebar.write(
    "Offline ML predictions:",
    "🟢 Available" if ml_results else "⚪ No predictions",
)

if st.sidebar.button("Refresh dashboard"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.caption(
    "ML predictions are based on the public dataset or supplied scoring "
    "files, not live Windows event classification."
)


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def show_event_filters(data):
    """Return Windows events after applying analyst filters."""

    if data.empty:
        return data

    filtered = data.copy()

    st.subheader("Investigation Filters")

    col1, col2 = st.columns(2)

    if "timestamp" in filtered.columns:
        valid_dates = filtered["timestamp"].dropna()

        if not valid_dates.empty:
            min_date = valid_dates.min().date()
            max_date = valid_dates.max().date()

            with col1:
                date_range = st.date_input(
                    "Event date range",
                    value=(min_date, max_date),
                    min_value=min_date,
                    max_value=max_date,
                )

            if isinstance(date_range, tuple) and len(date_range) == 2:
                start_date, end_date = date_range

                filtered = filtered[
                    filtered["timestamp"].dt.date.between(
                        start_date, end_date
                    )
                ]

    if "event_type" in filtered.columns:
        event_options = sorted(
            filtered["event_type"].dropna().unique().tolist()
        )

        with col2:
            selected_types = st.multiselect(
                "Authentication event type",
                event_options,
                default=event_options,
            )

        filtered = filtered[
            filtered["event_type"].isin(selected_types)
        ]

    col3, col4 = st.columns(2)

    if "target_user" in filtered.columns:
        account_options = sorted(
            filtered["target_user"].dropna().unique().tolist()
        )

        with col3:
            selected_accounts = st.multiselect(
                "Target account",
                account_options,
                default=account_options,
            )

        filtered = filtered[
            filtered["target_user"].isin(selected_accounts)
        ]

    if "logon_type" in filtered.columns:
        logon_options = sorted(
            filtered["logon_type"].dropna().unique().tolist()
        )

        with col4:
            selected_logon_types = st.multiselect(
                "Logon type",
                logon_options,
                default=logon_options,
            )

        filtered = filtered[
            filtered["logon_type"].isin(selected_logon_types)
        ]

    st.caption(f"{len(filtered)} events match your filters.")

    return filtered


def show_windows_investigation(alerts):
    st.subheader("Windows Alert Investigation")

    if not alerts:
        st.info("No Windows detection alerts are available.")
        return

    alert_df = pd.DataFrame(alerts)

    st.dataframe(alert_df, use_container_width=True)

    options = list(range(len(alerts)))

    selected_index = st.selectbox(
        "Select an alert to investigate",
        options,
        format_func=lambda i: (
            f"{alerts[i].get('alert_type', 'Windows alert')} | "
            f"{alerts[i].get('computer', 'Unknown computer')} | "
            f"{alerts[i].get('failure_count', 0)} failures"
        ),
        key="windows_alert_selection",
    )

    alert = alerts[selected_index]

    st.markdown("### Investigation Details")

    col1, col2, col3 = st.columns(3)

    col1.metric("Severity", alert.get("severity", "Unknown"))
    col2.metric("Failure Count", alert.get("failure_count", 0))
    col3.metric("Attribution", alert.get("attribution", "Unknown"))

    st.write("**Detection reason:**", alert.get("reason", "Not provided"))
    st.write("**Source IP:**", alert.get("source_ip") or "Unavailable")
    st.write("**Target account:**", alert.get("target_user") or "Unknown")
    st.write("**Computer:**", alert.get("computer") or "Unknown")
    st.write("**Logon type:**", alert.get("logon_type") or "Unknown")
    st.write("**First seen:**", alert.get("first_seen", "Unknown"))
    st.write("**Last seen:**", alert.get("last_seen", "Unknown"))
    st.write("**Status:**", alert.get("status", "Requires investigation"))

    st.caption(
        "An alert indicates repeated failed authentication events. "
        "It does not independently confirm malicious activity."
    )

    with st.expander("View raw alert JSON"):
        st.json(alert)


def show_ml_investigation(results):
    st.subheader("ML Prediction Investigation")

    if not results:
        st.info("No ML prediction results are available.")
        return

    predictions = pd.DataFrame(results)

    if "predicted_label" not in predictions.columns:
        st.warning("Prediction labels are missing.")
        return

    attacks = predictions[
        predictions["predicted_label"] == "attack"
    ].copy()

    if attacks.empty:
        st.info("No attack predictions in the current scoring report.")
        return

    st.dataframe(attacks, use_container_width=True)

    selected_index = st.selectbox(
        "Select a prediction to investigate",
        attacks.index.tolist(),
        format_func=lambda i: (
            f"{attacks.loc[i].get('session_id', 'Unknown session')} | "
            f"Probability: "
            f"{attacks.loc[i].get('attack_probability', 'Unknown')}"
        ),
        key="ml_alert_selection",
    )

    prediction = attacks.loc[selected_index].to_dict()

    st.markdown("### Prediction Details")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Prediction",
        prediction.get("predicted_label", "Unknown"),
    )

    col2.metric(
        "Attack Probability",
        prediction.get("attack_probability", "Unknown"),
    )

    col3.metric(
        "Severity",
        prediction.get("severity", "Unknown"),
    )

    st.write("**Session ID:**", prediction.get("session_id", "Unknown"))
    st.write("**Threshold:**", prediction.get("threshold", "Unknown"))

    st.warning(
        "This is an offline model prediction from the supplied session "
        "dataset. It is not a confirmed incident or a live Windows alert."
    )

    with st.expander("View raw prediction JSON"):
        st.json(prediction)


# --------------------------------------------------
# Overview
# --------------------------------------------------

if page == "Overview":

    st.subheader("Security Overview")

    total_events = len(auth_df)

    if not auth_df.empty and "event_type" in auth_df.columns:
        failed = int(
            (auth_df["event_type"] == "authentication_failure").sum()
        )
        successful = int(
            (auth_df["event_type"] == "authentication_success").sum()
        )
    else:
        failed = 0
        successful = 0

    ml_attack_count = sum(
        item.get("predicted_label") == "attack"
        for item in ml_results
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Windows Events", total_events)
    col2.metric("Failed Logons", failed)
    col3.metric("Windows Alerts", len(windows_alerts))
    col4.metric("Offline ML Predictions", ml_attack_count)

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Windows Authentication Distribution")

        if total_events:
            chart = pd.DataFrame({
                "Event Type": ["Successful", "Failed"],
                "Count": [successful, failed],
            }).set_index("Event Type")

            st.bar_chart(chart)
        else:
            st.info("No Windows authentication events available.")

    with right:
        st.subheader("Detection Summary")

        summary = pd.DataFrame({
            "Detection Source": [
                "Windows Rule Engine",
                "Offline ML Dataset",
            ],
            "Alerts": [
                len(windows_alerts),
                ml_attack_count,
            ],
        }).set_index("Detection Source")

        st.bar_chart(summary)

    st.subheader("Recent Windows Events")

    if not auth_df.empty:
        st.dataframe(
            auth_df.tail(10),
            use_container_width=True,
        )
    else:
        st.info("No Windows events available.")


# --------------------------------------------------
# Windows Authentication
# --------------------------------------------------

elif page == "Windows Authentication":

    st.subheader("Windows Authentication Monitoring")

    if auth_df.empty:
        st.warning("Windows authentication data is unavailable.")
    else:
        filtered_df = show_event_filters(auth_df)

        failed = (
            filtered_df["event_type"] == "authentication_failure"
        ).sum()

        successful = (
            filtered_df["event_type"] == "authentication_success"
        ).sum()

        col1, col2, col3 = st.columns(3)

        col1.metric("Filtered Events", len(filtered_df))
        col2.metric("Failed Logons", int(failed))
        col3.metric("Successful Logons", int(successful))

        st.subheader("Filtered Authentication Events")

        st.dataframe(
            filtered_df.sort_values(
                "timestamp",
                ascending=False,
                na_position="last",
            ),
            use_container_width=True,
        )

        st.subheader("Failed Logons by Account")

        failures = filtered_df[
            filtered_df["event_type"] == "authentication_failure"
        ]

        if not failures.empty:
            account_counts = (
                failures["target_user"].value_counts()
            )
            st.bar_chart(account_counts)
        else:
            st.info("No failed logons match the selected filters.")


# --------------------------------------------------
# Security Alerts
# --------------------------------------------------

elif page == "Security Alerts":

    st.subheader("Security Alert Center")

    col1, col2 = st.columns(2)

    col1.metric("Windows Rule Alerts", len(windows_alerts))

    col2.metric(
        "Offline ML Attack Predictions",
        sum(
            item.get("predicted_label") == "attack"
            for item in ml_results
        ),
    )

    st.divider()

    show_windows_investigation(windows_alerts)

    st.divider()

    show_ml_investigation(ml_results)


# --------------------------------------------------
# ML Detection
# --------------------------------------------------

elif page == "ML Detection":

    st.subheader("Machine Learning Intrusion Detection")

    if not ml_results:
        st.info(
            "No ML predictions available. Run the scoring script first."
        )
    else:
        ml_df = pd.DataFrame(ml_results)

        attack_count = (
            ml_df["predicted_label"] == "attack"
        ).sum()

        normal_count = (
            ml_df["predicted_label"] == "normal"
        ).sum()

        col1, col2, col3 = st.columns(3)

        col1.metric("Records Scored", len(ml_df))
        col2.metric("Attack Predictions", int(attack_count))
        col3.metric("Normal Predictions", int(normal_count))

        summary = pd.DataFrame({
            "Prediction": ["Attack", "Normal"],
            "Count": [attack_count, normal_count],
        }).set_index("Prediction")

        st.subheader("Prediction Distribution")
        st.bar_chart(summary)

        show_ml_investigation(ml_results)


# --------------------------------------------------
# Footer
# --------------------------------------------------

st.divider()

st.caption(
    "Mini SOC Prototype | Windows Rule-Based Detection | "
    "Offline Machine Learning Analysis"
)
