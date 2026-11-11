# Phase 23 – Predictive Security Analytics

## 1. Overview

Phase 23 adds predictive security analytics to the AI-Powered Cyber Digital
Twin for Linux Infrastructure. It analyses historical SSH security events
and infrastructure metrics to identify trends, estimate future risk,
forecast metric behaviour, classify suspicious attack patterns and generate
predictive alerts.

The analytics are read-only. Predictive alerts are generated as data and
are not automatically delivered through email or Telegram.

## 2. Objectives

- Analyse historical SSH security events.
- Identify changes in suspicious login activity.
- Estimate future SSH-related security risk.
- Forecast CPU, memory and disk metric trends.
- Classify suspicious SSH source patterns.
- Correlate predictions into predictive alerts.
- Display results on the authenticated dashboard.

## 3. Architecture

PostgreSQL Database
        |
        v
Historical Security and Infrastructure Data
        |
        v
Backend Analytics Modules
        |
        +--> Historical Security Analysis
        |
        +--> SSH Attack Trend Analysis
        |
        +--> Predictive Risk Scoring
        |
        +--> Infrastructure Anomaly Forecasting
        |
        +--> Attack Pattern Prediction
        |
        +--> Predictive Alert Generation
        |
        v
Protected FastAPI Endpoints
        |
        v
Authenticated Dashboard
        |
        v
Predictive Analytics Tables and Chart

## 4. Implementation Modules

### 4.1 Historical Security Data Analysis

File: backend/analytics/security_history.py

Analyses historical SSH events and provides:
- Event totals by type.
- Suspicious event trends.
- Top suspicious source IP addresses.
- Daily, weekly and monthly grouping.
- Configurable analysis periods from 1 to 90 days.

### 4.2 SSH Attack Trend Analysis

File: backend/analytics/security_history.py

Compares the current period with the preceding equal-length period.

It calculates percentage changes in failed logins, invalid-user attempts
and suspicious activity, and classifies the direction as increasing,
decreasing, stable or new activity.

### 4.3 Predictive Risk Scoring

File: backend/analytics/predictive_risk.py

Uses a linear trend projection based on current and previous periods.

The predicted failed-login and invalid-user counts are used in a weighted
risk score. The score is limited to 0–100 and assigned a risk level:

- LOW: below 20
- MEDIUM: 20–49
- HIGH: 50–79
- CRITICAL: 80–100

This is a transparent heuristic score, not a calibrated probability.

### 4.4 Infrastructure Anomaly Forecasting

File: backend/analytics/anomaly_forecast.py

Analyses daily CPU, memory and disk averages over a 30-day lookback.

It compares the latest three observed daily averages with the preceding
three observations and projects the next daily observation.

Historical standard deviation is used to estimate an anomaly threshold.
At least six observed days are required for each metric.

### 4.5 Attack Pattern Prediction

File: backend/analytics/attack_pattern_predictor.py

Groups failed-login and invalid-user events by source IP.

It classifies patterns as:
- INVALID_USER_ENUMERATION
- POSSIBLE_BRUTE_FORCE
- REPEATED_FAILED_LOGIN
- LOW_VOLUME_SUSPICIOUS_ACTIVITY

It also calculates historical event frequency and a heuristic recurrence
estimate.

### 4.6 Predictive Alert Generation

File: backend/analytics/predictive_alerts.py

Combines predictive risk, infrastructure anomaly forecasts and attack
pattern analysis.

It can generate:
- PREDICTIVE_SECURITY_RISK
- PREDICTED_INFRASTRUCTURE_ANOMALY
- PREDICTED_ATTACK_PATTERN

The module returns predictive alerts with severity and descriptions.
Notification status is NOT_SENT. It does not send email or Telegram
notifications or execute incident responses.

## 5. API Endpoints

All six endpoints require authentication.

| Endpoint | Purpose |
|---|---|
| GET /security/analytics/history | Historical security analysis |
| GET /security/analytics/attack-trends | SSH attack trend comparison |
| GET /security/analytics/predictive-risk | Predictive SSH risk score |
| GET /security/analytics/anomaly-forecast | Infrastructure metric forecast |
| GET /security/analytics/attack-patterns | Suspicious attack pattern classification |
| GET /security/analytics/predictive-alerts | Correlated predictive alerts |

The history and attack-trend endpoints accept a configurable period.
The prediction endpoints use a 1–90 day SSH analysis period where applicable.
The anomaly forecast uses its 30-day infrastructure lookback.

## 6. Dashboard Integration

The authenticated frontend contains a Predictive Security Analytics section.

It displays:
1. Predictive security risk.
2. CPU, memory and disk forecast chart.
3. Predicted attack patterns.
4. Predictive security alerts.

The frontend uses the existing authenticated apiFetch() helper.
Predictive analytics refresh every 30 seconds.

## 7. Security Controls

- Analytics API endpoints require an authenticated user.
- The frontend uses the existing session access token.
- No JWT token is embedded in the dashboard source.
- Predictive analytics are read-only.
- Predictive alerts do not trigger notification delivery.
- Existing incident-response execution controls remain separate.

## 8. Validation and Test Results

Validation performed:

| Test | Result |
|---|---|
| Python analytics and API syntax compilation | PASS |
| Frontend JavaScript syntax check | PASS |
| Unauthenticated access to six analytics endpoints | HTTP 401 |
| Authenticated admin access to six analytics endpoints | HTTP 200 |
| Predictive alert API response | PASS |
| Dashboard predictive panels | PASS |
| Dashboard automatic refresh integration | PASS |

The dashboard was opened at the HTTPS controller address and all four
predictive analytics panels were confirmed to display data.

## 9. Limitations

- Predictions use transparent statistical projections and heuristic rules.
- They are not trained or validated machine-learning probability models.
- Forecast accuracy depends on the available historical observations.
- The infrastructure forecast requires at least six observed daily values.
- A predicted alert is an indicator for investigation, not proof of a future
  attack.
- Predictive notifications are intentionally not sent automatically.

## 10. Conclusion

Phase 23 adds historical analysis, trend comparison, predictive risk
scoring, infrastructure forecasting, attack pattern classification and
predictive alert generation to the Cyber Digital Twin.

The results are exposed through authenticated FastAPI endpoints and
presented in the dashboard, providing an integrated view of historical
security behaviour and heuristic predictions.
