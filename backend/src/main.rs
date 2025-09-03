use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// --- SHARED APPLICATION STATE ---
#[derive(Clone)]
struct AppState {
    event_store: Arc<Mutex<HashMap<String, Vec<UserEvent>>>>,
    ip_blacklist: Arc<HashSet<String>>,
}

// --- DATA STRUCTURES ---
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UserEvent {
    session_id: String,
    user_id: Option<String>,
    event_type: EventType,
    timestamp: DateTime<Utc>,
    ip_address: String,
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
enum EventType {
    PageLoad,
    Click,
    FormSubmission,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FraudCheckResult {
    session_id: String,
    fraud_score: i32,
    flagged: bool,
    reasons: Vec<String>,
    check_timestamp: DateTime<Utc>,
}

// --- API ENDPOINT HANDLER ---
async fn analyze_event_handler(
    State(state): State<Arc<AppState>>,
    Json(event): Json<UserEvent>,
) -> (StatusCode, Json<FraudCheckResult>) {
    state.event_store.lock().unwrap().entry(event.session_id.clone()).or_default().push(event.clone());

    let mut score = 0;
    let mut reasons = Vec::new();

    const IMPOSSIBLY_FAST_SUBMISSION_MS: i64 = 1000;

    if state.ip_blacklist.contains(&event.ip_address) {
        warn!("BLACKLISTED IP DETECTED: IP {} in session {}", &event.ip_address, &event.session_id);
        score += 100;
        reasons.push("Blacklisted IP address".to_string());
    }

    let events_for_session = state.event_store.lock().unwrap();
    let session_events = events_for_session.get(&event.session_id).unwrap();

    if session_events.len() > 1 {
        let previous_event = &session_events[session_events.len() - 2];
        let time_diff = event.timestamp.timestamp_millis() - previous_event.timestamp.timestamp_millis();

        if time_diff < IMPOSSIBLY_FAST_SUBMISSION_MS {
            score += 75;
            reasons.push("Impossibly fast user interaction".to_string());
        }
    }

    if session_events.len() > 10 {
        score += 50;
        reasons.push("High frequency of events".to_string());
    }

    let result = FraudCheckResult {
        session_id: event.session_id.clone(),
        fraud_score: score,
        flagged: score >= 50,
        reasons,
        check_timestamp: Utc::now(),
    };

    info!("Analysis complete for session [{}]: Score = {}, Flagged = {}", &result.session_id, result.fraud_score, result.flagged);

    (StatusCode::OK, Json(result))
}

// --- MAIN FUNCTION ---
#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let shared_state = AppState {
        event_store: Arc::new(Mutex::new(HashMap::new())),
        ip_blacklist: Arc::new(HashSet::from(["1.1.1.1".to_string(), "2.2.2.2".to_string()])),
    };

    let app = Router::new()
        .route("/api/v1/events", post(analyze_event_handler))
        .fallback_service(
            ServeDir::new("../frontend")
                .fallback(ServeFile::new("../frontend/index.html"))
        )
        .with_state(Arc::new(shared_state));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Starting server, listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}