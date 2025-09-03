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
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// --- SHARED APPLICATION STATE ---
// This struct holds the data that needs to be shared across all requests.
// `Arc<Mutex<...>>` is the idiomatic way in Rust to safely share mutable data between threads.
#[derive(Clone)]
struct AppState {
    event_store: Arc<Mutex<HashMap<String, Vec<UserEvent>>>>,
    ip_blacklist: Arc<HashSet<String>>,
}

// --- DATA STRUCTURES (equivalent to Java POJOs) ---
// The `derive` macros automatically implement traits for our structs.
// `Deserialize` allows turning JSON into this struct.
// `Serialize` allows turning this struct into JSON.
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
    PAGE_LOAD,
    CLICK,
    FORM_SUBMISSION,
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
// This is the main function that handles incoming POST requests to /api/v1/events.
async fn analyze_event_handler(
    State(state): State<AppState>,
    Json(event): Json<UserEvent>,
) -> (StatusCode, Json<FraudCheckResult>) {
    
    // Store the event for stateful analysis. The .lock() call safely acquires access to the data.
    state.event_store.lock().unwrap().entry(event.session_id.clone()).or_default().push(event.clone());

    let mut score = 0;
    let mut reasons = Vec::new();
    const IMPOSSIBLY_FAST_SUBMISSION_MS: i64 = 1000;

    // --- Rule 1: Check for blacklisted IP ---
    if state.ip_blacklist.contains(&event.ip_address) {
        warn!("BLACKLISTED IP DETECTED: IP {} in session {}", &event.ip_address, &event.session_id);
        score += 50;
        reasons.push("IP address is on the blacklist.".to_string());
    }

    // --- Rule 2: Check for impossibly fast form submissions ---
    if event.event_type == EventType::FORM_SUBMISSION {
        if let Some(metadata) = &event.metadata {
            if let Some(page_load_str) = metadata.get("pageLoadTimestamp") {
                if let Ok(page_load_time) = page_load_str.parse::<DateTime<Utc>>() {
                    let diff = event.timestamp.signed_duration_since(page_load_time).num_milliseconds();
                    if diff < IMPOSSIBLY_FAST_SUBMISSION_MS {
                        score += 40;
                        reasons.push(format!("Form submitted impossibly fast: {}ms.", diff));
                    }
                }
            }
        }
    }

    // --- Rule 3: High frequency of events ---
    let session_history = state.event_store.lock().unwrap();
    if let Some(history) = session_history.get(&event.session_id) {
        let five_seconds_ago = event.timestamp - Duration::from_secs(5);
        let recent_event_count = history.iter().filter(|e| e.timestamp > five_seconds_ago).count();
        
        if recent_event_count > 10 {
            score += (recent_event_count as i32 - 10) * 5;
            reasons.push(format!("High frequency of events detected: {} in the last 5 seconds.", recent_event_count));
        }
    }

    // Finalize the result
    let result = FraudCheckResult {
        session_id: event.session_id.clone(),
        fraud_score: score,
        flagged: score > 60,
        reasons: if reasons.is_empty() { vec!["No issues".to_string()] } else { reasons },
        check_timestamp: Utc::now(),
    };
    
    info!("Analysis complete for session [{}]: Score = {}, Flagged = {}", &result.session_id, result.fraud_score, result.flagged);

    (StatusCode::OK, Json(result))
}

// --- MAIN FUNCTION (Application Entry Point) ---
#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize our shared state
    let shared_state = AppState {
        event_store: Arc::new(Mutex::new(HashMap::new())),
        ip_blacklist: Arc::new(HashSet::from(["1.1.1.1".to_string(), "2.2.2.2".to_string()])),
    };

    // Build our application router
    let app = Router::new()
        .route("/api/v1/events", post(analyze_event_handler))
        .with_state(shared_state);

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("Starting server, listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
