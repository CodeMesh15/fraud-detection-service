# Fraud & Bot Detection Service

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Axum](https://img.shields.io/badge/Axum-7E466A?style=for-the-badge)
![TailwindCSS](https://img.shields.io/badge/tailwindcss-%2338B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white)

A full-stack application that simulates a real-time fraud and bot detection system for an e-commerce platform. The project features a high-performance Rust backend and an interactive web dashboard for monitoring.

---
## ✨ Features

* **Real-time Event Ingestion:** A robust Axum-based API endpoint for receiving user activity events.
* **Rule-Based Detection Engine:** Analyzes events against a set of rules to detect suspicious behavior, including:
    * IP Address Blacklisting
    * Impossibly Fast Form Submissions
    * High-Frequency Activity Bursts
* **Interactive Web Dashboard:** A single-page application built with Tailwind CSS and Chart.js to visualize system activity in real-time.
* **Live Metrics & Logs:** Displays key metrics like total events processed, sessions flagged, and provides detailed logs for both all events and just fraudulent activity.
* **Event Simulation:** Frontend controls allow for easy simulation of various event types to test the detection engine.

---
## 🛠️ Tech Stack

### Backend
* **Language:** Rust
* **Web Framework:** Axum
* **Asynchronous Runtime:** Tokio
* **Serialization:** Serde
* **Logging:** Tracing

### Frontend
* **Frameworks:** HTML5, Tailwind CSS
* **Language:** JavaScript (Vanilla)
* **Visualizations:** Chart.js

---
## 🚀 Getting Started

You can run this project easily on Replit or on your local machine.

### Running on Replit (Easiest Method)
This project is pre-configured for Replit.
1.  Open the Repl.
2.  Click the big green **"Run"** button.
3.  The backend will compile and start, and the frontend will automatically appear in the WebView pane.

### Running Locally
**Prerequisites:**
* Rust and Cargo installed (see [rust-lang.org](https://www.rust-lang.org/))
* A modern web browser

**Instructions:**
1.  Clone the repository:
    ```bash
    git clone <your-repo-url>
    cd fraud-detection-service
    ```
2.  Run the backend server:
    ```bash
    # Navigate to the backend directory
    cd backend
    # Compile and run the project in release mode
    cargo run --release
    ```
3.  The server will start on `http://localhost:8080`. Open this URL in your web browser to view and interact with the dashboard.

---
## 🔌 API Endpoint

The backend exposes a single API endpoint to ingest user events.

* **Endpoint:** `POST /api/v1/events`
* **Body:** JSON

**Example Payload:**
```json
{
  "sessionId": "user-session-uuid-12345",
  "userId": "optional-user-id-abcde",
  "eventType": "FormSubmission",
  "timestamp": "2025-09-03T16:30:00.000Z",
  "ipAddress": "192.168.1.10",
  "metadata": {
    "pageLoadTimestamp": "2025-09-03T16:29:59.000Z",
    "path": "/checkout"
  }
}
