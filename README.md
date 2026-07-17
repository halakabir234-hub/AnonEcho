# AnonEcho
A Zero-Knowledge anonymous feedback board built with Midnight's Compact language, featuring decentralized group authentication and automatic cryptographic anti-spam defense.
# AnonEcho 🤫🔊 — Verifiable, Zero-Knowledge Anonymous Feedback Board

Welcome to **AnonEcho**! This is my official submission for the [Midnight Hackathon](https://events.mlh.com/events/14413-midnight-hackathon). 

AnonEcho is a private, verifiable feedback microservice built to give users absolute anonymity while guaranteeing to an organization that every piece of feedback comes from an actual, authenticated member.

## 💡 The Inspiration
In workplaces, DAOs, and online communities, people want to give honest, critical feedback without fear of retaliation. Traditional "anonymous" forms can track you via IP addresses or database IDs. On standard blockchains, your public wallet address leaks your entire financial identity. I built AnonEcho to solve this by bringing zero-knowledge logic to everyday communication.

## 🛠️ What It Does
*   **Private Identity:** Users hold a secret credential key locally. A smart contract manages approved members inside a Merkle Tree without ever knowing their cleartext keys.
*   **Zero-Knowledge Proofs:** When a user submits feedback, the app computes a cryptographic proof locally, verifying: *"I belong to this group, but I won't reveal which member I am."*
*   **Built-in Anti-Spam Defense:** The system generates a deterministic session nullifier. If a user tries to double-post, the application instantly catches and flags it without breaking their privacy.

## 💻 Tech Stack & Architecture
*   **Smart Contract:** Written in Midnight's **Compact** (`contract.compact`), utilizing cryptographic state proofs, ledger fields, and customized nullifier assertions.
*   **Simulation & Testing Runtime:** Built a Node.js wrapper (`index.js`) to trace cryptographic states, emulate local client provers, and log transaction parameters.
*   **Frontend Interface:** Designed a single-page interactive UI (`index.html`) to visually display successful zero-knowledge proof generation and active nullifier error handling.

## 🚀 How to Run the Project
1. Clone the repository and navigate to the directory.
2. Initialize npm and run the backend simulator:
   ```bash
   npm init -y
   node index.js
