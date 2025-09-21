# 🔐 HashLocker — Password Management. Simplified.

HashLocker is a proof-of-concept password manager built as part of CSE 442: Software Engineering, the B.S. Computer Science capstone course at the University at Buffalo.
Developed by a small team using Agile methods, HashLocker provides a streamlined, user-friendly interface for managing login credentials directly in your browser.

    Note: This project was created for academic purposes and is not intended for production use. Vault entries are not encrypted/hashed in this version due to course requirements & limitations.

# 📌 Project Overview

HashLocker helps users store, organize, and share accounts in a style similar to Bitwarden — but with a simplified, intuitive interface.

Key Features

    🗄 Password Vault — Save, view, search, and manage credentials with custom account names and images.
    🔑 Password Generation — Create strong passwords with customizable complexity requirements.
    📏 Password Strength Checking — Using the zxcvbn library.
    🤝 Password Sharing (Invites) — Securely send and accept credentials between users, ideal for team management.
    🔍 Search — Quickly find entries in your vault.
    ♻ Account Recovery — Security question–based password reset (future: OTP reset system).

# 🛠 Tech Stack & Architecture

# Front End

    JavaScript, HTML, Bootstrap
    Chrome Extension APIs
    JSON for client–server communication

# Back End

    PHP
    MySQL database
    zxcvbn password strength estimation library

# Security Features (Proof-of-Concept)

    Input filtering (XSS mitigation)
    Anti-Forgery protection via Signed Double-Submit Cookies
    SQL injection prevention via prepared statements
    HTTPS encryption for data in transit

    🚧 Future improvement: Encrypt/hash vault credentials for real-world security.

# 📂 System Design

[Chrome Extension UI] <--JSON--> [PHP Web Server] <--SQL--> [MySQL Database]

    Chrome Extension UI — Presents the vault, password tools, and sharing features.
    PHP Server — Handles authentication, vault CRUD operations, and sharing logic.
    MySQL DB — Stores user accounts, vault entries, and invite metadata.

# 👤 My Role & Contributions

Front-End Developer and UX/UI Designer:

    Implementations:
        Overall design of user interface and application using Bootstrap
        Ensured seamless integration between front-end and back-end via JSON communication
        Developed UX/UI interaction to optimize usability
        
    Writing acceptance tests and frontend unit tests
    Collaborating with other developers using AGILE & Kanban methodology

# Contributors

| Name/Initials | Role |
|---------------|------------------------------------|
| CG            | Project Manager |
| JK (me)       | Front-End Design & Implementation |
| SC            | Front-End Design & Implementation |
| BW            | Front-End & API Implementation |
| PD            | Back-End Implementation |
| EG            | Back-End Design & Implementation |

# ⚠ Disclaimer
HashLocker was developed for educational purposes as part of a university course.
The security model is incomplete, and vault entries are not encrypted in this version.
Do not use for storing real credentials.
