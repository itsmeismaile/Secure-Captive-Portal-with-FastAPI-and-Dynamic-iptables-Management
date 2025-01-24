# Secure-Captive-Portal-with-FastAPI-and-Dynamic-iptables-Management
A modern captive portal solution using FastAPI and iptables to authenticate users, manage temporary internet access, and enforce network security with dynamic rules.
# Captive Portal with FastAPI and iptables

This project implements a **captive portal** using FastAPI and `iptables` to temporarily authorize users for internet access.

## Features
- **User authentication** via an external server with redirection.
- **Temporary authorization management** using iptables.
- Automatic redirection of unauthorized users to a login page.
- **Automatic expiration** of authorizations after a configurable time.
- Architecture based on two modules:
  - `database.py`: User management and authentication server.
  - `main.py`: Captive portal with iptables rule management.

## Prerequisites

- Python 3.8 or higher
- Required Python modules (installable via `pip install -r requirements.txt`)
- Administrative privileges to manage `iptables` rules

## Installation

1. Clone the GitHub repository:  
   ```bash
   git https://github.com/itsmeismaile/Secure-Captive-Portal-with-FastAPI-and-Dynamic-iptables-Management
   cd Secure-Captive-Portal-with-FastAPI-and-Dynamic-iptables-Management
