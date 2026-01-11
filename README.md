# 🛡️Log-Based SOC Platform

Threat Detection & SOC Automation System

📌 Project Overview

Log-Based SOC Platform is an enterprise-grade Security Operations Center (SOC) application designed to analyze logs, detect threats, correlate events, enrich intelligence, and automate incident response — all through a modern desktop GUI built with PySide6.

The platform simulates real-world SOC workflows such as:

Log ingestion & normalization

Rule-based and behavioral threat detection

IOC-based threat intelligence

Alerting & response automation

Analyst-friendly dashboards and reports

The application is packaged as a standalone Windows EXE using PyInstaller, requiring no Python installation on the target system.

🎯 Objectives

Build a realistic SOC simulation tool

Detect common web & system attacks from logs

Demonstrate SOC analyst workflows

Provide GUI-based security analytics

Package as a production-ready EXE

🚀 Key Features
🔍 Log Analysis

Apache / application log parsing

Request, IP, status, and timestamp normalization

Live and offline log viewing

🚨 Threat Detection

SQL Injection

XSS

Brute Force

IDOR

Credential Stuffing

Sensitive File Access

Repeated Suspicious Activity

🧠 Threat Intelligence (IOC)

IP-based IOC matching

Severity classification

IOC enable/disable toggle

📊 SOC Dashboard

Threat summary

Severity breakdown

Timeline-based analysis

Visual analytics (charts)

📁 Reporting

Automated PDF incident reports

One-click report generation

🔐 Authentication

SOC operator login

User registration

Password reset workflow

🎨 UI / UX

Dark & Light themes

Sidebar navigation

Modular views

SOC-grade minimal UI

📦 Deployment

Single-file Windows EXE

Custom application icon

EXE-safe resource handling

🏗️ System Architecture
Logs → Parser → Normalizer → Detector
                    ↓
            Correlation Engine
                    ↓
        Threat Intelligence (IOC)
                    ↓
        Alerts / Dashboard / Reports
