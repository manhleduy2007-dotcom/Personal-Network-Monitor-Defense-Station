# 🛡️ Personal Network Monitor & Defense Station

> A lightweight, modular network monitoring and intrusion detection system built in Python — designed to run quietly in the background and alert you when something unexpected shows up on your network.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey)
![Status](https://img.shields.io/badge/Status-In%20Development-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Overview

**Personal Network Monitor & Defense Station** is a Python-based tool for continuously scanning your local network, tracking connected devices, and detecting anomalies in real time. It serves as both a **practical security utility** and a **learning platform** for understanding how network reconnaissance and host discovery work under the hood — without relying on heavyweight tools like Nmap or Wireshark for every task.

The project is structured around a clean modular architecture, making it easy to extend with new detection logic, alert channels, or export formats.

---

## 🔍 What It Does

- **Host Discovery** — Actively scans the local subnet to enumerate live hosts using ARP/ICMP probing
- **Change Detection** — Tracks the state of the network over time and flags new, missing, or modified devices
- **Baseline Management** — Saves a known-good snapshot of the network to compare against future scans
- **Real-time Alerting** — Notifies you when a new device appears or a known device goes offline
- **Modular Design** — Core logic is split into clean, testable components (`scanner`, `detector`, `reporter`)

---