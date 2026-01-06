# VSTChat: Secure Enclave Communication Platform

## Overview
VSTChat is an enterprise-grade, cross-platform messaging solution designed with a "Security First" architecture. Written in C++17, it utilizes advanced cryptographic standards (AES-256-GCM, PBKDF2, SHA-256) to ensure strict End-to-End Encryption (E2E). The system operates on a Zero-Knowledge principle, where the server acts as a blind relay and possesses no capability to decrypt user traffic.

This project demonstrates the implementation of low-level socket programming, multi-threaded connection handling, and authenticated encryption protocols suitable for environments requiring high confidentiality.

## Key Features

### Security Architecture
* **Authenticated Encryption (AEAD):** Utilizes AES-256-GCM (Galois/Counter Mode) to provide both data confidentiality and message integrity. Any modification of the ciphertext during transit results in decryption failure, preventing Man-in-the-Middle (MITM) attacks.
* **Cryptographic Isolation:** Each communication channel (Room) utilizes a unique UUID acting as a cryptographic salt. This ensures that identical passwords across different channels generate mathematically distinct encryption keys, preventing rainbow table attacks and key collisions.
* **Secure Key Derivation:** Session keys are generated using PBKDF2-HMAC-SHA256, significantly increasing the computational cost for brute-force attempts.
* **Zero-Knowledge Server:** The server architecture is designed to store user credentials only as salted hashes. It routes encrypted packets without having access to the decryption keys.

### System Functionality
* **Cross-Platform Compatibility:** Native support for Linux, Windows (via MSYS2/MinGW), and Android (via Termux).
* **Custom Binary Protocol:** Implemented a lightweight, packet-based TCP protocol to ensure low latency and reliable data framing.
* **Access Control System:** Built-in Whitelist mechanism for private server instances, requiring administrator approval for new user registrations.
* **Persistent Storage:** File-based database system for user credentials and access logs.

## Technical Stack
* **Language:** C++17
* **Build System:** CMake (3.10+)
* **Cryptography:** OpenSSL 1.1 / 3.0
* **Networking:** BSD Sockets (Linux/Unix), Winsock2 (Windows)
* **Concurrency:** std::thread, std::mutex, std::atomic

---

## Build Instructions

### Prerequisites
Ensure the following tools are installed on your system:
* C++ Compiler (GCC, Clang, or MSVC)
* CMake
* OpenSSL Development Libraries

### Linux (Ubuntu/Debian/Kali)
```bash
sudo apt update
sudo apt install g++ cmake libssl-dev make
mkdir build
cd build
cmake ..
make
```

### Android (Termux)
```bash
pkg update
pkg install clang cmake make openssl-tool openssl
mkdir build
cd build
cmake ..
make
```

### Windows (MSYS2 / MinGW64)
1. Open MSYS2 MinGW 64-bit terminal.
2. Install dependencies:
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl make
```
3. Compile:
```bash
mkdir build
cd build
cmake -G "Unix Makefiles" ..
make
```

---

## Usage Guide

### 1. Server Deployment
The server manages connections, authentication, and packet routing.

**Starting the Server:**
```bash
./server
```
*Default Port: 4433*

**Server Administration (Console Commands):**
The server console supports runtime administration commands:
* `/whitelist on` — Enable strict access control. Only approved users can log in.
* `/whitelist off` — Disable access control (open registration).
* `/approve <nickname>` — Approve a pending registration request.
* `/users` — Display the count of registered users.

### 2. Client Operations
The client handles encryption, decryption, and user interface.

**Starting the Client:**
```bash
./client
```

**Workflow:**
1.  **Connection:** Enter the server IP address (default is `127.0.0.1`).
2.  **Authentication:** Login or Register. If whitelisting is active, wait for administrator approval.
3.  **Channel Selection:** Select a communication room from the list retrieved from the server.
4.  **Secure Handshake:** Enter the "Channel Password". This password is never sent to the server. It is used locally to derive the AES-256-GCM session key.
5.  **Messaging:** All messages are encrypted locally before transmission.

---

## License

Copyright 2026 VSTChat Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.