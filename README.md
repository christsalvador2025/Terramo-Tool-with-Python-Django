# Terramo Setup Guide

## 🚀 Requirements

Make sure you have **Docker Desktop** and **Docker Compose** installed.

### 🔗 Installation Links
- **Docker Desktop for Mac**: https://docs.docker.com/desktop/setup/install/mac-install/
- **Docker Desktop for Windows**: https://docs.docker.com/desktop/setup/install/windows-install/
- **Docker Engine for Linux**: https://docs.docker.com/desktop/setup/install/linux/

### ✅ Check if Docker is installed:
Open your terminal and run:
```bash
docker --version
docker compose version
```

---

## 📥 Project Setup

1. **Clone the Repository**
```bash
git clone <githubrepolink>
```

2. **Extract the Project** (if zipped).

3. **Open VS Code or Terminal** and `cd` into the project directory where `local.yml` is located.

4. **Setup Environment Variables**
- Go to the `.envs` folder in the root directory.
- Copy `.env.example` and paste it in the same folder.
- Rename it to `.env.local`, ( I will provide this for local testing )
- Fill in the values. *Note:* Cloudinary config is optional if you're not uploading images yet.

5. **Make sure Docker Desktop is running.**
- Create docker network to connect all of the containers.
```bash
docker network create terramoapp_local_nw
```
---

## ⚙️ Running the Project

### Step 1: Build and Start Containers
```bash
docker compose -f local.yml up --build -d --remove-orphans
```
Wait until the Docker containers finish building. You’ll see output in the terminal.

**[Optional]**: Check Docker Desktop > Containers to verify they're running.

### Step 2: Make Migrations
```bash
docker compose -f local.yml run --rm api python manage.py makemigrations
```

### Step 3: Apply Migrations
```bash
docker compose -f local.yml run --rm api python manage.py migrate
```

### Step 4: Create Superuser (for Django Admin)
```bash
docker compose -f local.yml run --rm api python manage.py createsuperuser
```
Follow the prompts. Note: When entering a password, it won't be visible for security.

---

## 🔐 Accessing the Admin Panel

Visit: [http://localhost:8080/supersecret/](http://localhost:8080/supersecret/)

You can change the URL in `.env.local`:
```
ADMIN_URL="supersecret/"
```

Log in using the email and password you set with the `createsuperuser` command.

---

## 🧭 Dashboard Overview

### 🏢 Company
- Create clients or companies.
- Default stakeholder groups will be automatically created:
  - Customers
  - Employees
  - Society
  - Industry Representatives
  - Owners

Each is linked to the company and given a unique invite token.

### 📦 Products
- Create products sold inside the Terramo platform.

### 🏢 Company Products
- Represents products purchased by a company.
- Requires both company and product to be created first.
- `purchased_at` is automatically timestamped.

### 📊 ESG Categories
- Create ESG categories like: Environment, Social, Corporate Governance.

### ❓ ESG Questions
- Add ESG-related questions and assign them to categories.

### ✍️ ESG Responses
- Where user answers are recorded, tied to company, question, and comments.

### 💌 Stakeholder Invitations
- Generate secure invite links for individuals or bulk email.
- Includes stakeholder group, company, invite token, status, and expiry tracking.

---

## 📁 Notes
- UI and modularization are ongoing improvements.
- Logo uploads and photo handling will be added later.

---

© 2025 Terramo – All rights reserved.
