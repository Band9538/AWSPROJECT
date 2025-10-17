# 🏢 AWS Badge Access Security Analytics  
### _Amazon AWS Security Career Pathway Activity — Physical Security Simulation & Detection Project_

![AWS Security Badge](https://img.shields.io/badge/AWS-Security-orange?logo=amazonaws)
![Python](https://img.shields.io/badge/Python-3.9-blue?logo=python)
![Rust](https://img.shields.io/badge/Rust-1.80-red?logo=rust)
![Status](https://img.shields.io/badge/Status-Completed-success)


---

## 🔍 Project Overview
This project simulates and analyzes **employee badge access events** across multiple AWS-style facility locations to detect:
- 🚨 **Cloned badges** (impossible traveler anomalies)
- 🔎 **Curious users** (unauthorized access attempts)
- 🏢 **Room usage patterns** (behavior-based classification)

It forms part of the **Amazon AWS Security Career Pathway** hands-on challenge — focused on building repeatable detection logic for physical security analytics using **Rust** and **Python**.

---

## ⚙️ Technical Stack

| Layer | Tool / Technology | Purpose |
|-------|--------------------|----------|
| Simulation | 🦀 **Rust** | Generates realistic badge access logs |
| Analysis | 🐍 **Python (pandas, dateutil)** | Processes and detects anomalies |
| Reporting | 📊 **python-pptx** | Produces professional PowerPoint summaries |
| Data Format | 🧾 **JSON / JSONL** | Structured event & user data |
| Platform | 💻 **GitHub Codespaces / VS Code** | Cloud-ready development environment |

---

## 📁 Project Structure


---

## How to Run (Step-by-Step)

```bash
# 1️⃣ Build the simulator
cargo build --release

# 2️⃣ Run simulation for 2 days
./target/release/amzn-career-pathway-activity-rust \
  --config config.json \
  --user-profiles-output userprofile.json \
  --days 2 > events.jsonl

# 3️⃣ (Optional) Convert userprofile.json to array format if JSONL
python - <<'PY'
import json
with open("userprofile.json") as f: data=[json.loads(l) for l in f if l.strip()]
json.dump(data, open("userprofile_fixed.json","w"), indent=2)
PY

# 4️⃣ Run the Python analytics
python analyze_badges.py events.jsonl userprofile_fixed.json


