# تحليل حركة الشبكة | Network Traffic Analysis

> **الهدف:** فهم كيف يراقب محلل SOC حركة الشبكة لاكتشاف التهديدات مبكراً.

---

## ما هو Network Traffic Analysis؟

تحليل حركة الشبكة هو عملية مراقبة وفحص البيانات المتدفقة عبر الشبكة للكشف عن:
- **الأنشطة المشبوهة** (Suspicious Activity)
- **الاختراقات** (Intrusions)
- **تسرب البيانات** (Data Exfiltration)
- **البرمجيات الخبيثة** (Malware Communication)

---

## أدوات التحليل الرئيسية

### 1. Wireshark
- الأداة الأشهر لتحليل الـ PCAP
- تعرض الـ Packets بشكل مفصل
- تدعم الـ Filters لتضييق نطاق البحث

```
# فلاتر مهمة في Wireshark
http                    # عرض HTTP فقط
tcp.port == 443         # HTTPS traffic
ip.addr == 192.168.1.1  # عنوان IP محدد
dns                     # DNS queries
```

### 2. tcpdump
- أداة Command Line لالتقاط الـ Packets
- مثالية للـ Linux environments

```bash
# التقاط كل الـ traffic على واجهة eth0
tcpdump -i eth0

# حفظ الـ Packets في ملف
tcpdump -i eth0 -w capture.pcap

# فلترة بـ Port
tcpdump -i eth0 port 80

# فلترة بـ IP
tcpdump -i eth0 host 192.168.1.100
```

### 3. Zeek (Bro)
- يولّد Logs منظمة من الـ PCAP
- مثالي للـ SIEM integration

---

## أنواع حركة الشبكة المشبوهة

### Port Scanning
```
المؤشرات:
- اتصالات سريعة على بورتات متعددة
- SYN packets بدون إتمام الـ handshake
- مصدر واحد يستهدف عشرات الـ ports
```

### DNS Tunneling
```
المؤشرات:
- DNS queries طويلة بشكل غير طبيعي
- عدد ضخم من الـ DNS requests من جهاز واحد
- Subdomains عشوائية وطويلة
- TXT records تحمل بيانات مشفرة
```

### Data Exfiltration
```
المؤشرات:
- Upload traffic أكبر من المعتاد
- اتصالات بـ IPs خارجية غير معروفة
- نشاط في أوقات غير طبيعية (منتصف الليل)
- بروتوكولات غير معتادة (IRC, FTP)
```

### C2 Communication (Command & Control)
```
المؤشرات:
- Beaconing منتظم (ping دوري)
- اتصالات بـ Domain Generating Algorithm (DGA) domains
- استخدام HTTP/HTTPS لإخفاء C2 traffic
- Periodic connections بفاصل زمني ثابت
```

---

## بروتوكولات يجب فهمها

| البروتوكول | Port | الاستخدام | ما يبحث عنه المحلل |
|-----------|------|-----------|-------------------|
| HTTP | 80 | Web traffic | Plain text credentials, malware downloads |
| HTTPS | 443 | Encrypted web | Certificate anomalies, unusual destinations |
| DNS | 53 | Name resolution | Tunneling, DGA domains |
| FTP | 21 | File transfer | Unencrypted credentials |
| SSH | 22 | Secure shell | Brute force, lateral movement |
| SMB | 445 | File sharing | Ransomware propagation, lateral movement |
| RDP | 3389 | Remote desktop | Brute force, unauthorized access |

---

## Network Baseline

**المفهوم:** معرفة ما هو "طبيعي" في الشبكة لاكتشاف ما هو "غير طبيعي"

```
أسئلة الـ Baseline:
- ما هي ساعات النشاط الطبيعية؟
- ما هي الـ IPs الداخلية والخارجية المعتادة؟
- ما هو متوسط حجم الـ traffic اليومي؟
- ما هي البروتوكولات المستخدمة عادة؟
```

---

## تحليل الـ PCAP - خطوات عملية

```
1. افتح الـ PCAP في Wireshark
2. راجع Statistics > Protocol Hierarchy
3. ابحث عن Conversations غير عادية
4. فلتر بالـ protocols المشبوهة
5. تتبع الـ TCP/UDP Streams
6. ابحث عن Credentials في النص الصريح
7. استخرج الملفات المرسلة (File > Export Objects)
```

---

## IOCs من الشبكة

```
Network-based IOCs:
- IP Addresses مشبوهة
- Domain names خبيثة
- URLs تحمل Malware
- File hashes لملفات تم تنزيلها
- Port combinations غير طبيعية
- User-Agent strings مشبوهة
```

---

## الخلاصة

> **الشبكة لا تكذب.** كل اتصال يترك أثراً.
> مهمة المحلل: قراءة هذه الآثار وتفسيرها قبل أن يفوت الأوان.

### نقاط المراجعة السريعة ✅
- [ ] فهمت الفرق بين SYN Scan و Full Connect Scan
- [ ] أعرف كيف أكتشف الـ DNS Tunneling
- [ ] أستطيع قراءة الـ PCAP في Wireshark
- [ ] أعرف مؤشرات الـ C2 Communication
- [ ] أفهم مفهوم الـ Network Baseline

---

*Published by Badi Alosaimi | SOC Analyst | Blue Team*
