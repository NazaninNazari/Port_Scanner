# N0aziXss Port Scanner 🍓

## 🌟 Introduction
**N0aziXss Port Scanner** is an advanced network scanning tool featuring:
- High-performance multithreaded scanning
- Automatic service detection
- Security severity classification
- Beautiful purple-themed UI with strawberry accents

```bash
pip install colorama
python scanner.py

#clone the repository
git clone https://github.com/NazaninNazari/Port_Scanner.git
cd Port_Scanner-tools

# install dependencies
pip install -r requirements.txt

# run the scanner
python port_scanner.py

# Usage Example:
1. basic scan (default ports):
```bash
Enter target IP/hostname: example.com
Protocol (tcp/udp): tcp

2. custom port range:
```bash
Enter port/range: 80-500

3. UDP scan:
```bash
Protocol (tcp/udp): udp

# Sample Output
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧
  OPEN PORTS FOUND  
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧
No.  Port    Service           Protocol    Severity
--------------------------------------------------
1    22      SSH               TCP         Critical
2    80      HTTP              TCP         High
3    443     HTTPS             TCP         Critical
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧
  Total open ports found: 3 🍓
✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧