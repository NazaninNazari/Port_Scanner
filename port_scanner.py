import socket
import sys
from pyfiglet import Figlet
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Optional, Union, List
from colorama import Fore, Style, init
from rich.console import Console

# Initialize colorama
init(autoreset=True)
console = Console()

# Security ports with importance levels
SECURITY_PORTS = {
    21: ('FTP', 'High'), 22: ('SSH', 'Critical'), 23: ('Telnet', 'High'),
    25: ('SMTP', 'Medium'), 53: ('DNS', 'Critical'), 80: ('HTTP', 'High'),
    443: ('HTTPS', 'Critical'), 3306: ('MySQL', 'High'), 3389: ('RDP', 'Critical'),
    8080: ('HTTP-Alt', 'Medium'), 8443: ('HTTPS-Alt', 'Medium')
}

# Banner
BANNER = Figlet(font='slant').renderText('Port Scanner')
console.print(Fore.CYAN + BANNER)
print(Fore.CYAN + "♦*"*15)
print(Fore.GREEN + "🍓N0aziXss Port Scanner v3.0🍓")
print(Fore.CYAN + "♦*"*15 + "\n")

def ShowPortsTree(open_ports):
    print(Fore.CYAN + "\n" + "═"*65)
    print("╔" + " OPEN PORTS FOUND ".center(63, "═") + "╗")
    print("╠" + "═"*63 + "╣")
    print("║" + Fore.CYAN + f" {'No.':<4} {'Port':<8} {'Service':<20} {'Protocol':<12} {'Severity':<13} " + Fore.CYAN + "║")
    print("╠" + "═"*63 + "╣")
    
    for i, (port, service, proto, severity) in enumerate(open_ports, 1):
        color = Fore.RED if severity == 'Critical' else Fore.YELLOW if severity == 'High' else Fore.WHITE
        print(Fore.CYAN + "║ " + Fore.CYAN + f"{i:<4}" + Fore.WHITE + f"{port:<8} {service:<20} {proto:<12} " + color + f"{severity:<14}" + Fore.CYAN + " ║")
    
    print("╠" + "═"*63 + "╣")
    print("║" + Fore.MAGENTA + f" Total open ports: {len(open_ports)} ".center(63) + Fore.CYAN + "║")
    print("╚" + "═"*63 + "╝" + Style.RESET_ALL + "\n")

class PortScannerError(Exception):
    pass

class HostResolutionError(PortScannerError):
    pass

class PortScanError(PortScannerError):
    pass

class InvalidInputError(PortScannerError):
    pass

def ValidateIP(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def ResolveHost(target: str) -> str:
    if not target:
        raise InvalidInputError("Target cannot be empty")
    
    if ValidateIP(target):
        return target
    
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise HostResolutionError(f"Could not resolve hostname: {target}")
    except Exception as e:
        raise HostResolutionError(f"Resolution error: {str(e)}")

def ParsePortInput(input_str: str) -> Union[int, range]:
    if not input_str.strip():
        raise InvalidInputError("Port input cannot be empty")
    
    try:
        if '-' in input_str:
            parts = input_str.split('-')
            if len(parts) != 2:
                raise InvalidInputError("Invalid port range format")
            
            start = int(parts[0].strip())
            end = int(parts[1].strip())
            
            if not (0 < start <= 65535) or not (0 < end <= 65535):
                raise InvalidInputError("Ports must be between 1-65535")
            if start > end:
                raise InvalidInputError("Start port must be <= end port")
                
            return range(start, end + 1)
        
        port = int(input_str)
        if not 0 < port <= 65535:
            raise InvalidInputError("Port must be between 1-65535")
        return port
        
    except ValueError:
        raise InvalidInputError("Port must be a valid number")
    
def ScanPort(ip: str, port: int, proto: str, timeout: float = 1.0) -> Optional[Tuple[int, str, str, str]]:
    try:
        sock_type = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(timeout)
            
            if proto == 'tcp':
                if sock.connect_ex((ip, port)) == 0:
                    service, severity = SECURITY_PORTS.get(port, ('Unknown', 'Low'))
                    return port, service, proto.upper(), severity
            else:
                sock.sendto(b'', (ip, port))
                try:
                    sock.recvfrom(1024)
                    service, severity = SECURITY_PORTS.get(port, ('Unknown', 'Low'))
                    return port, service, proto.upper(), severity
                except socket.timeout:
                    pass
                    
    except socket.timeout:
        pass
    except socket.error as e:
        raise PortScanError(f"Network error on port {port}: {str(e)}")
    except Exception as e:
        raise PortScanError(f"Unexpected error on port {port}: {str(e)}")
    
    return None

def RunScan(ip: str, ports: Union[int, range, List[int]], proto: str) -> List[Tuple[int, str, str, str]]:
    if proto not in ('tcp', 'udp'):
        raise InvalidInputError("Invalid protocol")
    
    port_list = [ports] if isinstance(ports, int) else ports
    open_ports = []
    
    try:
        with ThreadPoolExecutor(max_workers=min(100, len(port_list))) as executor:
            futures = {executor.submit(ScanPort, ip, port, proto): port for port in port_list}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if result := future.result():
                        open_ports.append(result)
                        print(Fore.CYAN + f"[+] Found: {port}/{proto} - {result[1]} " + 
                              Fore.YELLOW + f"(Severity: {result[3]})" + Style.RESET_ALL)
                except PortScanError as e:
                    print(Fore.RED + f"[!] Warning: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        
        return sorted(open_ports, key=lambda x: x[0])
        
    except Exception as e:
        raise PortScanError(f"Scan failed: {str(e)}")

def main():
    try:
        target = input(Fore.CYAN + "[?] " + Fore.WHITE + "Enter target IP/hostname: " + Style.RESET_ALL).strip()
        proto = input(Fore.CYAN + "[?] " + Fore.WHITE + "Protocol (tcp/udp): " + Style.RESET_ALL).strip().lower()
        
        ip = ResolveHost(target)
        print(Fore.BLUE + f"\n[i] Target resolved: " + Fore.WHITE + f"{target}" + Fore.YELLOW + " → " + Fore.WHITE + f"{ip}" + Style.RESET_ALL)
        
        # Phase 1: Default security scan
        print(Fore.MAGENTA + "\n[+] Scanning security ports..." + Style.RESET_ALL)
        open_ports = RunScan(ip, SECURITY_PORTS.keys(), proto)
        ShowPortsTree(open_ports)
        
        # Phase 2: Custom scan
        while True:
            try:
                custom = input(Fore.CYAN + "\n[?] " + Fore.WHITE + "Enter port/range or 'quit': " + Style.RESET_ALL).strip()
                if custom.lower() == 'quit':
                    break
                    
                ports = ParsePortInput(custom)
                print(Fore.MAGENTA + "\n[+] Scanning custom ports..." + Style.RESET_ALL)
                open_ports = RunScan(ip, ports, proto)
                ShowPortsTree(open_ports)
                
            except InvalidInputError as e:
                print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
            except KeyboardInterrupt:
                print(Fore.YELLOW + "\n[!] Scan interrupted by user" + Style.RESET_ALL)
                break
            except Exception as e:
                print(Fore.RED + f"[!] Error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
                
    except (HostResolutionError, InvalidInputError) as e:
        print(Fore.RED + f"\n[!] Fatal error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Operation cancelled by user" + Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()