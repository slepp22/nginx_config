# DEFENSE-Team: Step-by-Step Guide

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
```

Überprüfe die Verbindung zu dem Servern mit dem ansible ping, das Ergebnis sollte pong sein, was bedeutet, dass die Verbindung erfolgreich war

```bash
ansible -i ~/Schreibtisch/ansible/inventory/hosts all -m ping --user ubuntu --private-key ~/.ssh/id_rsa
```

![Untitled](DEFENSE-Team%20Step-by-Step%20Guide%2045ab7cffd79f4f0bb885c31c9ea0b01f/Untitled.png)

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

![Untitled](DEFENSE-Team%20Step-by-Step%20Guide%2045ab7cffd79f4f0bb885c31c9ea0b01f/Untitled%201.png)

### Schritt 6: Überprüfe die Installation

Verbindet euch über SSH mit der “NGINX Instanz” 

```bash
ssh -i ~/.ssh/id_rsa ubuntu@!!!!!!!PUT YOUR NGINX SERVER IPV6 HERE!!!!!!!
```

Wenn das erfolgreich war sollte es wie folgt aussehen (ggfs. anderer Team Name):

![Untitled](DEFENSE-Team%20Step-by-Step%20Guide%2045ab7cffd79f4f0bb885c31c9ea0b01f/Untitled%202.png)

Nun prüft ob der Nginx Service läuft

```bash
systemctl status nginx
```

![Untitled](DEFENSE-Team%20Step-by-Step%20Guide%2045ab7cffd79f4f0bb885c31c9ea0b01f/Untitled%203.png)

Rufe die floating IP im Browser auf, Du solltest nun folgendes sehen

![Untitled](DEFENSE-Team%20Step-by-Step%20Guide%2045ab7cffd79f4f0bb885c31c9ea0b01f/Untitled%204.png)

Glückwunsch, dein NGINX Webserver läuft!

![https://media3.giphy.com/media/pHYaWbspekVsTKRFQT/giphy.gif?cid=7941fdc65faqc4ondkceasepec7sqifygm2jb494kj7hmik0&ep=v1_gifs_search&rid=giphy.gif&ct=g](https://media3.giphy.com/media/pHYaWbspekVsTKRFQT/giphy.gif?cid=7941fdc65faqc4ondkceasepec7sqifygm2jb494kj7hmik0&ep=v1_gifs_search&rid=giphy.gif&ct=g)

### Schritt 7: Systemmonitoring aktivieren

Aktiviere mit folgendem Befehl das Monitoring und lasse das Fenster geöffnet um gleich den Effekt deines DDos Angriffs beobachten zu können

```bash
htop
```

## Quest 2: NGINX gegen DDOS Angriffe absichern

### Schritt 1: Weiteres Ansible Playbook erstellen

Erstelle ein weiteres Ansible Playbook mit dem die Konfiguration aktualisiert werden kann

```bash
nano ~/Schreibtisch/ansible/playbooks/update_nginx_config.yml
```

Fügen folgenden Inhalt ein

```yaml
---
- name: Update Nginx configuration
  hosts: nginx
  become: yes
  vars:
    nginx_conf_template: /etc/nginx/nginx.conf
  tasks:
    - name: Backup current Nginx configuration
      copy:
        src: "{{ nginx_conf_template }}"
        dest: "{{ nginx_conf_template }}.backup"
        remote_src: yes

    - name: Update Nginx configuration file from template
      template:
        src: ~/Schreibtisch/ansible/nginx/nginx.conf.j2
        dest: "{{ nginx_conf_template }}"
      notify:
        - restart nginx

    - name: Test Nginx configuration
      command: nginx -t
      register: nginx_test_result
      changed_when: false
      failed_when: nginx_test_result.rc != 0

  handlers:
    - name: restart nginx
      systemd:
        name: nginx
        state: restarted
```

### Schritt 2: Aktualisieren der Konfiguration

Nun könnt ihr die in Quest 1 Schritt 4 erstelle Konfiguration erweitern. 

```bash
nano nginx/nginx.conf.j2
```

Kleiner Tipp, vielleicht findet ihr hier etwas in den Modulen: [https://nginx.org/en/docs/be](https://nginx.org/en/docs/)

### Schritt 3: Aktualisierung mit Playbook deployen

Führt das Playbook mit Ansible aus um die aktualsierte Konfiguration auf den Server zu deployen

```bash
ansible-playbook ~/Schreibtisch/ansible/playbooks/update_nginx_config.yml --user ubuntu --private-key ~/.ssh/id_rsa -i ~/Schreibtisch/ansible/inventory/hosts
```

Ziel ist es die Konfiguration gegen DDOS Angriffe abzusichern. Am Ende der Übung wird eure Instanz vom Attack-Team angegriffen