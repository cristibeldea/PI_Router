Documentație Proiect: Router pe Raspberry Pi 4 cu Firewall, Display și Interfață Web

##1. Introducere
##Scopul proiectului este transformarea unui Raspberry Pi 4 într-un router complet funcțional, capabil să:
•	Facă toutare între interfețele Ethernet și Ethernet
•	facă routare între interfețele Ethernet și Wi-Fi (bridge),
•	ofere funcționalități de firewall și management,
•	afișeze pe un ecran SPI lista device-urilor active și viteza conexiunii la Internet,
•	furnizeze o interfață web securizată pentru administrarea regulilor firewall și vizualizarea statusului rețelei.
Acest setup transformă Raspberry Pi într-un mini-router administrabil.

##2. Tehnologii utilizate
##2.1. Linux Networking (bridge, routing)
•	Am configurat un bridge (br0) între interfața wireless (wlan0) și Ethernet-ul secundar (eth1).
•	IP-ul fix al router-ului: 192.168.50.1/24.
•	Pachetele din LAN sunt rutate către Internet prin interfața principală eth0.

Instrumente folosite:
•	ip link / ip addr / ip route pentru gestionarea interfețelor.
•	Script de systemd custom (bridge-br0.service) care:
o	creează bridge-ul la boot,
o	mută IP-ul de pe interfețele membre pe br0,
o	configurează wlan0 și eth1 ca slave în bridge.

##2.2. DHCP și DNS
•	dnsmasq este folosit pentru a oferi IP-uri dinamice în LAN.
•	Fișierul dnsmasq.conf specifică gama de IP-uri (de ex. 192.168.50.100 – 192.168.50.200) și gateway-ul (Raspberry Pi).
Avantaje:
•	Serviciu simplu, ușor de configurat, integrat cu bridge-ul.
•	Păstrează fișierul /var/lib/misc/dnsmasq.leases unde vedem dispozitivele active.
 

##2.3. Firewall
•	Am folosit UFW (Uncomplicated Firewall) ca interfață pentru iptables.
•	Setările includ:
o	Politici implicite: deny (incoming), allow (outgoing), deny (routed)
o	NAT/MASQUERADE pentru a permite accesul clienților la Internet:
o	*nat
o	:POSTROUTING ACCEPT [0:0]
o	-A POSTROUTING -o eth0 -j MASQUERADE
o	COMMIT
o	Reguli pentru:
 -	DNS (53/tcp, 53/udp),
 -	DHCP (67/udp),
 -	management prin SSH (22/tcp),
 -	acces la interfața web (8080/tcp).

##2.4. Interfața grafică pe LCD SPI
Hardware: un display TFT de 2.8" ILI9341 SPI.
Librării utilizate:
•	Adafruit Blinka (suport hardware layer),
•	adafruit-circuitpython-rgb-display (driver ILI9341),
•	Pillow (PIL) pentru randarea textului și graficii.
Funcționalități:
•	Afișează device-urile active din LAN, extrase din dnsmasq.leases.
•	Afișează în timp real viteza conexiunii Internet (download/upload Mbps) prin speedtest-cli.
•	Se actualizează automat la un interval (5–10 secunde).
•	Pornirea la boot este gestionată printr-un serviciu systemd:
•	/etc/systemd/system/display-status.service

##2.5. Interfața Web (Flask)
•	Aplicație Python bazată pe Flask, rulată ca serviciu systemd (ufw-web.service).
•	Funcționalități:
o	Vizualizare reguli firewall (ufw status numbered).
o	Adăugare/ștergere reguli (formular web).
o	Blocare/deblocare device-uri după IP (printr-o regulă UFW deny from <ip>).
o	Vizualizare device-uri active (din dnsmasq.leases).
o	Afișarea vitezei Internet (prin integrarea cu speedtest-cli).
o	Buton de reboot (folosind sudo reboot cu NOPASSWD în visudo).
•	Autentificare de bază (username/parolă hardcodate în config).
•	Layout simplu, responsive, text-based (HTML templates integrate cu Flask).

     



2.6. Servicii și systemd
Pentru pornirea automată la boot am configurat:
•	bridge-br0.service – configurează bridge-ul.
•	dnsmasq.service – DHCP/DNS.
•	hostapd.service – Wi-Fi AP (opțional, pentru hotspot).
•	ufw.service – firewall.
•	display-status.service – script Python pentru LCD.
•	ufw-web.service – server Flask pe portul 8080.

3. Fluxul funcțional al routerului
1.	Raspberry Pi pornește → systemd configurează bridge-ul și adresele IP.
2.	dnsmasq oferă IP-uri clientelor (telefon, laptop etc.).
3.	UFW/iptables fac NAT și filtrează traficul conform regulilor.
4.	LCD-ul se aprinde și începe să afișeze:
o	lista device-urilor active în timp real,
o	viteza la Internet (Mbps down/up),
o	ora curentă.
5.	UI Web este accesibil pe http://192.168.50.1:8080, unde adminul poate:
o	vedea regulile firewall,
o	adăuga sau șterge reguli,
o	bloca/debloca device-uri,
o	vedea device-urile active și viteza Internet,
o	da reboot la router.

4. Concluzii
Prin acest proiect, Raspberry Pi 4 a fost transformat într-un router complet funcțional cu:
•	Routare și bridge LAN/Wi-Fi,
•	Firewall avansat și reguli administrabile,
•	UI hardware (LCD) pentru monitorizare rapidă,
•	UI web (Flask) pentru administrare remote,
•	Automatizare completă prin systemd.
Avantaje:
•	Sistem extensibil (se pot adăuga grafice, logging, control parental etc.).
•	Interfață duală: locală (LCD) și remote (web).
•	Siguranță și control total asupra traficului.
Limitări:
•	Puterea de procesare a Raspberry Pi e modestă → potrivit pentru rețele mici.
•	Speedtest-ul constant poate consuma trafic și CPU (se poate rula la intervale mai mari).

5. Tehnologii folosite
•	Raspberry Pi OS (Debian)
•	Bridge-utils / iproute2 pentru networking
•	dnsmasq pentru DHCP/DNS
•	ufw + iptables pentru firewall
•	Flask pentru interfață web
•	Adafruit Blinka + CircuitPython RGB Display pentru ILI9341
•	Pillow (PIL) pentru randare grafică
•	systemd pentru automatizare la boot

