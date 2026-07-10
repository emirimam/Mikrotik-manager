# MikroTik Fleet Manager

Web aplikacija za masovno upravljanje MikroTik uređajima putem SSH-a.

## Instalacija

```bash
pip install -r requirements.txt
python app.py
```

Otvori `http://localhost:5000` u pregledaču.

## Korištenje

1. **SSH Pristup** – unesi korisničko ime, lozinku i port (default 22)
2. **Ciljani uređaji** – unesi IP adrese, jedna po liniji
3. **Odaberi akciju** – iz liste predefinisanih akcija ili "Prilagođena komanda"
4. **Izvrši** – aplikacija se spaja na sve uređaje paralelno i prikazuje rezultate

## Ugrađene akcije

### Firewall / Routing
- Blokiraj IP adresu (address-list)
- Ukloni IP iz blackliste
- Postavi DNS servere
- Postavi NTP server

### Korisnici i lozinke
- Dodaj korisnika
- Promijeni lozinku
- Ukloni korisnika

### Update / Upgrade
- Provjeri i instaliraj update
- Reboot uređaja
- Kreiraj backup

### Prilagođena komanda
- Unesi bilo koje RouterOS komande (jedna po liniji)

## Podešavanja

- **Paralelno** – koliko uređaja se obrađuje istovremeno (default 10, max 50)
- Rezultati se prikazuju u realnom vremenu kako pristižu

## Produkcija

Za produkcijsku upotrebu preporučuje se Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -k gevent --bind 0.0.0.0:5000 app:app
```

Ili pokretanje kao systemd servis.
