import nmap
import os
from datetime import datetime
from xmlrpc.client import Boolean
import requests

import sqlalchemy.sql.sqltypes
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from apscheduler.schedulers.background import BackgroundScheduler

# Configuration
TELEGRAM_BOT_TOKEN = "token_bot"
TELEGRAM_CHAT_ID = "chat_id"

# Configuration de la base de données
DATABASE_URL = 'sqlite:///vulnax.db'
Base = declarative_base()
engine = create_engine(DATABASE_URL)
session = sessionmaker(bind=engine)()

# Modèles
class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    ip_address = Column(String, nullable=False, unique=True)
    os = Column(String, nullable=True)
    date_added = Column(DateTime, default=datetime.now)

class ScanTask(Base):
    __tablename__ = 'scan_tasks'
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, nullable=False)
    frequency = Column(String, nullable=False)
    last_run = Column(DateTime, nullable=True)
    active = Column(sqlalchemy.sql.sqltypes.BOOLEAN, default=True)

Base.metadata.create_all(engine)
scheduler = BackgroundScheduler()
scheduler.start()

print("[+] Base de données initialisée")

# Fonctions

def add_asset(name, ip_address, os=None):
    try:
        new_asset = Asset(name=name, ip_address=ip_address, os=os)
        session.add(new_asset)
        session.commit()
        print(f"[+] Asset ajouté : {name} ({ip_address})")
    except Exception as e:
        session.rollback()
        print(f"[!] Erreur lors de l'ajout de l'asset : {e}")


def list_assets():
    assets = session.query(Asset).all()
    if assets:
        for asset in assets:
            print(f"{asset.id} - {asset.name} - {asset.ip_address} - {asset.os} - {asset.date_added}")
    else:
        print("[!] Aucun asset trouvé")


def delete_asset(asset_id):
    asset = session.query(Asset).filter_by(id=asset_id).first()
    if asset:
        session.delete(asset)
        session.commit()
        print(f"[+] Asset supprimé : {asset.name} ({asset.ip_address})")
    else:
        print("[!] Asset introuvable")


def scan(target):
    print(f"[+] Lancement du scan sur {target}")
    nm = nmap.PortScanner()
    nm.scan(target)
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                cpe = nm[host][proto][port].get('cpe', '')
                vuln = check_vuln(cpe)
                if vuln:
                    results.append({
                        'host': host,
                        'port': port,
                        'service': service,
                        'vulnerabilities': vuln
                    })
    return results


def add_scan_task(asset_id, frequency):
    task = ScanTask(asset_id=asset_id, frequency=frequency)
    session.add(task)
    session.commit()
    print(f"[+] Tache de scan ajoutée pour Asset ID {asset_id} - Fréquence {frequency}")
    schedule_task(task)


def schedule_task(task):
    asset = session.query(Asset).filter_by(id=task.asset_id).first()
    if not asset:
        print(f"[!] Asset non trouvé pour la tâche {task.id}")
        return

    if task.frequency == 'daily':
        scheduler.add_job(scan, 'interval', days=1, args=[asset.ip_address], id=str(task.id))
    elif task.frequency == 'hourly':
        scheduler.add_job(scan, 'interval', hours=1, args=[asset.ip_address], id=str(task.id))

    print(f"[+] Tâche planifiée pour {asset.ip_address} ({task.frequency})")


# API Vulnérabilités
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API_URL = f"{CVE_API_URL}?resultsPerPage=5&cpeName=cpe:2.3:"


def get_cve_from_cpe(cpeName):
    url = f"{CPE_API_URL}{cpeName}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print("An error occurred:", e)
    return None


def check_vuln(service):
    cpe_name = service.removeprefix("cpe:/")
    vuln = get_cve_from_cpe(cpe_name)
    if vuln:
        return vuln.get('vulnerabilities', [])
    return None


if __name__ == "__main__":
    while True:
        print("\n--- Vulnax Asset Manager ---")
        print("1. Ajouter un Asset")
        print("2. Lister les Assets")
        print("3. Supprimer un Asset")
        print("4. Quitter")
        choice = input("Entrez votre choix : ")
        if choice == "1":
            name = input("Nom de l'asset : ")
            ip = input("Adresse IP : ")
            os = input("Système d'exploitation : ")
            add_asset(name, ip, os)
        elif choice == "2":
            list_assets()
        elif choice == "3":
            asset_id = int(input("ID de l'Asset : "))
            delete_asset(asset_id)
        elif choice == "4":
            print("[+] Bye bye chef !!")
            break
        else:
            print("[!] Choix invalide")
