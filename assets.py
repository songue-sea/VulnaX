"""Pour la gestion des assets """
import nmap
import os
from datetime import datetime
from xmlrpc.client import Boolean
import requests

import sqlalchemy.sql.sqltypes
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from apscheduler.schedulers.background import BackgroundScheduler

from check_vuln import check_vuln

#Configuration
TELEGRAM_BOT_TOKEN = "token_bot"
TELEGRAM_CHAT_ID = "chat_id"

#Configuration du base de données
DATABASE_URL = 'sqlite:///vulnax.db'
Base = declarative_base() # Crée une classe de base pour définir des classes d'entités.
engine = create_engine(DATABASE_URL)  #creer une connexion à la BD
session = sessionmaker(bind=engine) #Crée une session pour interagir avec la base de données (ajout, suppression, mise à jour de données).
session = session()

# Modèles Asset
class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String,nullable=False)
    ip_address = Column(String,nullable=False,unique=True)
    os = Column(String,nullable=True)
    date_added = Column(DateTime, default=datetime.now)

    def __repr__(self):
        return f"Assets(name={self.name}, ip_address={self.ip_address}, os={self.os})"

#Modèle ScanTask
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


#Fonction pour ajouter une tầche de scan plannifiée
def add_scan_task(asset_id, frequency):
    task = ScanTask(asset_id=asset_id, frequency=frequency)
    session.add(task)
    session.commit()
    print(f"[+] Tache de scan ajoutée pour Asset ID {asset_id}  - Fréquence {frequency}")
    schedule_task(task)

# Fontion pour plannifier une tache avec APScheduler
def schedule_task(task):
    asset = session.query(Asset).filter_by(id=task.asset_id).first()
    if not asset:
        print(f"[!] Asset non trouvé pour la tâche {task.id}")
        return

    if task.frequency == 'daily':
        scheduler.add_job(scan, 'interval', days=1, args=[asset.ip_address], id=str(task.id))
    elif task.frequency == 'hourly':
        scheduler.add_job(scan, 'interval', hours=1, args=[asset.ip_address], id=str(task.id))

    print(f"[+] Tâche plannifiée pour {asset.ip_address} ({task.frequency})")

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
                cpe = nm[host][proto][port]['cpe']
                print(f"{host}:{port} --- {service}")
                print(f"{host}:{port} --- {cpe}")
                vuln = check_vuln(cpe)
                if vuln:
                    results.append({
                        'host': host,
                        'port': port,
                        'service': service,
                        'vulnerabilities': vuln
                    })



# Gestion des assets
def add_asset(name, ip_address, os=None):
    """Fonction pour ajouter un asset"""
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
        print("\n--- Liste des Assets ---")
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
        print(f"[!] Asset introuvable")

# Menu
def manage_assets():
    while True:
        print("\n--- Vulnax Asset Manager --- ")
        print("1. Ajouter un Asset")
        print("2. Lister les assets")
        print("3. Supprimer un asset")
        print("4. Quitter")
        choice = input("Entrez votre choix : ")

        if choice == "1":
            name = input("Nom de l'asset : ")
            ip_address = input("Adresse IP : ")
            os = input("Système d'exploitation(optionnel) : ")
            add_asset(name, ip_address, os)
        elif choice == "2":
            list_assets()
        elif choice == "3":
            asset_id = int(input("ID de l'Asset à supprimer : "))
            delete_asset(asset_id)
        elif choice == "4":
            print("[+] Bye bye chef !!")
            break
        else:
            print(f"[!] choix invalide")

if __name__ == "__main__":
    manage_assets()