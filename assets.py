"""Pour la gestion des assets """
import os
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker


#Configuration
TELEGRAM_BOT_TOKEN = "token_bot"
TELEGRAM_CHAT_ID = "chat_id"
CVE_API_URL = "https://cve.circl.lu/api/search"

#Configuration du base de données

DATABASE_URL = 'sqlite:///vulnax.db'
Base = declarative_base() # Crée une classe de base pour définir des classes d'entités.
engine = create_engine(DATABASE_URL)  #creer une connexion à la BD
session = sessionmaker(bind=engine) #Crée une session pour interagir avec la base de données (ajout, suppression, mise à jour de données).
session = session()

class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String,nullable=False)
    ip_address = Column(String,nullable=False,unique=True)
    os = Column(String,nullable=True)
    date_added = Column(DateTime, default=datetime.now)

    def __repr__(self):
        return f"Assets(name={self.name}, ip_address={self.ip_address}, os={self.os})"

Base.metadata.create_all(engine)
print("[+] Base de données initialisée")

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