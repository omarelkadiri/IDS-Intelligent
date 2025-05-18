#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Application Streamlit pour visualiser les données IDS en temps réel
générées par le script zeek_to_nslkdd_v2.py.
"""

import streamlit as st
import pandas as pd
import time
import os
import datetime

# Configuration de la page
st.set_page_config(
    page_title="IDS Intelligent - Surveillance en temps réel",
    page_icon="🛡️",
    layout="wide"
)

# Chemin vers le fichier CSV
CSV_PATH = "/home/admin_web/Documents/IDS-Intelligent/resultats.csv"

# Fonction pour charger les données
def load_data():
    try:
        if os.path.exists(CSV_PATH):
            df = pd.read_csv(CSV_PATH)
            
            # Trier les données pour afficher les plus récentes en haut
            if 'duration' in df.columns:
                df = df.sort_values(by='duration', ascending=False)
            
            return df
        else:
            return pd.DataFrame()
    except Exception as e:
        st.error(f"Erreur lors de la lecture du fichier CSV: {e}")
        return pd.DataFrame()

# Titre principal
st.title("🛡️ Système de détection d'intrusion intelligent")
st.subheader("Visualisation en temps réel des logs Zeek convertis au format NSL-KDD")

# Initialiser le compteur de lignes précédent s'il n'existe pas
if 'previous_row_count' not in st.session_state:
    st.session_state.previous_row_count = 0

# Variables pour le rafraîchissement
refresh_interval = 30  # secondes
auto_refresh = True

# Créer une mise en page à trois colonnes pour les informations
col1, col2, col3 = st.columns(3)

# Afficher les informations sur le système
with col1:
    st.metric("Réseau surveillé", "OPNPF (192.168.58.0/24)")
with col2:
    st.metric("Réseau surveillé", "DMZ (192.168.57.0/24)")
with col3:
    st.info(f"Rafraîchissement automatique: {refresh_interval} secondes")

# Créer un placeholder pour le tableau
data_table = st.empty()

# Créer un placeholder pour le message de statut
status_message = st.empty()

# Créer un placeholder pour le bouton de rafraîchissement
refresh_button_col, _ = st.columns([1, 5])
with refresh_button_col:
    if st.button("Rafraîchir maintenant"):
        # Ne rien faire ici, le code continuera avec le rafraîchissement normal
        pass

# Afficher l'horodatage du dernier rafraîchissement
last_refresh_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
refresh_time_text = st.empty()
refresh_time_text.markdown(f"<div style='text-align: right;'><i>Dernier rafraîchissement: {last_refresh_time}</i></div>", unsafe_allow_html=True)

# Boucle principale
while True:
    # Charger les données
    df = load_data()
    
    # Calculer le nombre de nouvelles lignes
    current_row_count = len(df)
    new_rows = max(0, current_row_count - st.session_state.previous_row_count)
    
    # Mettre à jour le nombre précédent de lignes
    st.session_state.previous_row_count = current_row_count
    
    # Afficher un message sur les nouvelles lignes
    if new_rows > 0:
        status_message.success(f"✨ {new_rows} nouvelles connexions détectées!")
    else:
        status_message.info("Aucune nouvelle connexion détectée depuis le dernier rafraîchissement.")
    
    # Afficher le tableau de données
    with data_table.container():
        st.markdown("### 📋 Tableau des connexions détectées")
        
        if df.empty:
            st.warning("Aucune donnée disponible. Vérifiez que le script zeek_to_nslkdd_v2.py est en cours d'exécution.")
        else:
            # Version simplifiée : afficher le tableau sans style pour éviter les erreurs
            st.dataframe(df, use_container_width=True)
            
            # Afficher le nombre total d'enregistrements
            st.info(f"Nombre total d'enregistrements: {current_row_count}")
    
    # Mettre à jour l'horodatage du dernier rafraîchissement
    last_refresh_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    refresh_time_text.markdown(f"<div style='text-align: right;'><i>Dernier rafraîchissement: {last_refresh_time}</i></div>", unsafe_allow_html=True)
    
    # Attendre le prochain rafraîchissement
    time.sleep(refresh_interval) 
