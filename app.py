#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Application Streamlit pour visualiser les données IDS en temps réel
générées par le script zeek_to_nslkdd_v2.py.
"""

import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import datetime
import pickle
import sys
import traceback

# Configuration de la page
st.set_page_config(
    page_title="IDS Intelligent - Surveillance en temps réel",
    page_icon="🛡️",
    layout="wide"
)

# Chemin vers le fichier CSV et le modèle
CSV_PATH = "/home/admin_web/Documents/IDS-Intelligent/resultats.csv"
MODEL_PATH = "/home/admin_web/Documents/IDS-Intelligent/xgboost_full_pipeline.pkl"

# Vérifier si sklearn est installé
sklearn_installed = False
try:
    import sklearn
    sklearn_installed = True
    st.sidebar.success("scikit-learn est installé: version " + sklearn.__version__)
except ImportError:
    st.sidebar.error("scikit-learn n'est pas installé. Exécutez: pip install scikit-learn")
    st.sidebar.code("pip install scikit-learn")

# Vérifier l'existence du modèle
model_exists = os.path.exists(MODEL_PATH)
st.sidebar.write(f"Fichier modèle existe: {model_exists}")
if model_exists:
    st.sidebar.write(f"Taille du fichier: {os.path.getsize(MODEL_PATH)} octets")
    st.sidebar.write(f"Date de modification: {datetime.datetime.fromtimestamp(os.path.getmtime(MODEL_PATH)).strftime('%Y-%m-%d %H:%M:%S')}")

# Ajouter une option pour activer/désactiver la prédiction
use_model = st.sidebar.checkbox("Activer la prédiction d'attaques", value=model_exists and sklearn_installed)

# Message de débogage dans la barre latérale
st.sidebar.write("### Informations système")
st.sidebar.write(f"Version de Python: {sys.version}")
st.sidebar.write(f"Version de pandas: {pd.__version__}")

# Tenter d'afficher la version de XGBoost
try:
    import xgboost as xgb
    st.sidebar.write(f"Version de XGBoost: {xgb.__version__}")
except ImportError:
    st.sidebar.error("XGBoost n'est pas installé")
except Exception as e:
    st.sidebar.error(f"Erreur lors de la vérification de XGBoost: {e}")

# Noms des colonnes à afficher (correspondant au format NSL-KDD)
column_names = {
    'duration': 'Durée',
    'protocol_type': 'Protocole',
    'service': 'Service',
    'flag': 'Drapeau',
    'src_bytes': 'Octets src',
    'dst_bytes': 'Octets dst',
    'wrong_fragment': 'Fragments erronés',
    'hot': 'Hot',
    'logged_in': 'Connecté',
    'num_compromised': 'Nb compromis',
    'count': 'Compte',
    'srv_count': 'Compte srv',
    'serror_rate': 'Taux err syn',
    'srv_serror_rate': 'Taux err syn srv',
    'rerror_rate': 'Taux err rej',
    'attack_pred': 'Prédiction',
    'attack_prob': 'Probabilité'
}

# Chargement du modèle avec gestion d'erreur détaillée
@st.cache_resource
def load_model():
    if not model_exists or not use_model or not sklearn_installed:
        return None
        
    try:
        with open(MODEL_PATH, 'rb') as f:
            saved_dict = pickle.load(f)
        
        # Vérifier les clés requises
        required_keys = ['model', 'scaler', 'label_encoders', 'columns']
        for key in required_keys:
            if key not in saved_dict:
                st.sidebar.error(f"Clé manquante dans le modèle chargé: {key}")
                return None
        
        st.sidebar.success("Structure du modèle validée avec succès")
        
        return saved_dict
    except Exception as e:
        error_msg = f"Erreur lors du chargement du modèle: {str(e)}"
        stack_trace = traceback.format_exc()
        st.sidebar.error(error_msg)
        st.sidebar.code(stack_trace)
        return None

# Fonction pour prétraiter les données
def preprocess_data(df, pipeline):
    if pipeline is None:
        return df
    
    try:
        # Copier le DataFrame pour ne pas modifier l'original
        df_copy = df.copy()
        
        # Vérifier si toutes les colonnes nécessaires sont présentes
        expected_columns = pipeline['columns']
        missing_columns = [col for col in expected_columns if col not in df_copy.columns]
        
        # Ajouter des colonnes manquantes avec des valeurs par défaut
        for col in missing_columns:
            df_copy[col] = 0
        
        # Encoder les colonnes catégorielles
        for col, encoder in pipeline['label_encoders'].items():
            if col in df_copy.columns:
                try:
                    # Gérer les valeurs inconnues (non vues pendant l'entraînement)
                    df_copy[col] = df_copy[col].apply(lambda x: x if x in encoder.classes_ else encoder.classes_[0])
                    df_copy[col] = encoder.transform(df_copy[col])
                except Exception as e:
                    st.warning(f"Erreur lors de l'encodage de la colonne {col}: {e}")
                    df_copy[col] = 0
        
        # Sélectionner uniquement les colonnes nécessaires dans le bon ordre
        features = df_copy[expected_columns].copy()
        
        # Appliquer le scaler si disponible
        if 'scaler' in pipeline and pipeline['scaler'] is not None:
            features = pd.DataFrame(pipeline['scaler'].transform(features), 
                                    columns=expected_columns)
            
        return features
    except Exception as e:
        st.error(f"Erreur lors du prétraitement des données: {e}")
        return df

# Fonction pour effectuer la prédiction
def predict_attacks(df, pipeline):
    if pipeline is None or df.empty:
        return df
    
    try:
        # Prétraiter les données
        features = preprocess_data(df, pipeline)
        
        # Faire la prédiction
        predictions = pipeline['model'].predict(features)
        probabilities = pipeline['model'].predict_proba(features)
        
        # Ajouter les prédictions au DataFrame original
        df_result = df.copy()
        df_result['attack_pred'] = predictions
        df_result['attack_prob'] = np.max(probabilities, axis=1)
        
        # Convertir les valeurs numériques en libellés
        df_result['attack_pred'] = df_result['attack_pred'].map({0: 'normal', 1: 'attack'})
        
        # Formater les probabilités en pourcentage
        df_result['attack_prob'] = (df_result['attack_prob'] * 100).round(2).astype(str) + '%'
        
        return df_result
    except Exception as e:
        error_msg = f"Erreur lors de la prédiction: {str(e)}"
        stack_trace = traceback.format_exc()
        st.sidebar.error(error_msg)
        st.sidebar.code(stack_trace)
        return df

# Fonction pour charger les données
def load_data():
    try:
        if os.path.exists(CSV_PATH):
            df = pd.read_csv(CSV_PATH)
            
            # Trier les données pour afficher les plus récentes en haut
            if 'duration' in df.columns:
                df = df.sort_values(by='duration', ascending=False)
            
            # Afficher un échantillon des premières lignes dans la barre latérale pour debug
            with st.sidebar.expander("Aperçu des données"):
                st.dataframe(df.head(3))
            
            return df
        else:
            st.sidebar.warning(f"Fichier CSV non trouvé: {CSV_PATH}")
            return pd.DataFrame()
    except Exception as e:
        st.error(f"Erreur lors de la lecture du fichier CSV: {e}")
        return pd.DataFrame()

# Fonction pour renommer les colonnes avec des noms plus lisibles
def rename_columns(df):
    # Créer une copie pour éviter de modifier l'original
    df_display = df.copy()
    
    # Renommer uniquement les colonnes qui existent dans notre mapping
    rename_dict = {col: column_names[col] for col in df.columns if col in column_names}
    if rename_dict:
        df_display = df_display.rename(columns=rename_dict)
    
    return df_display

# Fonction pour mettre en évidence les attaques
def highlight_attacks(df):
    # Si la colonne de prédiction n'existe pas, retourner le DataFrame sans style
    if 'attack_pred' not in df.columns:
        return df
    
    try:
        # Appliquer un style de base au dataframe
        def style_row(row):
            color = 'background-color: rgba(255, 80, 80, 0.3)' if row['attack_pred'] == 'attack' else ''
            return [color for _ in range(len(row))]
        
        return df.style.apply(style_row, axis=1)
    except Exception as e:
        st.warning(f"Erreur lors de l'application du style: {e}")
        return df

# Titre principal
st.title("🛡️ Système de détection d'intrusion intelligent")
st.subheader("Visualisation en temps réel des logs Zeek convertis au format NSL-KDD")

# Charger le modèle
pipeline = load_model() if use_model and sklearn_installed else None

# Initialiser le compteur de lignes précédent s'il n'existe pas
if 'previous_row_count' not in st.session_state:
    st.session_state.previous_row_count = 0

# Variables pour le rafraîchissement
refresh_interval = st.sidebar.slider("Intervalle de rafraîchissement (secondes)", min_value=5, max_value=60, value=30, step=5)

# Créer une mise en page à trois colonnes pour les informations
col1, col2, col3 = st.columns(3)

# Afficher les informations sur le système
with col1:
    st.metric("Réseau surveillé", "OPNPF (192.168.58.0/24)")
with col2:
    st.metric("Réseau surveillé", "DMZ (192.168.57.0/24)")
with col3:
    if use_model:
        if pipeline:
            st.success("Modèle IDS chargé ✓")
        else:
            st.error("Modèle IDS non chargé ✗")
    else:
        st.info("Prédiction d'attaques désactivée")

# Créer un placeholder pour le tableau
data_table = st.empty()

# Créer un placeholder pour les métriques d'attaque
attack_metrics = st.empty()

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
    
    # Appliquer le modèle pour obtenir les prédictions
    if use_model and pipeline and not df.empty and sklearn_installed:
        try:
            df = predict_attacks(df, pipeline)
            prediction_status = "✓ Prédictions appliquées"
        except Exception as e:
            prediction_status = f"✗ Erreur de prédiction: {str(e)}"
    else:
        prediction_status = "Prédiction désactivée ou modèle non disponible"
    
    st.sidebar.write(f"Status prédiction: {prediction_status}")
    
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
            # Renommer les colonnes pour l'affichage
            df_display = rename_columns(df)
            
            # Afficher le tableau (avec ou sans mise en évidence des attaques)
            try:
                if 'attack_pred' in df.columns:
                    styled_df = highlight_attacks(df_display)
                    st.dataframe(styled_df, use_container_width=True)
                else:
                    st.dataframe(df_display, use_container_width=True)
            except Exception as e:
                # Fallback si le style échoue
                st.dataframe(df_display, use_container_width=True)
                st.warning(f"Problème d'affichage du style: {e}")
            
            # Afficher le nombre total d'enregistrements
            st.info(f"Nombre total d'enregistrements: {current_row_count}")
    
    # Afficher les métriques d'attaque si le modèle est chargé
    if use_model and pipeline and 'attack_pred' in df.columns and not df.empty:
        with attack_metrics.container():
            attack_count = (df['attack_pred'] == 'attack').sum()
            normal_count = (df['attack_pred'] == 'normal').sum()
            
            metrics_cols = st.columns(3)
            metrics_cols[0].metric("Connexions normales", normal_count)
            metrics_cols[1].metric("Attaques détectées", attack_count)
            
            if current_row_count > 0:
                attack_percentage = (attack_count / current_row_count) * 100
                metrics_cols[2].metric("Taux d'attaques", f"{attack_percentage:.2f}%")
    
    # Mettre à jour l'horodatage du dernier rafraîchissement
    last_refresh_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    refresh_time_text.markdown(f"<div style='text-align: right;'><i>Dernier rafraîchissement: {last_refresh_time}</i></div>", unsafe_allow_html=True)
    
    # Attendre le prochain rafraîchissement
    time.sleep(refresh_interval) 
