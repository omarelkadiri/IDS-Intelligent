#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interface web Streamlit pour le prédicteur en temps réel de détection d'attaques réseau.
"""

import os
import time
import pickle
import pandas as pd
import numpy as np
from collections import deque
from datetime import datetime
from io import StringIO
import warnings
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from threading import Thread
import queue
warnings.filterwarnings('ignore')

class RealtimePredictorWeb:
    def __init__(self, input_file, model_path, max_history=500):
        """
        Initialise le prédicteur en temps réel avec interface web.

        Args:
            input_file (str): Chemin vers le fichier CSV généré par zeek_to_nslkdd
            model_path (str): Chemin vers le fichier du modèle XGBoost
            max_history (int): Nombre maximum de prédictions à conserver
        """
        self.input_file = input_file
        self.model_path = model_path
        self.max_history = max_history
        self.last_position = 0
        self.predictions_history = deque(maxlen=max_history)
        self.prediction_queue = queue.Queue()
        
        # Charger le modèle et les préprocesseurs
        self.load_model()
        
        # Vérifier que le fichier d'entrée existe
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Le fichier {input_file} n'existe pas")

    def load_model(self):
        """Charge le modèle XGBoost et les préprocesseurs."""
        try:
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
            
            self.model = data['model']
            self.scaler = data['scaler']
            self.label_encoders = data['label_encoders']
            self.columns = data['columns']
            
        except Exception as e:
            raise Exception(f"Erreur lors du chargement du modèle: {e}")

    def preprocess_data(self, df):
        """Prétraite les données pour la prédiction."""
        df_processed = df.copy()
        
        for col, encoder in self.label_encoders.items():
            if col in df_processed.columns:
                unknown_mask = ~df_processed[col].isin(encoder.classes_)
                if unknown_mask.any():
                    df_processed.loc[unknown_mask, col] = encoder.classes_[0]
                df_processed[col] = encoder.transform(df_processed[col])
        
        numeric_cols = df_processed.select_dtypes(include=[np.number]).columns
        df_processed[numeric_cols] = self.scaler.transform(df_processed[numeric_cols])
        
        return df_processed[self.columns].values

    def predict(self, data):
        """Effectue la prédiction sur les données prétraitées."""
        return self.model.predict(data)

    def get_prediction_probability(self, data):
        """Obtient les probabilités de prédiction."""
        return self.model.predict_proba(data)

    def monitor_file(self):
        """Surveille le fichier d'entrée en temps réel et effectue des prédictions."""
        while True:
            try:
                current_size = os.path.getsize(self.input_file)
                
                if current_size > self.last_position:
                    with open(self.input_file, 'r') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                    
                    if new_lines:
                        if self.last_position == 0 and new_lines[0].startswith('duration'):
                            new_lines = new_lines[1:]
                        
                        df_new = pd.read_csv(StringIO(''.join(new_lines)), 
                                           names=self.columns)
                        
                        processed_data = self.preprocess_data(df_new)
                        predictions = self.predict(processed_data)
                        probabilities = self.get_prediction_probability(processed_data)
                        
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
                            prediction_info = {
                                'timestamp': timestamp,
                                'prediction': 'NORMAL' if pred == 1 else 'ATTACK',
                                'confidence': prob[1] if pred == 1 else prob[0],
                                'data': df_new.iloc[i].to_dict()
                            }
                            self.predictions_history.append(prediction_info)
                            self.prediction_queue.put(prediction_info)
                    
                    self.last_position = current_size
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Erreur lors de la surveillance: {e}")
                time.sleep(5)

    def get_statistics(self):
        """Retourne des statistiques sur les prédictions récentes."""
        if not self.predictions_history:
            return {"message": "Aucune prédiction disponible"}
        
        total = len(self.predictions_history)
        attacks = sum(1 for p in self.predictions_history if p['prediction'] == 'ATTACK')
        normals = total - attacks
        
        return {
            "total_predictions": total,
            "attacks": attacks,
            "normals": normals,
            "attack_rate": attacks/total if total > 0 else 0,
            "average_confidence": sum(p['confidence'] for p in self.predictions_history)/total if total > 0 else 0
        }

def main():
    st.set_page_config(
        page_title="IDS - Détection d'Intrusions en Temps Réel",
        page_icon="🛡️",
        layout="wide"
    )

    # Titre et description
    st.title("🛡️ Système de Détection d'Intrusions en Temps Réel")
    st.markdown("""
    Ce tableau de bord affiche en temps réel les prédictions du système de détection d'intrusions
    basé sur l'apprentissage automatique.
    """)

    # Initialisation du prédicteur
    try:
        predictor = RealtimePredictorWeb(
            input_file='nslkdd_format.csv',
            model_path='xgboost_full_pipeline.pkl',
            max_history=500
        )
        
        # Démarrer la surveillance dans un thread séparé
        monitor_thread = Thread(target=predictor.monitor_file, daemon=True)
        monitor_thread.start()
        
    except Exception as e:
        st.error(f"Erreur d'initialisation: {e}")
        return

    # Créer deux colonnes pour le layout
    col1, col2 = st.columns([2, 1])

    # Conteneurs pour les statistiques en temps réel
    stats_container = st.empty()
    total_container = st.empty()
    attacks_container = st.empty()
    rate_container = st.empty()
    
    # Conteneur pour le graphique
    chart_container = st.empty()
    
    # Conteneur pour les prédictions
    predictions_container = st.empty()

    # Fonction pour mettre à jour les statistiques
    def update_stats():
        stats = predictor.get_statistics()
        if "message" in stats:
            return
        
        with stats_container:
            st.subheader("📊 Statistiques en Temps Réel")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                total_container.metric("Total Prédictions", stats["total_predictions"])
            with col2:
                attacks_container.metric("Attaques Détectées", stats["attacks"])
            with col3:
                rate_container.metric("Taux d'Attaques", f"{stats['attack_rate']:.1%}")

    # Fonction pour mettre à jour le graphique
    def update_chart():
        if not predictor.predictions_history:
            return
            
        # Préparer les données pour le graphique
        df = pd.DataFrame([
            {
                'timestamp': p['timestamp'],
                'prediction': p['prediction'],
                'confidence': p['confidence']
            }
            for p in predictor.predictions_history
        ])
        
        # Créer le graphique avec Plotly
        fig = px.scatter(
            df,
            x='timestamp',
            y='confidence',
            color='prediction',
            title='Confiance des Prédictions en Temps Réel',
            labels={
                'timestamp': 'Heure',
                'confidence': 'Confiance',
                'prediction': 'Type'
            }
        )
        
        fig.update_layout(
            xaxis_title="Heure",
            yaxis_title="Confiance",
            showlegend=True
        )
        
        with chart_container:
            st.plotly_chart(fig, use_container_width=True, key=f"chart_{datetime.now().strftime('%Y%m%d%H%M%S')}")

    # Fonction pour mettre à jour les dernières prédictions
    def update_predictions():
        if not predictor.predictions_history:
            return
            
        with predictions_container:
            st.subheader("🔍 Dernières Prédictions")
            
            # Convertir l'historique des prédictions en DataFrame
            predictions_data = []
            for pred in reversed(list(predictor.predictions_history)):  # Inverser pour avoir les plus récentes en haut
                pred_data = {
                    'Timestamp': pred['timestamp'],
                    'Type': pred['prediction'],
                    'Confiance': f"{pred['confidence']:.1%}",
                    'Protocole': pred['data'].get('protocol_type', 'N/A'),
                    'Service': pred['data'].get('service', 'N/A'),
                    'Flag': pred['data'].get('flag', 'N/A'),
                    'Src Bytes': pred['data'].get('src_bytes', 'N/A'),
                    'Dst Bytes': pred['data'].get('dst_bytes', 'N/A')
                }
                predictions_data.append(pred_data)
            
            # Créer le DataFrame
            df_predictions = pd.DataFrame(predictions_data)
            
            # Définir le style conditionnel
            def highlight_attacks(row):
                if row['Type'] == 'ATTACK':
                    return ['background-color: #ffcdd2'] * len(row)  # Rouge clair
                return [''] * len(row)
            
            # Appliquer le style
            styled_df = df_predictions.style.apply(highlight_attacks, axis=1)
            
            # Afficher le tableau avec style
            st.dataframe(
                styled_df,
                use_container_width=True,
                hide_index=True,
                height=400
            )

    # Boucle principale de mise à jour
    while True:
        try:
            # Vérifier s'il y a de nouvelles prédictions
            try:
                while not predictor.prediction_queue.empty():
                    predictor.prediction_queue.get_nowait()
            except queue.Empty:
                pass
            
            # Mettre à jour l'interface
            update_stats()
            update_chart()
            update_predictions()
            
            # Attendre avant la prochaine mise à jour
            time.sleep(1)
            
        except Exception as e:
            st.error(f"Erreur de mise à jour: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main() 