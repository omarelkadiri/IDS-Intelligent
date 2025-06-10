#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ce script lit en temps réel la sortie de zeek_to_nslkdd.py et effectue des prédictions
à l'aide du modèle XGBoost entraîné pour détecter les attaques réseau.
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
warnings.filterwarnings('ignore')

class RealtimePredictor:
    def __init__(self, input_file, model_path, max_history=500):
        """
        Initialise le prédicteur en temps réel.

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
        
        # Charger le modèle et les préprocesseurs
        self.load_model()
        
        # Vérifier que le fichier d'entrée existe
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Le fichier {input_file} n'existe pas")
            
        print(f"Prédicteur initialisé avec succès!")
        print(f"Fichier d'entrée: {input_file}")
        print(f"Modèle: {model_path}")
        print(f"Historique maximum: {max_history} prédictions")

    def load_model(self):
        """Charge le modèle XGBoost et les préprocesseurs."""
        try:
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
            
            self.model = data['model']
            self.scaler = data['scaler']
            self.label_encoders = data['label_encoders']
            self.columns = data['columns']
            
            print("Modèle et préprocesseurs chargés avec succès!")
            
        except Exception as e:
            raise Exception(f"Erreur lors du chargement du modèle: {e}")

    def preprocess_data(self, df):
        """
        Prétraite les données pour la prédiction.

        Args:
            df (pd.DataFrame): Données brutes à prétraiter

        Returns:
            np.array: Données prétraitées
        """
        # Copier les données pour éviter les modifications sur l'original
        df_processed = df.copy()
        
        # Encoder les variables catégorielles
        for col, encoder in self.label_encoders.items():
            if col in df_processed.columns:
                # Gérer les valeurs inconnues
                unknown_mask = ~df_processed[col].isin(encoder.classes_)
                if unknown_mask.any():
                    print(f"Attention: Valeurs inconnues trouvées dans la colonne {col}")
                    df_processed.loc[unknown_mask, col] = encoder.classes_[0]
                
                df_processed[col] = encoder.transform(df_processed[col])
        
        # Appliquer le scaler
        numeric_cols = df_processed.select_dtypes(include=[np.number]).columns
        df_processed[numeric_cols] = self.scaler.transform(df_processed[numeric_cols])
        
        return df_processed[self.columns].values

    def predict(self, data):
        """
        Effectue la prédiction sur les données prétraitées.

        Args:
            data (np.array): Données prétraitées

        Returns:
            np.array: Prédictions (0: normal, 1: attaque)
        """
        return self.model.predict(data)

    def get_prediction_probability(self, data):
        """
        Obtient les probabilités de prédiction.

        Args:
            data (np.array): Données prétraitées

        Returns:
            np.array: Probabilités de prédiction
        """
        return self.model.predict_proba(data)

    def monitor_file(self, interval=1):
        """
        Surveille le fichier d'entrée en temps réel et effectue des prédictions.

        Args:
            interval (int): Intervalle de vérification en secondes
        """
        print(f"\nDébut de la surveillance du fichier {self.input_file}")
        print("Appuyez sur Ctrl+C pour arrêter...")
        
        try:
            while True:
                # Vérifier si le fichier a été modifié
                current_size = os.path.getsize(self.input_file)
                
                if current_size > self.last_position:
                    # Lire les nouvelles lignes
                    with open(self.input_file, 'r') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                    
                    if new_lines:
                        # Ignorer l'en-tête si c'est la première lecture
                        if self.last_position == 0 and new_lines[0].startswith('duration'):
                            new_lines = new_lines[1:]
                        
                        # Convertir les nouvelles lignes en DataFrame
                        df_new = pd.read_csv(StringIO(''.join(new_lines)), 
                                           names=self.columns)
                        
                        # Prétraiter les données
                        processed_data = self.preprocess_data(df_new)
                        
                        # Effectuer les prédictions
                        predictions = self.predict(processed_data)
                        probabilities = self.get_prediction_probability(processed_data)
                        
                        # Enregistrer les prédictions avec horodatage
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
                            prediction_info = {
                                'timestamp': timestamp,
                                'prediction': 'NORMAL' if pred == 0 else 'ATTACK',
                                'confidence': prob[0] if pred == 0 else prob[1],
                                'data': df_new.iloc[i].to_dict()
                            }
                            self.predictions_history.append(prediction_info)
                            
                            # Afficher la prédiction
                            self.display_prediction(prediction_info)
                    
                    # Mettre à jour la position
                    self.last_position = current_size
                
                # Attendre l'intervalle spécifié
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nSurveillance arrêtée par l'utilisateur.")
        except Exception as e:
            print(f"\nErreur lors de la surveillance: {e}")

    def display_prediction(self, prediction_info):
        """
        Affiche une prédiction de manière formatée.

        Args:
            prediction_info (dict): Informations sur la prédiction
        """
        print("\n" + "="*80)
        print(f"Timestamp: {prediction_info['timestamp']}")
        print(f"Prédiction: {prediction_info['prediction']}")
        print(f"Confiance: {prediction_info['confidence']:.2%}")
        print("\nDétails de la connexion:")
        for key, value in prediction_info['data'].items():
            print(f"  {key}: {value}")
        print("="*80)

    def get_statistics(self):
        """
        Retourne des statistiques sur les prédictions récentes.

        Returns:
            dict: Statistiques des prédictions
        """
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
    """Fonction principale."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Prédicteur en temps réel pour la détection d\'attaques réseau')
    parser.add_argument('--input', type=str, default='nslkdd_format.csv',
                        help='Fichier CSV généré par zeek_to_nslkdd (par défaut: nslkdd_format.csv)')
    parser.add_argument('--model', type=str, default='xgboost_full_pipeline.pkl',
                        help='Chemin vers le modèle XGBoost (par défaut: xgboost_full_pipeline.pkl)')
    parser.add_argument('--interval', type=int, default=1,
                        help='Intervalle de vérification en secondes (par défaut: 1)')
    parser.add_argument('--history', type=int, default=500,
                        help='Nombre maximum de prédictions à conserver (par défaut: 500)')
    
    args = parser.parse_args()
    
    try:
        predictor = RealtimePredictor(
            input_file=args.input,
            model_path=args.model,
            max_history=args.history
        )
        predictor.monitor_file(interval=args.interval)
        
    except Exception as e:
        print(f"Erreur: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 