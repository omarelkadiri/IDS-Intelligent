# IDS-Intelligent : Système de Détection d'Intrusion basé sur l'IA

Ce projet implémente un système de détection d'intrusion (IDS) intelligent qui utilise Zeek (anciennement Bro) pour la capture de trafic réseau et des modèles d'apprentissage automatique pour la détection d'anomalies en temps réel.

## Fonctionnalités

- Capture et analyse du trafic réseau avec Zeek
- Conversion des logs Zeek en format NSL-KDD
- Détection d'intrusions en temps réel
- Interface web pour la visualisation des alertes
- Intégration avec ElasticSearch (optionnelle)

## Prérequis

### Système d'exploitation
- Linux (Ubuntu 20.04 LTS ou plus récent recommandé)
- 4GB RAM minimum (8GB recommandé)
- 20GB d'espace disque minimum

### Outils système
- Python 3.8 ou plus récent
- pip (gestionnaire de paquets Python)
- Zeek (anciennement Bro)
- Git

## Installation

### 1. Installation de Zeek

```bash
# Ajouter le dépôt Zeek
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Mettre à jour les paquets
sudo apt update

# Installer Zeek
sudo apt install zeek

# Configurer Zeek pour démarrer au boot
sudo systemctl enable zeek
sudo systemctl start zeek
```

### 2. Installation des dépendances Python

```bash
# Cloner le dépôt
git clone https://github.com/omarelkadiri/IDS-Intelligent.git
cd IDS-Intelligent

# Créer un environnement virtuel (recommandé)
python -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

### 3. Configuration de Zeek

Créez ou modifiez le fichier de configuration Zeek (`/opt/zeek/share/zeek/site/local.zeek`) :

```zeek
# Activer les logs en temps réel
@load tuning/defaults
@load tuning/json-logs

# Configurer le répertoire des logs
redef Log::default_rotation_interval = 1 day;
redef Log::default_rotation_postprocessor_cmd = "gzip";

# Activer les logs spécifiques
@load protocols/conn
@load protocols/dns
@load protocols/http
@load protocols/ssh
@load protocols/ssl
@load protocols/ftp
@load protocols/smtp
@load protocols/ntp
@load protocols/weird
@load protocols/notice
@load protocols/software
```

## Utilisation

### 1. Conversion des logs Zeek en format NSL-KDD

Le script `zeek_to_nslkdd.py` convertit les logs Zeek en format NSL-KDD pour l'analyse :

```bash
# Mode traitement par lots
python zeek_to_nslkdd.py --logs-dir /opt/zeek/logs --output nslkdd_format.csv

# Mode temps réel
python zeek_to_nslkdd.py --logs-dir /opt/zeek/logs --output nslkdd_format.csv --real-time --interval 60
```

Options disponibles :
- `--logs-dir` : Répertoire contenant les logs Zeek (défaut: /opt/zeek/logs)
- `--output` : Fichier de sortie au format NSL-KDD (défaut: nslkdd_format.csv)
- `--real-time` : Activer la surveillance en temps réel
- `--interval` : Intervalle de surveillance en secondes (défaut: 60)
- `--elasticsearch` : Activer l'intégration avec ElasticSearch

### 2. Détection en temps réel

Le script `realtime_predictor.py` effectue la détection d'intrusions en temps réel :

```bash
python realtime_predictor.py --input nslkdd_format.csv --model xgboost_full_pipeline.pkl
```

Options disponibles :
- `--input` : Fichier d'entrée au format NSL-KDD
- `--model` : Chemin vers le modèle entraîné
- `--threshold` : Seuil de détection (défaut: 0.5)

### 3. Interface Web

L'interface web permet de visualiser les alertes en temps réel :

```bash
streamlit run realtime_predictor_web.py
```

## Configuration

### Configuration ElasticSearch (optionnelle)

Si vous souhaitez utiliser ElasticSearch, configurez les paramètres dans `zeek_to_nslkdd.py` :

```python
self.es_config = {
    "url": "https://elasticsearch.service:9200",
    "api_key": "votre_api_key",
    "index": "zeek-ids-analytics",
    "batch_size": 1000
}
```

### Configuration des modèles

Le modèle XGBoost pré-entraîné est fourni dans le fichier `xgboost_full_pipeline.pkl`. Pour entraîner un nouveau modèle :

1. Préparer les données au format NSL-KDD
2. Utiliser le script d'entraînement (à implémenter)
3. Sauvegarder le modèle entraîné

## Structure du Projet

```
IDS-Intelligent/
├── zeek_to_nslkdd.py          # Conversion des logs Zeek
├── realtime_predictor.py      # Détection en temps réel
├── realtime_predictor_web.py  # Interface web
├── xgboost_full_pipeline.pkl  # Modèle pré-entraîné
└── requirements.txt           # Dépendances Python
```

## Dépendances Python

- numpy>=1.19.2
- pandas>=1.2.0
- xgboost>=1.5.0
- scikit-learn>=0.24.0
- streamlit>=1.22.0
- plotly>=5.13.0

## Dépannage

### Problèmes courants

1. **Zeek ne démarre pas**
   ```bash
   # Vérifier le statut de Zeek
   sudo systemctl status zeek
   
   # Vérifier les logs
   sudo journalctl -u zeek
   ```

2. **Erreurs de permission**
   ```bash
   # Donner les permissions nécessaires
   sudo chown -R zeek:zeek /opt/zeek/logs
   sudo chmod -R 755 /opt/zeek/logs
   ```

3. **Problèmes de mémoire**
   - Augmenter la mémoire virtuelle
   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```

### Logs et débogage

- Logs Zeek : `/opt/zeek/logs/`
- Logs de conversion : Vérifier les messages dans la console
- Logs de détection : Vérifier les messages dans la console et l'interface web

## Contribution

### Développement

1. Fork le projet
2. Créer une branche pour votre fonctionnalité
   ```bash
   git checkout -b feature/nouvelle-fonctionnalite
   ```
3. Commiter vos changements
   ```bash
   git commit -m 'Ajout d'une nouvelle fonctionnalité'
   ```
4. Pousser vers la branche
   ```bash
   git push origin feature/nouvelle-fonctionnalite
   ```
5. Créer une Pull Request

### Tests

Pour exécuter les tests (à implémenter) :
```bash
python -m pytest tests/
```

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Auteurs

- Omar El Kadiri - Développeur principal

## Remerciements

- Zeek Project pour l'outil d'analyse de trafic réseau
- NSL-KDD pour le format de données
- XGBoost pour le framework d'apprentissage automatique

## Support

Pour toute question ou problème :
1. Vérifier la section Dépannage
2. Ouvrir une issue sur GitHub
3. Contacter l'auteur

## Mises à jour futures

- [ ] Support pour d'autres formats de logs
- [ ] Interface web améliorée
- [ ] Plus de modèles d'apprentissage automatique
- [ ] Documentation API
- [ ] Tests automatisés 