#!/bin/bash
# Script de démarrage pour le système IDS intelligent

# Définir les chemins
SCRIPT_DIR="/home/admin_web/Documents/IDS-Intelligent"
CSV_FILE="$SCRIPT_DIR/resultats.csv"
ZEEK_SCRIPT="$SCRIPT_DIR/zeek_to_nslkdd_v2.py"
STREAMLIT_APP="$SCRIPT_DIR/app.py"
LOG_FILE="$SCRIPT_DIR/ids_log.txt"
VENV_PATH="$SCRIPT_DIR/venv"

# Créer le fichier CSV s'il n'existe pas
touch "$CSV_FILE"

# Vérifier que tous les fichiers nécessaires existent
if [ ! -f "$ZEEK_SCRIPT" ]; then
    echo "ERREUR: Le script $ZEEK_SCRIPT n'existe pas."
    exit 1
fi

if [ ! -f "$STREAMLIT_APP" ]; then
    echo "ERREUR: L'application $STREAMLIT_APP n'existe pas."
    exit 1
fi

# Vérifier si l'environnement virtuel existe
if [ ! -d "$VENV_PATH" ]; then
    echo "ATTENTION: L'environnement virtuel n'a pas été trouvé dans $VENV_PATH."
    echo "Voulez-vous créer un nouvel environnement virtuel ? (o/n)"
    read create_venv

    if [[ "$create_venv" == "o" || "$create_venv" == "O" ]]; then
        echo "Création d'un nouvel environnement virtuel..."
        python3 -m venv "$VENV_PATH"
        source "$VENV_PATH/bin/activate"
        pip install pandas streamlit
    else
        echo "Exécution sans environnement virtuel. Cela pourrait échouer si streamlit n'est pas installé globalement."
    fi
else
    echo "Environnement virtuel trouvé: $VENV_PATH"
fi

# Fonction pour activer l'environnement virtuel
activate_venv() {
    if [ -d "$VENV_PATH" ]; then
        source "$VENV_PATH/bin/activate"
        echo "Environnement virtuel activé."
    fi
}

# Fonction pour arrêter proprement les processus
cleanup() {
    echo "Arrêt des processus..."
    # Récupérer et arrêter les processus par PID
    if [ -f "$SCRIPT_DIR/zeek_pid.txt" ]; then
        kill $(cat "$SCRIPT_DIR/zeek_pid.txt") 2>/dev/null
        rm "$SCRIPT_DIR/zeek_pid.txt"
    fi
    
    if [ -f "$SCRIPT_DIR/streamlit_pid.txt" ]; then
        kill $(cat "$SCRIPT_DIR/streamlit_pid.txt") 2>/dev/null
        rm "$SCRIPT_DIR/streamlit_pid.txt"
    fi
    
    echo "Système IDS arrêté."
    exit 0
}

# Capturer les signaux pour un arrêt propre
trap cleanup SIGINT SIGTERM

# Afficher le menu
echo "=== Système de détection d'intrusion intelligent ==="
echo "1. Démarrer le système complet (convertisseur + interface web)"
echo "2. Démarrer uniquement le convertisseur Zeek"
echo "3. Démarrer uniquement l'interface web Streamlit"
echo "4. Quitter"

read -p "Choisir une option (1-4): " choice

# Traiter le choix de l'utilisateur
case $choice in
    1)
        echo "Démarrage du système complet..."
        
        # Démarrer le convertisseur Zeek en arrière-plan
        echo "Démarrage du convertisseur Zeek..."
        # Activer l'environnement virtuel
        activate_venv
        python3 "$ZEEK_SCRIPT" --real-time --interval 30 --output "$CSV_FILE" > "$LOG_FILE" 2>&1 &
        echo $! > "$SCRIPT_DIR/zeek_pid.txt"
        
        # Attendre que le convertisseur démarre
        sleep 2
        
        # Démarrer l'application Streamlit en arrière-plan
        echo "Démarrage de l'interface web Streamlit..."
        # Détecter l'adresse IP pour l'affichage
        IP_ADDRESS=$(hostname -I | awk '{print $1}')
        streamlit run "$STREAMLIT_APP" --server.address 0.0.0.0 --server.port 8501 >> "$LOG_FILE" 2>&1 &
        echo $! > "$SCRIPT_DIR/streamlit_pid.txt"
        
        echo "Système IDS démarré !"
        echo "Interface web disponible à l'adresse: http://$IP_ADDRESS:8501"
        echo "Les logs sont disponibles dans $LOG_FILE"
        echo "Appuyez sur Ctrl+C pour arrêter le système."
        
        # Attendre indéfiniment (jusqu'à Ctrl+C)
        while true; do sleep 1; done
        ;;
        
    2)
        echo "Démarrage du convertisseur Zeek uniquement..."
        # Activer l'environnement virtuel
        activate_venv
        python3 "$ZEEK_SCRIPT" --real-time --interval 30 --output "$CSV_FILE" > "$LOG_FILE" 2>&1 &
        echo $! > "$SCRIPT_DIR/zeek_pid.txt"
        
        echo "Convertisseur Zeek démarré !"
        echo "Les logs sont disponibles dans $LOG_FILE"
        echo "Appuyez sur Ctrl+C pour arrêter."
        
        # Attendre indéfiniment (jusqu'à Ctrl+C)
        while true; do sleep 1; done
        ;;
        
    3)
        echo "Démarrage de l'interface web Streamlit uniquement..."
        # Activer l'environnement virtuel
        activate_venv
        # Détecter l'adresse IP pour l'affichage
        IP_ADDRESS=$(hostname -I | awk '{print $1}')
        streamlit run "$STREAMLIT_APP" --server.address 0.0.0.0 --server.port 8501 >> "$LOG_FILE" 2>&1 &
        echo $! > "$SCRIPT_DIR/streamlit_pid.txt"
        
        echo "Interface web Streamlit démarrée !"
        echo "Interface web disponible à l'adresse: http://$IP_ADDRESS:8501"
        echo "Les logs sont disponibles dans $LOG_FILE"
        echo "Appuyez sur Ctrl+C pour arrêter."
        
        # Attendre indéfiniment (jusqu'à Ctrl+C)
        while true; do sleep 1; done
        ;;
        
    4)
        echo "Au revoir !"
        exit 0
        ;;
        
    *)
        echo "Option invalide. Veuillez redémarrer le script."
        exit 1
        ;;
esac 
