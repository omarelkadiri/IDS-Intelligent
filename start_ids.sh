#!/bin/bash

# Configuration
PROJECT_DIR="/home/lan/IDS-Intelligent"
VENV_DIR="$PROJECT_DIR/venv"
ZEEK_LOGS_DIR="/opt/zeek/logs"
OUTPUT_FILE="$PROJECT_DIR/nslkdd_format.csv"
LOG_DIR="$PROJECT_DIR/logs"
PID_FILE="$PROJECT_DIR/ids.pid"

# Créer le répertoire de logs s'il n'existe pas
mkdir -p "$LOG_DIR"

# Fonction pour logger les messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/startup.log"
}

# Fonction pour vérifier si un processus est en cours d'exécution
check_process() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Fonction pour arrêter proprement le système
stop_ids() {
    log_message "Arrêt du système IDS..."
    
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            kill "$pid"
            rm "$PID_FILE"
        fi
    fi
    
    # Arrêter Zeek si nécessaire
    if systemctl is-active --quiet zeek; then
        sudo systemctl stop zeek
    fi
    
    log_message "Système IDS arrêté"
}

# Gestion du signal d'arrêt
trap stop_ids SIGINT SIGTERM

# Vérifier si le système est déjà en cours d'exécution
if check_process; then
    log_message "Le système IDS est déjà en cours d'exécution"
    exit 1
fi

# Démarrer Zeek s'il n'est pas déjà en cours d'exécution
if ! systemctl is-active --quiet zeek; then
    log_message "Démarrage de Zeek..."
    sudo systemctl start zeek
    sleep 5  # Attendre que Zeek démarre complètement
fi

# Vérifier que Zeek est bien démarré
if ! systemctl is-active --quiet zeek; then
    log_message "ERREUR: Impossible de démarrer Zeek"
    exit 1
fi

# Activer l'environnement virtuel
if [ ! -d "$VENV_DIR" ]; then
    log_message "ERREUR: Environnement virtuel non trouvé"
    exit 1
fi

source "$VENV_DIR/bin/activate"

# Vérifier les permissions des logs Zeek
if [ ! -w "$ZEEK_LOGS_DIR" ]; then
    log_message "Ajustement des permissions des logs Zeek..."
    sudo chown -R zeek:zeek "$ZEEK_LOGS_DIR"
    sudo chmod -R 755 "$ZEEK_LOGS_DIR"
fi

# Démarrer le convertisseur Zeek vers NSL-KDD
log_message "Démarrage du convertisseur Zeek vers NSL-KDD..."
python3 "$PROJECT_DIR/zeek_to_nslkdd.py" \
    --logs-dir "$ZEEK_LOGS_DIR" \
    --output "$OUTPUT_FILE" \
    --real-time \
    --interval 30 \
    > "$LOG_DIR/ids_output.log" \
    2> "$LOG_DIR/ids_error.log" &

# Sauvegarder le PID
echo $! > "$PID_FILE"

# Démarrer l'interface web
log_message "Démarrage de l'interface web..."
streamlit run "$PROJECT_DIR/realtime_predictor_web.py" \
    --server.address 0.0.0.0 \
    --server.port 8501 \
    > "$LOG_DIR/web_output.log" \
    2> "$LOG_DIR/web_error.log" &

# Sauvegarder le PID de l'interface web
echo $! >> "$PID_FILE"

log_message "Système IDS démarré avec succès"
log_message "Interface web accessible sur http://localhost:8501"

# Garder le script en cours d'exécution
while true; do
    sleep 60
    if ! check_process; then
        log_message "ERREUR: Le système IDS s'est arrêté inopinément"
        stop_ids
        exit 1
    fi
done 