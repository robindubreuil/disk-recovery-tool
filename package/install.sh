#!/bin/bash
# Script d'installation pour Disk Recovery Tool

set -e

if [[ $EUID -ne 0 ]]; then
   echo "Ce script doit être exécuté en root" 
   exit 1
fi

INSTALL_DIR="/opt/disk-recovery"
BINARY_NAME="disk-recovery-tool"

echo "Installation de Disk Recovery Tool..."

# Création du répertoire
mkdir -p "$INSTALL_DIR"

# Copie des fichiers
cp "$BINARY_NAME" "$INSTALL_DIR/"
cp "README.txt" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Service systemd (optionnel)
if [[ -f "disk-recovery.service" ]]; then
    read -p "Installer le service systemd? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Configuration du service systemd..."
        echo "ATTENTION: Modifiez le hash de mot de passe dans le service avant activation!"
        cp "disk-recovery.service" "/etc/systemd/system/"
        systemctl daemon-reload
        echo "Service installé. Pour l'activer:"
        echo "  1. Éditez /etc/systemd/system/disk-recovery.service"
        echo "  2. Remplacez \$HASH_HERE\$ par votre hash de mot de passe"
        echo "  3. systemctl enable disk-recovery"
        echo "  4. systemctl start disk-recovery"
    fi
fi

echo ""
echo "Installation terminée dans $INSTALL_DIR"
echo ""
echo "Pour démarrer manuellement:"
echo "  cd $INSTALL_DIR"
echo "  sudo ./$BINARY_NAME -help"
echo ""
echo "Pour générer un hash de mot de passe:"
echo "  htpasswd -nbB admin votremotdepasse | cut -d: -f2"
echo ""
