Disk Recovery Tool v2.1.0
============================

Installation:
1. Copier le binaire dans /opt/disk-recovery/
2. Rendre exécutable: chmod +x disk-recovery-tool
3. Exécuter en root: sudo ./disk-recovery-tool -help

Exemples:
  # Sans authentification
  sudo ./disk-recovery-tool
  
  # Avec mot de passe
  sudo ./disk-recovery-tool -password "monmotdepasse"
  
  # Avec hash bcrypt
  sudo ./disk-recovery-tool -password-hash '$2y$10$...'

Fonctionnalités:
- Dump de disques avec compression XZ/ZSTD
- Chiffrement AES-256 optionnel
- Restauration via interface web
- Authentification sécurisée
- Interface multilingue (FR/EN)
- Checksum SHA256 automatique

Support: Version 2.1.0 (build: )
