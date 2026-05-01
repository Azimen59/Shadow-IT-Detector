# 🏭 Shadow IT Detector V5.2

**Moteur d'audit OAuth Enterprise · Scoring Tiered · Détection de Drift · Remédiation Automatique**

[![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-blue.svg)](https://aka.ms/powershell)
[![Azure](https://img.shields.io/badge/Azure%20Automation-Compatible-green.svg)](https://learn.microsoft.com/azure/automation/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

---

## 📖 Table des matières

- [🎯 Qu'est-ce que le Shadow IT Detector ?](#-quest-ce-que-le-shadow-it-detector-)
- [🆕 Nouveautés de la V5.2](#-nouveautés-de-la-v52)
- [📋 Prérequis](#-prérequis)
- [🚀 Guide d'utilisation rapide](#-guide-dutilisation-rapide)
- [⚙️ Utilisation avancée](#-utilisation-avancée)
- [📁 Fichiers de configuration](#-fichiers-de-configuration)
- [🔄 Migration depuis la V5.1](#-migration-depuis-la-v51)
- [🏗️ Architecture du code](#-architecture-du-code)
- [📊 Dashboard HTML](#-dashboard-html)
- [🔒 Sécurité](#-sécurité)
- [⚠️ Limitations connues](#-limitations-connues)
- [📝 Licence](#-licence)

---

## 🎯 Qu'est-ce que le Shadow IT Detector ?

Dans les environnements Microsoft 365 / Entra ID, les applications tierces s'accumulent au fil du temps. Certaines sont oubliées, leurs secrets expirent, ou elles conservent des permissions critiques sans être utilisées. **C'est le Shadow IT.**

Le **Shadow IT Detector V5.2** est un moteur d'audit PowerShell 7 qui :

- 🔍 **Scanne massivement** tous les Service Principals d'un tenant (100 000+ applications supportées)
- 📊 **Évalue le risque** via un scoring Tiered (Tier 1 = Directory.ReadWrite, RoleManagement… / Tier 2 = Mail, Files, Sites…)
- 🚨 **Détecte les dérives** : escalade de permissions, changement de propriétaire, réactivation suspecte
- ⚡ **Remédie automatiquement** : quarantaine (48h) puis désactivation des apps critiques
- 📈 **Génère un dashboard HTML interactif** pour les équipes SOC
- 🔔 **Envoie des alertes Microsoft Teams** (Adaptive Cards)

---

## 🆕 Nouveautés de la V5.2

### 🔧 Correctifs critiques

| Correctif | Description |
|-----------|-------------|
| **RBAC M2M** | Le Gate 1 vérifie désormais l'appartenance réelle de l'identité managée au groupe SOC Admin via `checkMemberGroups` |
| **Flush Interlocked** | Correction du compteur partagé — les variables locales sont extraites avant `[ref]` |
| **Index OAuth2** | L'index secondaire par AppId est correctement construit via cross-référence `$SPById` |
| **Retry Graph** | Détection de toutes les erreurs transitoires (429, 5xx, timeout) — plus de retry sur les erreurs permanentes (400-404) |
| **WaitOne** | Le retour de `WaitOne()` est capturé pour éviter `ReleaseMutex` sans ownership |
| **Scoring Secret** | Distinction entre "secret expirant" et "secret expiré" — deux flags séparés |
| **SIEM Breaking Change** | `has_expiring_secret`, `has_expired_secret`, `secret_penalty_suppressed` au lieu d'un seul champ |

### ✨ Nouvelles fonctionnalités

- 🕐 **Soft-exit timeout** : paramètre `-MaxExecutionMinutes 150` pour Azure Automation (sandbox 180 min)
- 🧹 **Nettoyage FlushTemp** : suppression automatique des fichiers temporaires orphelins
- 🏷️ **Déduplication** : élimination des doublons dans le rapport final (`Group-Object AppId`)
- ⚡ **HTML StringBuilder** : génération du dashboard 10× plus rapide sur les grands tenants
- 🔍 **Debounce search** : recherche JavaScript avec debounce 300ms pour la fluidité

---

## 📋 Prérequis

### Logiciels

| Composant | Version minimale | Installation |
|-----------|------------------|--------------|
| **PowerShell** | 7.2+ | `winget install Microsoft.PowerShell` |
| **Microsoft.Graph.Authentication** | 2.0+ | `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` |
| **Microsoft.Graph.Applications** | 2.0+ | `Install-Module Microsoft.Graph.Applications -Scope CurrentUser` |
| **Microsoft.Graph.Reports** | 2.0+ | `Install-Module Microsoft.Graph.Reports -Scope CurrentUser` |
| **Microsoft.Graph.Users** | 2.0+ | `Install-Module Microsoft.Graph.Users -Scope CurrentUser` |

### Permissions Entra ID

| Scope | Type | Requis pour |
|-------|------|-------------|
| `Application.Read.All` | Application | Lecture des Service Principals |
| `Directory.Read.All` | Application | Résolution des groupes (RBAC Gate) |
| `AuditLog.Read.All` | Application | Cache Sign-Ins ⚠️ **Requiert licence Entra ID P1/P2** |
| `Application.ReadWrite.All` | Application | Remédiation (quarantaine/désactivation) |
| `User.Read` | Delegated | Mode interactif (fallback) |
| `GroupMember.Read.All` | Application | Vérification appartenance groupe SOC |

### Fichiers de configuration

| Fichier | Format | Description |
|---------|--------|-------------|
| `whitelist.csv` | CSV (colonne `AppId`) | Applications exclues du scoring |
| `ExpectedDrift.csv` | CSV (colonne `AppId`) | Applications dont la rotation d'owner/secret est attendue |

> 💡 Des fichiers d'exemple sont disponibles dans le dossier [`samples/`](samples/).

### Variables d'environnement

| Variable | Requise | Description |
|----------|---------|-------------|
| `TEAMS_WEBHOOK_URL` | Non | URL du webhook Teams pour les alertes drift |
| `SOC_ADMIN_GROUP_ID` | Oui (remédiation) | GUID du groupe Entra ID autorisé à lancer la remédiation |
| `SOC_REMEDIATION_CONFIRMED` | Oui (remédiation M2M) | `true` pour confirmer la remédiation en mode non-interactif |
| `GRAPH_CLIENT_ID` | Non | ClientId pour l'auth par certificat |
| `GRAPH_TENANT_ID` | Non | TenantId pour l'auth par certificat |
| `GRAPH_CERT_THUMBPRINT` | Non | Thumbprint du certificat pour l'auth par certificat |

---

## 🚀 Guide d'utilisation rapide

### 1. Premier lancement — Audit simple

```powershell
.\ShadowIT-Detector-V5.2.ps1
```

✅ Scanne le tenant, génère le rapport HTML, **aucune modification**.

---

### 2. Simulation de remédiation (WhatIf)

```powershell
.\ShadowIT-Detector-V5.2.ps1 -RemediateHighRisk -WhatIf
```

🔮 Affiche ce qui **serait** fait, sans rien modifier.

---

### 3. Remédiation interactive

```powershell
.\ShadowIT-Detector-V5.2.ps1 -RemediateHighRisk
```

🛡️ Demande une confirmation manuelle (`CONFIRMER`) après vérification RBAC.

---

### 4. Pipeline CI/CD (Azure Automation)

```powershell
.\ShadowIT-Detector-V5.2.ps1 `
    -ManagedIdentity `
    -RemediateHighRisk `
    -RemediationScoreThreshold 80 `
    -Force `
    -MaxExecutionMinutes 150
```

🤖 Entièrement automatisé — nécessite les variables d'environnement `SOC_ADMIN_GROUP_ID` et `SOC_REMEDIATION_CONFIRMED=true`.

---

### 5. Auth par certificat

```powershell
.\ShadowIT-Detector-V5.2.ps1 `
    -ClientId "12345678-1234-1234-1234-123456789abc" `
    -TenantId "87654321-4321-4321-4321-cba987654321" `
    -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
```

---

## ⚙️ Utilisation avancée

### Paramètres principaux

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-ManagedIdentity` | Switch | `$false` | Utilise l'identité managée Azure |
| `-ClientId` | String | `$env:GRAPH_CLIENT_ID` | ClientId pour auth certificat |
| `-TenantId` | String | `$env:GRAPH_TENANT_ID` | TenantId pour auth certificat |
| `-CertificateThumbprint` | String | `$env:GRAPH_CERT_THUMBPRINT` | Thumbprint du certificat |
| `-RemediateHighRisk` | Switch | `$false` | Active la remédiation automatique |
| `-Force` | Switch | `$false` | Passe le Gate 2 en mode M2M |
| `-WhatIf` | Switch | `$false` | Mode simulation (aucune modification) |

### Seuils de scoring

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-RemediationScoreThreshold` | Int | 70 | Score minimum pour remédiation |
| `-InactivityThresholdDays` | Int | 90 | Jours sans sign-in → flag INACTIF |
| `-SecretExpiryWarningDays` | Int | 30 | Jours avant expiration → flag SECRET EXP. |
| `-TeamsAlertScoreThreshold` | Int | 40 | Score minimum pour alerte Teams |
| `-QuarantineHours` | Int | 48 | Délai avant désactivation définitive |

### Performance

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-ThrottleLimit` | Int | 15 | Nombre de runspaces parallèles |
| `-MaxRetryAttempts` | Int | 3 | Tentatives de retry Graph |
| `-MaxExecutionMinutes` | Int | 150 | Soft-exit timeout (Azure Automation) |

---

## 📁 Fichiers de configuration

### whitelist.csv

```csv
AppId
12345678-1234-1234-1234-123456789abc
87654321-4321-4321-4321-cba987654321
```

Les AppIds listées sont **exclues du scoring** (score = 0, label « RISQUE ACCEPTÉ »).

### ExpectedDrift.csv

```csv
AppId
aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

Les AppIds listées **ne déclenchent pas d'alerte** en cas de :
- Changement de propriétaire
- Secret expirant (pénalité de scoring neutralisée)

---

## 🔄 Migration depuis la V5.1

### ⚠️ Breaking change SIEM

Le champ `has_expiring_secret` est remplacé par **trois champs** :

| Ancien champ (V5.1) | Nouveaux champs (V5.2) |
|----------------------|--------------------------|
| `has_expiring_secret` | `has_expiring_secret` (fait observé brut) |
| — | `has_expired_secret` (secret déjà périmé) |
| — | `secret_penalty_suppressed` (décision de scoring masquée) |

**Actions requises :**
- Mettre à jour les règles KQL dans Azure Sentinel
- Mettre à jour les workbooks analytiques
- Vérifier les alertes configurées sur l'ancien champ

---

## 🏗️ Architecture du code

Le script suit un pipeline de traitement en 13 étapes :

```
┌─────────────────────────────────────────────────────────────┐
│  1. Authentification M2M (Managed Identity / Cert / User)   │
│  2. Double Gate RBAC (SOC Admin + Confirmation)              │
│  3. Chargement fichiers de référence (Whitelist, Drift)      │
│  4. Collecte Graph Bulk (SPs, OAuth2, Sign-Ins)             │
│  5. Analyse Parallèle (15 runspaces)                        │
│     ├─ Early Exit (Microsoft disabled SPs)                  │
│     ├─ Collecte Locale (Permissions, Owners, Secrets)        │
│     ├─ Scoring Tiered (Tier 1 / Tier 2 / Reads)             │
│     ├─ Smart Alerts (Orphaned, Toxic, Dormant, Untrusted)   │
│     ├─ Drift Detection (4 dimensions)                       │
│     ├─ Remédiation (Quarantine / Disable)                   │
│     └─ Flush Mémoire (Double-Checked Locking)               │
│  6. Sauvegarde État Drift                                   │
│  7. Alertes Teams (Adaptive Cards)                          │
│  8. Statistiques                                            │
│  9. Affichage Console                                       │
│ 10. Export CSV                                              │
│ 11. Export SIEM JSON                                        │
│ 12. Dashboard HTML interactif                               │
│ 13. Déconnexion                                             │
└─────────────────────────────────────────────────────────────┘
```

### Modèle de scoring Tiered

```
Tier 1 — Infrastructure & Contrôle (Directory.*, RoleManagement.*, Policy.*, Application.ReadWrite.*)
  └─ +50 pts (1ère permission) / +10 pts (suivantes) / Plafond bucket : 70 pts

Tier 2 — Données Métier (Mail.*, Files.*, Sites.*, Chat.*)
  └─ +30 pts (1ère permission) / +10 pts (suivantes) / Plafond bucket : 45 pts

Read simples (non classées)
  └─ +2 pts par permission / Pas de plafond

Majorations contextuelles
  └─ App tierce : +20 pts
  └─ Inactif > 90j : +15 pts
  └─ Secret expirant : +10 pts

Score global plafonné à 100
```

---

## 📊 Dashboard HTML

Le rapport HTML est **auto-suffisant** (zéro dépendance externe, pas de CDN). Il inclut :

- 🎨 **Dark Mode Enterprise** avec grille d'arrière-plan subtile
- 📊 **Cartes KPI** (Total, Critique, Élevé, Whitelist, Orphaned, Toxic, Quarantaine, Désactivés)
- 🔍 **Barre de recherche** avec debounce 300ms
- 🎛️ **Filtres** par niveau de risque (Tous, Critique, Élevé, Accepté)
- ↕️ **Tri dynamique** des colonnes (ascendant/descendant)
- 🏷️ **Badges colorés** pour les flags de sécurité
- 📱 **Design responsive** (grilles CSS Grid adaptatives)

---

## 🔒 Sécurité

- 🛡️ **Double Gate** : RBAC (groupe SOC Admin) + confirmation manuelle/env var
- 🔐 **Pas de secrets hardcodés** : toutes les credentials passent par `$env:`
- 🔍 **WhatIf** : mode simulation activable pour auditer avant de modifier
- 🧵 **Thread-safe** : Mutex nommés, Interlocked, ConcurrentBag
- 🧹 **Nettoyage** : trap global pour nettoyer les fichiers temporaires en cas d'erreur fatale
- ⚠️ **Mutex locaux** : les mutex protègent la concurrence **locale** (15 threads). Pour une exécution CI/CD multi-agents, sérialisez le pipeline via l'orchestrateur (ex: Concurrency GitHub Actions)

---

## ⚠️ Limitations connues

- **Licence Entra ID** : Le cache des Sign-Ins (`AuditLog.Read.All`) nécessite une licence **Entra ID P1/P2**. Sur un tenant gratuit, le script poursuit sans ce cache — les flags INACTIF sont alors basés sur la date de création du SP.
- **Permissions applicatives** : L'octroi des App permissions (`Application.Read.All`, etc.) peut nécessiter un abonnement selon le type de tenant. Les permissions Déléguées fonctionnent sur tous les tenants.
- **Mutex inter-machines** : Les mutex nommés (`Global\ShadowIT_*`) ne protègent que les threads d'une même machine. En CI/CD multi-agents, utilisez la sérialisation de pipeline.
- **Timeout Azure Automation** : Le paramètre `-MaxExecutionMinutes 150` permet un soft-exit avant les 180 minutes du sandbox. Un kill par l'infrastructure reste possible et le trap global ne s'exécutera pas.
- **Volumétrie** : Testé jusqu'à 100 000 Service Principals. Au-delà, la consommation mémoire de `$AllSPs` peut saturer la RAM du runner — envisager un pattern streaming en deux passes pour V6.
- **Token expiry** : Sur des exécutions > 1 heure, le token Graph peut expirer. Le SDK tente un refresh automatique mais en cas d'échec, les SPs analysés après l'expiration généreront des erreurs 401 traitées comme permanentes.

---

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

**🏭 Construit avec ❤️ par Aimen Boudalia - 05/2026**
