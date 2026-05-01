# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

---

## [V5.2] — BIG FIX 

### Correctifs critiques
- **FIX-001** — Flush Interlocked : `[ref]($using:array)[0]` remplacé par extraction en variable locale — le compteur partagé fonctionne désormais correctement entre les 15 runspaces
- **FIX-002 / FIX-016** — RBAC M2M : le Gate 1 vérifie l'appartenance réelle via `checkMemberGroups` avec résolution AppId → ObjectId (les deux valeurs sont différentes en Managed Identity)
- **FIX-003** — Index OAuth2 : `$grant.AppId` n'existe pas — l'index secondaire est construit via cross-référence `$SPById[$grant.ClientId].AppId`
- **FIX-004** — WaitOne : le retour booléen est capturé — `ReleaseMutex` n'est appelé que si le mutex est possédé
- **FIX-005 / FIX-008** — Scoring secret : distinction entre "expirant" (< 30j) et "expiré" (< 0j) — deux flags et trois champs SIEM séparés
- **FIX-006 / FIX-013 / FIX-017** — Retry Graph : erreurs permanentes (400-404) → throw immédiat, erreurs transitoires (429, 5xx, timeout, TaskCanceledException) → backoff exponentiel
- **FIX-007** — Type coercion : `[string[]]` cast sur les flags après `Select-Object -Unique` pour éviter la corruption PSObject après sérialisation JSON (flush)
- **FIX-009** — Mémoire : `$SPById` allégé (objets Graph → PSCustomObjects minimaux `{Id, AppId, AppRoles}`)
- **FIX-010** — Cleanup : trap global + nettoyage des répertoires FlushTemp orphelins au démarrage
- **FIX-011** — MemoryBarrier : barrière explicite post-WaitOne maintenue comme defensive coding
- **FIX-012** — FreshSP.Tags null : distinction entre null (intervention externe) et tableau vide
- **FIX-015** — Clone no-op : suppression des `.Clone()` inutiles avant `-join`

### Nouvelles fonctionnalités
- **Soft-exit timeout** : paramètre `-MaxExecutionMinutes` avec signal `$ShouldStop` partagé entre runspaces — évite le kill brutal Azure Automation
- **Déduplication** : `Group-Object AppId` sur le rapport final — élimine les doublons créés par un double-flush
- **HTML StringBuilder** : génération du dashboard via `System.Text.StringBuilder` — complexité O(n) au lieu de O(n²)
- **Debounce JS** : recherche HTML avec debounce 300ms — évite le freeze DOM sur les grands rapports
- **Tri colonnes HTML** : fonction `sortTable()` avec toggle asc/desc sur toutes les colonnes

### Architecture
- **Scoring Tiered V5** : Tier 1 (Directory/Role/Policy/App.RW → max 70pts) / Tier 2 (Mail/Files/Sites/Chat → max 45pts) / Read (+2pts)
- **Smart Alerts** : 4 patterns de corrélation (ORPHANED CRITICAL, TOXIC CONSENT, DORMANT PRIVILEGED, UNTRUSTED HIGH PRIVILEGE)
- **Drift Detection V4** : 4 dimensions comparées (permissions, owner, consentement, AccountEnabled)
- **ConcurrentBag** : collections thread-safe pour tous les bags de résultats
- **Double-Checked Locking** : pattern correct avec MemoryBarrier pour le flush mémoire

---

## [V5.1] — Industrialisé

### Ajouts
- Authentification Machine-to-Machine : Managed Identity, Certificat, Interactif
- Boucle `ForEach-Object -Parallel` avec ThrottleLimit 10 → 15
- Collections thread-safe : `ConcurrentBag<PSCustomObject>` pour Report, Drift, Quarantine, Remediation
- Retry backoff exponentiel sur HTTP 429 (2s → 4s → 8s)
- Early exit intelligent : SPs Microsoft désactivés ignorés avant toute collecte locale
- Flush mémoire dynamique avec Double-Checked Locking pour les tenants > 10k SPs
- Variable `$ShouldStop` partagée entre runspaces via `[bool[]]::new(1)`

---

## [V5.0] — Scoring Tiered + Smart Alerts

### Ajouts
- Scoring Tiered V5 : deux buckets distincts avec plafonds (Tier1 max 70, Tier2 max 45)
- 4 Smart Alerts : ORPHANED CRITICAL, TOXIC CONSENT, DORMANT PRIVILEGED APP, UNTRUSTED HIGH PRIVILEGE
- Auth M2M : Managed Identity, Certificat, fallback interactif
- Logging structuré : `Write-LogMain` scope principal + `Write-ParallelLog` thread-safe dans les runspaces
- Export SIEM JSON normalisé Azure Sentinel / Splunk

---

## [V4.0] — Quarantine Workflow + Expected Drift

### Ajouts
- Workflow de quarantaine en deux étapes : tag `SOC_QUARANTINE_YYYYMMDD` → délai 48h → `AccountEnabled = $false`
- Refresh API avant remédiation + détection d'intervention humaine (race condition)
- Double Gate sécurité : Gate 1 RBAC (groupe Entra ID) + Gate 2 Hard Prompt (`CONFIRMER`)
- `SupportsShouldProcess` natif : `-WhatIf` / `-Confirm` / `-Force`
- Expected Drift : suppression des faux positifs pour les rotations légitimes d'owner et de secret
- Logging fichier persistant : `ShadowIT_Execution.log`
- Déduplication des flags via `Select-Object -Unique`
- Export quarantaine JSON + export remédiation JSON

---

## [V3.0] — Parallélisation + Cache Sign-Ins

### Ajouts
- Cache Sign-Ins pré-chargé en RAM via une seule requête bulk : O(n×latence) → O(1) par SP
- `ForEach-Object -Parallel` avec ThrottleLimit 10
- Scoring Diminishing Returns : +30/+15/+5 pts (max 50) pour les permissions critiques
- Drift Detection enrichie V3 : comparaison Owner, ConsentType, AccountEnabled
- Alertes Teams Adaptive Cards pour les drifts avec score ≥ 40
- Variable d'environnement `$env:TEAMS_WEBHOOK_URL` — jamais en paramètre CLI
- `[long[]]::new(1)` pour les compteurs partagés entre runspaces

---

## [V2.0] — Scoring + HTML + SIEM

### Ajouts
- Système de scoring de risque (0-100) avec modèle Diminishing Returns
- 4 niveaux de criticité : CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE
- Permissions déléguées (OAuth2Grant) ET applicatives (AppRole) analysées
- Whitelist CSV : score forcé à 0, niveau "RISQUE ACCEPTÉ"
- Drift Detection V1 : comparaison des permissions avec l'état précédent (JSON)
- Export HTML Dark Mode avec dashboard de stats
- Export CSV
- Export SIEM JSON (Azure Sentinel / Splunk)
- Tags quarantaine SOC sur les Service Principals
- Flags visuels : USER CONSENT, UNVERIFIED PUBLISHER, INACTIF, SECRET EXP.

---

## [V1.0] — Proof of Concept

### Initial
- Connexion Microsoft Graph via `Connect-MgGraph`
- Récupération de tous les Service Principals (`Get-MgServicePrincipal -All`)
- Exclusion des apps Microsoft first-party via `AppOwnerOrganizationId`
- Affichage basique en tableau (`Format-Table`)
- Pas de scoring, pas d'export, pas de remédiation

---

**Auteur : Aimen Boudalia**
