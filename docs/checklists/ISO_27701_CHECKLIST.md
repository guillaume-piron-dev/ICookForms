# ✅ CHECKLIST DE CONFORMITÉ ISO 27701:2019
## ICookForms - Privacy Information Management System

**Version:** 1.0.0  
**Date:** 1er Novembre 2025  
**Norme:** ISO/IEC 27701:2019  
**Extension de:** ISO/IEC 27001:2022  
**Périmètre:** Système Complet ICookForms

---

## INSTRUCTIONS D'UTILISATION

Cette checklist couvre ISO 27701:2019 - Privacy Information Management System (PIMS):
- **Clauses 5: ** Exigences additionnelles au SMSI
- **Clauses 6:** Guidance additionnelle
- **Annex A:** Contrôles PII Controller (Responsable de traitement)
- **Annex B:** Contrôles PII Processor (Sous-traitant)

**Prérequis:** ISO 27001:2022 doit être conforme en premier

**Statuts possibles:**
- ✅ **Conforme:** Contrôle entièrement implémenté
- 🔄 **Partiel:** Contrôle partiellement implémenté
- ❌ **Non-Conforme:** Contrôle non implémenté
- ⚪ **N/A:** Non applicable

---

## RÔLE D'ICOOKFORMS

**Note importante:** ICookForms agit principalement comme **PII Processor** (sous-traitant) lorsqu'il analyse des cookies pour le compte de ses clients, mais peut aussi agir comme **PII Controller** (responsable de traitement) pour les données de ses propres utilisateurs.

**En tant que PII Processor (principal):**
- Traite les données de cookies pour le compte des clients
- Suit les instructions des clients
- Contrôles Annex B applicables

**En tant que PII Controller (secondaire):**
- Gère les comptes utilisateurs
- Gère les résultats d'analyse
- Contrôles Annex A applicables

---

## PARTIE 1: CLAUSES 5 - EXIGENCES PIMS

### 5.2 Politique du PIMS

#### 5.2.1 Politique de Protection de la Vie Privée

- [ ] Politique de protection de la vie privée établie
- [ ] Politique alignée avec la politique de sécurité (ISO 27001)
- [ ] Politique couvre le traitement des PII
- [ ] Politique approuvée par la direction
- [ ] Politique communiquée aux parties concernées
- [ ] Politique revue périodiquement

**Éléments de la politique:**
- [ ] Engagement envers la protection de la vie privée
- [ ] Principes de protection des données
- [ ] Conformité aux régulations (GDPR, CCPA, etc.)
- [ ] Droits des personnes concernées
- [ ] Rôles et responsabilités privacy
- [ ] Traitement des incidents privacy

**Document de politique:**
- Version actuelle: ________
- Date d'approbation: ________
- Approuvé par: ________
- Prochaine revue: ________

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 5.2.2 Communication de la Politique

- [ ] Politique communiquée en interne
- [ ] Politique communiquée aux parties intéressées
- [ ] Politique accessible aux personnes concernées (privacy notice)

**Preuves:** ________________________________

---

### 5.3 Rôles et Responsabilités Privacy

#### 5.3.1 Responsabilités Privacy

- [ ] Rôles et responsabilités privacy définis
- [ ] Responsabilités assignées
- [ ] Responsabilités communiquées

**Rôles clés ICookForms:**
- [ ] Data Protection Officer (DPO): ________
- [ ] Privacy Officer: ________
- [ ] Responsable PIMS: ________
- [ ] Contact privacy pour les personnes concernées: ________

**Preuves:** ________________________________

#### 5.3.2 DPO (Data Protection Officer)

- [ ] DPO désigné (si requis par GDPR Article 37)
- [ ] DPO possède expertise appropriée
- [ ] DPO indépendant (pas de conflit d'intérêt)
- [ ] DPO rapporte directement à la direction
- [ ] Coordonnées du DPO publiées
- [ ] DPO notifié à l'autorité de contrôle

**Cas où DPO obligatoire:**
- [ ] Autorité publique (non applicable pour ICookForms)
- [ ] Suivi régulier et systématique à grande échelle
- [ ] Traitement à grande échelle de données sensibles

**Si DPO non obligatoire:**
- [ ] Justification documentée
- [ ] Rôle Privacy Officer désigné en alternative

**Preuves:** ________________________________  
**Commentaires:** ________________________________

---

### 5.4 Approche Basée sur les Risques Privacy

#### 5.4.1 Évaluation des Risques Privacy

- [ ] Risques pour les personnes concernées identifiés
- [ ] Privacy Impact Assessment (PIA) réalisée
- [ ] Data Protection Impact Assessment (DPIA) réalisée si requis

**Quand réaliser une DPIA (GDPR Article 35):**
- [ ] Évaluation systématique et approfondie
- [ ] Prise de décision automatisée avec effets juridiques
- [ ] Traitement à grande échelle de données sensibles
- [ ] Surveillance systématique à grande échelle
- [ ] Nouvelles technologies

**DPIAs réalisées pour ICookForms:**
- [ ] DPIA pour le scanner de cookies: ________
- [ ] DPIA pour l'analyzer: ________
- [ ] DPIA pour le stockage des résultats: ________

**Preuves:** ________________________________  
**Commentaires:** ________________________________

---

### 5.5 PII Controllers et PII Processors

#### 5.5.1 Identification des Rôles

- [ ] Rôles clairement identifiés (Controller vs Processor)
- [ ] Documentation des relations contractuelles
- [ ] DPA (Data Processing Agreement) en place si processor

**Pour ICookForms:**
- [ ] En tant que Controller: Données des utilisateurs ICookForms
- [ ] En tant que Processor: Analyse de cookies pour les clients

**Preuves:** ________________________________

#### 5.5.2 Data Processing Agreement (DPA)

- [ ] DPA conclu avec les controllers (si processor)
- [ ] DPA conforme GDPR Article 28
- [ ] Obligations du processor documentées

**Éléments du DPA:**
- [ ] Objet et durée du traitement
- [ ] Nature et finalité du traitement
- [ ] Type de données personnelles
- [ ] Catégories de personnes concernées
- [ ] Obligations et droits du controller
- [ ] Instructions du controller documentées
- [ ] Confidentialité du personnel
- [ ] Mesures de sécurité
- [ ] Sous-traitance ultérieure
- [ ] Assistance au controller
- [ ] Notification des violations
- [ ] Suppression/retour des données
- [ ] Audits et inspections

**Preuves:** ________________________________

---

### 5.6 Transferts Transfrontaliers de PII

#### 5.6.1 Base Légale pour Transferts

- [ ] Transferts vers pays tiers identifiés
- [ ] Base légale pour chaque transfert établie
- [ ] Garanties appropriées en place

**Mécanismes GDPR (Chapitre V):**
- [ ] Décision d'adéquation (Article 45)
- [ ] Standard Contractual Clauses - SCC (Article 46)
- [ ] Binding Corporate Rules - BCR (Article 46)
- [ ] Dérogations (Article 49 - consentement explicite, etc.)

**Pour ICookForms:**
- [ ] Data residency: ________ (EU/US/autre)
- [ ] Transferts vers: ________
- [ ] Mécanisme utilisé: ________

**Preuves:** ________________________________  
**Commentaires:** ________________________________

---

## PARTIE 2: ANNEX A - CONTRÔLES PII CONTROLLER

**Note:** Ces contrôles s'appliquent quand ICookForms agit comme responsable de traitement (ex: gestion des comptes utilisateurs).

### A.6.2 Conditions pour la Collecte et le Traitement

#### A.6.2.1 Identification du Consentement et Autres Bases Légales

- [ ] Base légale identifiée pour chaque traitement
- [ ] Base légale documentée
- [ ] Base légale revue régulièrement

**Bases légales GDPR (Article 6):**
- [ ] a) Consentement de la personne
- [ ] b) Exécution d'un contrat
- [ ] c) Obligation légale
- [ ] d) Sauvegarde des intérêts vitaux
- [ ] e) Mission d'intérêt public
- [ ] f) Intérêt légitime

**Pour ICookForms (exemples):**
- Comptes utilisateurs: Exécution du contrat
- Analytics interne: Intérêt légitime
- Marketing: Consentement

**Preuves:** ________________________________

#### A.6.2.2 Finalités Licites et Spécifiées

- [ ] Finalités du traitement déterminées
- [ ] Finalités explicites
- [ ] Finalités légitimes
- [ ] Finalités communiquées aux personnes concernées

**Finalités ICookForms:**
- [ ] Fourniture du service d'analyse de cookies
- [ ] Support client
- [ ] Amélioration du produit
- [ ] Facturation
- [ ] Conformité légale

**Preuves:** ________________________________

#### A.6.2.3 Consentement

- [ ] Mécanisme de consentement conforme
- [ ] Consentement libre
- [ ] Consentement spécifique
- [ ] Consentement éclairé
- [ ] Consentement univoque (acte positif)
- [ ] Consentement facilement révocable

**Implémentation du consentement:**
- [ ] Checkbox non pré-cochée
- [ ] Texte clair et compréhensible
- [ ] Séparé des autres termes
- [ ] Preuve du consentement conservée
- [ ] Mécanisme de retrait facile

**Preuves:** ________________________________

#### A.6.2.4 Collection Directe de PII

- [ ] Information fournie au moment de la collecte
- [ ] Privacy notice claire et accessible

**Preuves:** ________________________________

#### A.6.2.5 Collection Indirecte de PII

- [ ] Source des PII documentée
- [ ] Information fournie à la personne concernée
- [ ] Délai: dans un délai raisonnable (1 mois max)

**Si applicable pour ICookForms:** ________________________________

#### A.6.2.6 Limitation de la Collecte

- [ ] PII limitées au strict nécessaire (minimisation)
- [ ] Principe appliqué systématiquement

**Pour ICookForms:**
- Collecter uniquement:
  - [ ] URLs scannées
  - [ ] Résultats d'analyse
  - [ ] Métadonnées minimales
- Ne pas collecter:
  - [ ] Données personnelles des visiteurs du site scanné

**Preuves:** ________________________________

---

### A.6.3 Obligations envers les PII Principals

#### A.6.3.1 Détermination et Communication avec les PII Principals

- [ ] Personnes concernées identifiées
- [ ] Mécanisme de communication établi
- [ ] Contact privacy accessible

**Contact privacy ICookForms:**
- Email: privacy@icookforms.example
- Formulaire web: https://icookforms.example/privacy-contact
- Adresse postale: ________

**Preuves:** ________________________________

#### A.6.3.2 Information aux PII Principals

- [ ] Information complète fournie (GDPR Articles 13-14)
- [ ] Information claire et compréhensible
- [ ] Information facilement accessible

**Informations obligatoires:**
- [ ] Identité du responsable de traitement
- [ ] Coordonnées du DPO
- [ ] Finalités du traitement
- [ ] Base légale
- [ ] Destinataires des données
- [ ] Transferts hors UE (si applicable)
- [ ] Durée de conservation
- [ ] Droits des personnes (accès, rectification, effacement, etc.)
- [ ] Droit de réclamation auprès de l'autorité
- [ ] Existence de décision automatisée

**Privacy Notice ICookForms:**
- [ ] Version actuelle: ________
- [ ] Date de dernière mise à jour: ________
- [ ] URL: ________

**Preuves:** ________________________________

#### A.6.3.3 Droit d'Accès

- [ ] Mécanisme pour exercer le droit d'accès
- [ ] Procédure de traitement des demandes (DSAR)
- [ ] Délai de réponse: 1 mois (GDPR)
- [ ] Format de réponse: structuré, lisible par machine

**Procédure DSAR ICookForms:**
1. Réception de la demande
2. Vérification de l'identité
3. Recherche des données
4. Préparation de la réponse (JSON/PDF)
5. Envoi dans les 30 jours

**Registre des DSAR:**
- [ ] Nombre de demandes cette année: ________
- [ ] Taux de réponse dans les délais: ________%

**Preuves:** ________________________________

#### A.6.3.4 Droit de Rectification et d'Effacement

- [ ] Mécanisme de rectification en place
- [ ] Mécanisme d'effacement en place
- [ ] Délai de réponse: 1 mois
- [ ] Notification aux destinataires si applicable

**Procédure d'effacement ("droit à l'oubli"):**
- [ ] Suppression définitive des données
- [ ] Suppression des sauvegardes
- [ ] Confirmation à la personne concernée

**Preuves:** ________________________________

#### A.6.3.5 Limitation du Traitement

- [ ] Possibilité de limiter le traitement
- [ ] Marquage des données concernées

**Preuves:** ________________________________

#### A.6.3.6 Portabilité des Données

- [ ] Mécanisme de portabilité implémenté
- [ ] Format structuré fourni (JSON, CSV, XML)
- [ ] Transmission directe possible (si techniquement faisable)

**Formats supportés par ICookForms:**
- [ ] JSON (standard)
- [ ] CSV (tableur)
- [ ] XML (interopérabilité)

**Preuves:** ________________________________

#### A.6.3.7 Droit d'Opposition

- [ ] Possibilité de s'opposer au traitement
- [ ] Opposition gratuite
- [ ] Délai de réponse: 1 mois

**Cas d'opposition:**
- [ ] Marketing direct (obligatoire)
- [ ] Intérêt légitime (évaluation au cas par cas)

**Preuves:** ________________________________

#### A.6.3.8 Décisions Automatisées

- [ ] Personnes informées des décisions automatisées
- [ ] Logique expliquée
- [ ] Possibilité d'intervention humaine
- [ ] Possibilité de contester la décision

**Pour ICookForms:**
- [ ] Analyse automatique de cookies (non décisionnelle)
- [ ] Scoring de risque (explicable)
- [ ] Pas de décision avec effets juridiques

**Preuves:** ________________________________

---

### A.6.4 Privacy by Design et Privacy by Default

#### A.6.4.1 Limitation du Traitement

- [ ] Mesures pour limiter le traitement au nécessaire
- [ ] Privacy by design implémenté
- [ ] Privacy by default implémenté

**Principes appliqués dans ICookForms:**
- [ ] Minimisation des données
- [ ] Pseudonymisation par défaut
- [ ] Chiffrement par défaut
- [ ] Accès restreint par défaut
- [ ] Rétention limitée par défaut

**Preuves:** ________________________________

#### A.6.4.2 Transparence

- [ ] Traitement transparent
- [ ] Communication claire avec les personnes
- [ ] Langage simple et accessible

**Preuves:** ________________________________

---

### A.6.5 Partage, Transfert et Divulgation de PII

#### A.6.5.1 Identification de la Base pour le Partage de PII

- [ ] Base légale pour chaque partage identifiée
- [ ] Destinataires informés de leurs obligations

**Destinataires ICookForms:**
- [ ] Hébergeurs cloud (AWS, Azure): DPA signé
- [ ] Processeurs de paiement: DPA signé
- [ ] Support technique: NDA signé

**Preuves:** ________________________________

#### A.6.5.2 Pays et Organisations Internationales Destinataires

- [ ] Transferts transfrontaliers documentés
- [ ] Garanties appropriées en place

**Preuves:** ________________________________

#### A.6.5.3 Enregistrements liés au Partage

- [ ] Registre des destinataires maintenu
- [ ] Finalités du partage documentées

**Preuves:** ________________________________

---

### A.6.6 Obligations liées aux Sous-traitants

#### A.6.6.1 Sélection des Sous-traitants

- [ ] Due diligence réalisée avant sélection
- [ ] Garanties de sécurité vérifiées
- [ ] Conformité GDPR vérifiée

**Processus de sélection:**
1. Évaluation de la sécurité
2. Vérification de conformité (certifications)
3. Revue contractuelle (DPA)
4. Approbation

**Preuves:** ________________________________

#### A.6.6.2 Contrats avec les Sous-traitants

- [ ] DPA conforme GDPR Article 28
- [ ] Obligations contractuelles claires
- [ ] Droit d'audit du controller

**Preuves:** ________________________________

---

### A.6.7 Exactitude et Qualité

#### A.6.7.1 Exactitude et Qualité

- [ ] Mesures pour assurer l'exactitude des PII
- [ ] Procédure de mise à jour
- [ ] Procédure de correction

**Mesures ICookForms:**
- [ ] Validation des données à la saisie
- [ ] Vérification périodique
- [ ] Possibilité de correction par l'utilisateur

**Preuves:** ________________________________

---

### A.6.8 Minimisation et Limitation

#### A.6.8.1 Minimisation

- [ ] Données limitées au strict nécessaire
- [ ] Revue régulière des données collectées

**Preuves:** ________________________________

#### A.6.8.2 Limitation de Conservation

- [ ] Durée de conservation définie
- [ ] Suppression automatique après expiration
- [ ] Anonymisation comme alternative

**Politique de rétention ICookForms:**
- Résultats de scan: 30 jours
- Comptes utilisateurs inactifs: 2 ans
- Logs d'audit: 12 mois
- Données anonymisées: conservation longue durée possible

**Preuves:** ________________________________

---

### A.6.9 Violations de PII

#### A.6.9.1 Notification des Violations

- [ ] Procédure de notification établie
- [ ] Notification à l'autorité: 72 heures (GDPR Article 33)
- [ ] Notification aux personnes concernées si risque élevé (Article 34)

**Processus de gestion des violations:**
1. Détection
2. Containment
3. Évaluation de la sévérité
4. Notification autorité (si requis)
5. Notification personnes concernées (si requis)
6. Documentation
7. Remediation
8. Lessons learned

**Registre des violations:**
- [ ] Nombre de violations cette année: ________
- [ ] Notifications à l'autorité: ________
- [ ] Notifications aux personnes: ________

**Preuves:** ________________________________

---

## PARTIE 3: ANNEX B - CONTRÔLES PII PROCESSOR

**Note:** Ces contrôles s'appliquent quand ICookForms agit comme sous-traitant (ex: analyse de cookies pour le compte d'un client).

### B.7.2 Conditions pour la Collecte et le Traitement

#### B.7.2.1 Traitement selon Instructions

- [ ] Traitement uniquement selon instructions du controller
- [ ] Instructions documentées
- [ ] Pas de traitement en dehors des instructions

**Instructions documentées pour ICookForms:**
- [ ] Scope du scan (URLs à scanner)
- [ ] Régulations à vérifier (GDPR, CCPA, etc.)
- [ ] Format de rapport (JSON, PDF, etc.)
- [ ] Rétention des données
- [ ] Suppression/retour des données

**Preuves:** ________________________________

#### B.7.2.2 Restriction du Traitement

- [ ] Traitement limité aux finalités spécifiées
- [ ] Pas de traitement pour propres finalités du processor

**Preuves:** ________________________________

---

### B.7.3 Obligations envers les PII Principals

#### B.7.3.1 Assistance au Controller

- [ ] Assistance fournie au controller pour répondre aux demandes
- [ ] Procédure d'assistance documentée

**Assistance fournie par ICookForms:**
- [ ] Recherche de données sur demande
- [ ] Export de données
- [ ] Rectification/suppression
- [ ] Délai de réponse: 7 jours ouvrés

**Preuves:** ________________________________

---

### B.7.4 Privacy by Design et Privacy by Default

#### B.7.4.1 Mesures Techniques et Organisationnelles

- [ ] Mesures appropriées pour protéger les PII
- [ ] Privacy by design appliqué
- [ ] Privacy by default appliqué

**Mesures ICookForms:**
- [ ] Chiffrement des données au repos (AES-256)
- [ ] Chiffrement des données en transit (TLS 1.3)
- [ ] Pseudonymisation
- [ ] Contrôle d'accès strict
- [ ] Logging et monitoring
- [ ] Tests de sécurité réguliers

**Preuves:** ________________________________

---

### B.7.5 Partage, Transfert et Divulgation de PII

#### B.7.5.1 Restriction de Divulgation

- [ ] Pas de divulgation sans autorisation du controller
- [ ] Exceptions: obligations légales

**Preuves:** ________________________________

---

### B.7.6 Obligations liées aux Sous-traitants Ultérieurs

#### B.7.6.1 Autorisation des Sous-traitants Ultérieurs

- [ ] Autorisation du controller obtenue
- [ ] Liste des sous-traitants communiquée
- [ ] Notification en cas de changement

**Sous-traitants ultérieurs ICookForms:**
- [ ] Hébergeur cloud: ________ (DPA signé)
- [ ] CDN: ________ (DPA signé)
- [ ] Email service: ________ (DPA signé)

**Preuves:** ________________________________

#### B.7.6.2 Contrats avec Sous-traitants Ultérieurs

- [ ] Même obligations que le processor principal
- [ ] DPA conforme

**Preuves:** ________________________________

---

### B.7.7 Exactitude et Qualité

#### B.7.7.1 Exactitude et Qualité

- [ ] Assistance au controller pour maintenir l'exactitude
- [ ] Signalement des erreurs détectées

**Preuves:** ________________________________

---

### B.7.8 Minimisation et Limitation

#### B.7.8.1 Suppression et Retour

- [ ] Suppression des PII en fin de contrat
- [ ] Ou: retour des PII au controller
- [ ] Choix du controller documenté
- [ ] Certificat de suppression fourni

**Procédure ICookForms:**
1. Notification de fin de contrat (30 jours avant)
2. Export des données (format demandé)
3. Transfert sécurisé
4. Confirmation de réception
5. Suppression sécurisée (7-pass wipe)
6. Certificat de destruction émis
7. Logs conservés (preuve de suppression)

**Preuves:** ________________________________

---

### B.7.9 Violations de PII

#### B.7.9.1 Notification au Controller

- [ ] Notification au controller sans délai indu
- [ ] Information complète sur la violation
- [ ] Assistance pour notification à l'autorité

**Délai de notification ICookForms → Controller:**
- Maximum: 24 heures après détection
- Préférence: immédiat (dès détection)

**Informations fournies:**
- [ ] Nature de la violation
- [ ] Données affectées
- [ ] Nombre de personnes concernées
- [ ] Conséquences potentielles
- [ ] Mesures prises
- [ ] Contact pour plus d'infos

**Preuves:** ________________________________

---

### B.7.10 Audits et Conformité

#### B.7.10.1 Démonstration de Conformité

- [ ] Démonstration de conformité possible
- [ ] Documentation disponible pour audits
- [ ] Coopération avec audits du controller

**Documentation disponible:**
- [ ] Politiques et procédures
- [ ] Certifications (ISO 27001, SOC 2, etc.)
- [ ] Rapports d'audit internes
- [ ] Logs d'accès
- [ ] Preuves de conformité

**Preuves:** ________________________________

#### B.7.10.2 Assistance aux Audits

- [ ] Assistance fournie pour audits et inspections
- [ ] Accès aux informations fourni
- [ ] Coopération avec autorités de contrôle

**Preuves:** ________________________________

---

## PARTIE 4: CLAUSES 6 - GUIDANCE (Informatif uniquement)

### 6.2 - 6.17 Guidance Sections

Les clauses 6.2 à 6.17 fournissent des guidance informatives sur:
- Conditions de collecte et traitement
- Obligations envers personnes concernées
- Privacy by Design/Default
- Partage et transfert de PII
- Sous-traitance
- Exactitude et qualité
- Conservation et suppression
- Violations de PII

**Note:** Ces clauses sont informatives et non normatives. Les exigences se trouvent dans les Annexes A et B.

---

## SCORE DE CONFORMITÉ ISO 27701

### Calcul du Score

**Annex A - PII Controller (applicables):**
- Contrôles applicables: _____ 
- Contrôles conformes: _____
- **Score Controller: _____%**

**Annex B - PII Processor (applicables):**
- Contrôles applicables: _____
- Contrôles conformes: _____
- **Score Processor: _____%**

**SCORE GLOBAL ISO 27701: _____%**

### Interprétation

- **≥95%:** ⭐⭐⭐ Excellent - Certification possible
- **90-94%:** ⭐⭐ Très Bon - Corrections mineures
- **80-89%:** ⭐ Bon - Corrections modérées
- **70-79%:** Acceptable - Améliorations importantes
- **<70%:** Insuffisant - Travail majeur nécessaire

---

## PLAN D'ACTION PRIVACY

### Non-Conformités Identifiées

| ID | Contrôle | Sévérité | Action | Responsable | Date Limite | Status |
|----|----------|----------|--------|-------------|-------------|--------|
| NC-P-001 | | | | | | ⏳ |
| NC-P-002 | | | | | | ⏳ |
| NC-P-003 | | | | | | ⏳ |

### Améliorations Privacy

| ID | Contrôle | Amélioration | Priorité | Responsable | Status |
|----|----------|--------------|----------|-------------|--------|
| IMP-P-001 | | | | | ⏳ |
| IMP-P-002 | | | | | ⏳ |
| IMP-P-003 | | | | | ⏳ |

---

## REGISTRES PRIVACY REQUIS

### Registres à Maintenir

- [ ] **Registre des traitements** (GDPR Article 30)
  - Finalités du traitement
  - Catégories de données
  - Catégories de personnes concernées
  - Destinataires
  - Transferts hors UE
  - Durées de conservation
  - Mesures de sécurité

- [ ] **Registre des violations de données**
  - Date de la violation
  - Nature de la violation
  - Données affectées
  - Personnes affectées
  - Conséquences
  - Mesures prises
  - Notification autorité (oui/non)
  - Notification personnes (oui/non)

- [ ] **Registre des DSAR** (Data Subject Access Requests)
  - Date de la demande
  - Type de demande (accès, rectification, effacement, etc.)
  - Demandeur (anonymisé)
  - Date de réponse
  - Action prise

- [ ] **Registre des DPIAs**
  - Date de la DPIA
  - Traitement évalué
  - Risques identifiés
  - Mesures d'atténuation
  - Conclusion
  - Revue (date)

- [ ] **Registre des sous-traitants**
  - Nom du sous-traitant
  - Service fourni
  - Données traitées
  - Localisation
  - DPA signé (oui/non)
  - Date de revue

**Preuves:** ________________________________

---

## DOCUMENTATION PRIVACY REQUISE

### Documents à Produire

- [ ] **Privacy Notice** (externe - pour personnes concernées)
  - Claire et accessible
  - Toutes informations obligatoires (Articles 13-14)
  - Multi-langues si nécessaire

- [ ] **Privacy Policy** (interne)
  - Principes de protection des données
  - Rôles et responsabilités
  - Procédures de traitement

- [ ] **Data Processing Agreement (DPA)** (avec clients en tant que processor)
  - Conforme GDPR Article 28
  - Obligations et droits

- [ ] **Cookie Policy** (si applicable)
  - Types de cookies utilisés
  - Finalités
  - Durée de conservation
  - Gestion du consentement

- [ ] **Data Retention Policy**
  - Durées de conservation par type de données
  - Procédures de suppression

- [ ] **Data Breach Response Plan**
  - Procédure de gestion des violations
  - Contacts d'urgence
  - Templates de notification

**Preuves:** ________________________________

---

## FORMATION PRIVACY

### Programme de Formation

- [ ] Sensibilisation GDPR pour tous les employés
- [ ] Formation approfondie pour équipe technique
- [ ] Formation DPO/Privacy Officer
- [ ] Mises à jour régulières sur évolutions légales

**Taux de formation:**
- Employés formés: ________%
- Dernière session: ________
- Prochaine session: ________

**Preuves:** ________________________________

---

## VALIDATION

**Complété par (Privacy Officer/DPO):** ________________________________  
**Date:** ________________________________  
**Signature:** ________________________________

**Revu par (Responsable PIMS):** ________________________________  
**Date:** ________________________________  
**Signature:** ________________________________

**Approuvé par (Direction):** ________________________________  
**Date:** ________________________________  
**Signature:** ________________________________

---

## ANNEXE: MAPPING GDPR - ISO 27701

| GDPR Article | ISO 27701 Contrôle | Description |
|--------------|---------------------|-------------|
| Art. 5 | A.6.2.2, A.6.4.1 | Principes du traitement |
| Art. 6 | A.6.2.1 | Bases légales |
| Art. 7 | A.6.2.3 | Consentement |
| Art. 13-14 | A.6.3.2 | Information aux personnes |
| Art. 15 | A.6.3.3 | Droit d'accès |
| Art. 16 | A.6.3.4 | Droit de rectification |
| Art. 17 | A.6.3.4 | Droit à l'effacement |
| Art. 18 | A.6.3.5 | Limitation du traitement |
| Art. 20 | A.6.3.6 | Portabilité |
| Art. 21 | A.6.3.7 | Droit d'opposition |
| Art. 22 | A.6.3.8 | Décisions automatisées |
| Art. 25 | A.6.4.1 | Privacy by Design/Default |
| Art. 28 | A.6.6.2, B.7.2.1 | DPA avec sous-traitants |
| Art. 30 | Clause 5 | Registre des traitements |
| Art. 32 | B.7.4.1 | Mesures de sécurité |
| Art. 33-34 | A.6.9.1, B.7.9.1 | Notification des violations |
| Art. 35 | Clause 5.4 | DPIA |
| Art. 44-50 | A.6.5.2 | Transferts internationaux |

---

**Document créé le:** 1er Novembre 2025  
**Version:** 1.0.0  
**Prochaine revue:** 1er Février 2026  
**Propriétaire:** DPO/Privacy Officer

**© 2025 ICookForms - All Rights Reserved**
