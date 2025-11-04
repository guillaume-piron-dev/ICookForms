# ✅ CHECKLIST DE CONFORMITÉ ISO 27001:2022
## ICookForms - Cookie Compliance & Security Scanner

**Version:** 1.0.0  
**Date:** 1er Novembre 2025  
**Norme:** ISO/IEC 27001:2022  
**Périmètre:** Système Complet ICookForms

---

## INSTRUCTIONS D'UTILISATION

Cette checklist couvre l'intégralité de la norme ISO 27001:2022:
- **Clauses 4-10:** Exigences du Système de Management (SMSI)
- **Annex A:** 93 Contrôles de Sécurité (A.5 à A.8)

**Statuts possibles:**
- ✅ **Conforme:** Contrôle entièrement implémenté et efficace
- 🔄 **Partiel:** Contrôle partiellement implémenté, amélioration nécessaire
- ❌ **Non-Conforme:** Contrôle non implémenté ou inefficace
- ⚪ **N/A:** Non applicable au contexte ICookForms

**Comment utiliser:**
1. Cocher les cases au fur et à mesure de l'implémentation
2. Noter les preuves et commentaires
3. Mettre à jour régulièrement (revue trimestrielle)
4. Utiliser pour préparation d'audits

---

## PARTIE 1: CLAUSES 4-10 (Système de Management)

### CLAUSE 4: CONTEXTE DE L'ORGANISATION

#### 4.1 Compréhension de l'Organisation et de son Contexte

- [ ] Enjeux internes et externes identifiés et documentés
- [ ] Analyse SWOT réalisée
- [ ] Impact sur le SMSI évalué
- [ ] Revue périodique programmée (au moins annuelle)

**Preuves:** ________________________________  
**Commentaires:** ________________________________  
**Date dernière revue:** ________________________________

#### 4.2 Compréhension des Besoins et Attentes des Parties Intéressées

- [ ] Parties intéressées pertinentes identifiées
- [ ] Exigences de sécurité de chaque partie documentées
- [ ] Exigences légales et réglementaires identifiées
- [ ] Exigences contractuelles documentées

**Parties intéressées identifiées:**
- [ ] Clients utilisateurs d'ICookForms
- [ ] Employés et développeurs
- [ ] Autorités de protection des données (CNIL, ICO, etc.)
- [ ] Fournisseurs cloud (AWS, Azure, etc.)
- [ ] Organismes de certification

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 4.3 Détermination du Périmètre du SMSI

- [ ] Périmètre du SMSI clairement défini
- [ ] Limites et frontières documentées
- [ ] Justification des exclusions fournie
- [ ] Périmètre cohérent avec les activités de l'organisation
- [ ] Périmètre disponible sous forme d'information documentée

**Périmètre ICookForms:**
- [ ] Application ICookForms (scanner, analyzer, compliance)
- [ ] Infrastructure de déploiement (Docker, CI/CD)
- [ ] Processus de développement
- [ ] Gestion des données personnelles
- [ ] Support client

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 4.4 Système de Management de la Sécurité de l'Information

- [ ] SMSI établi conformément à ISO 27001
- [ ] SMSI mis en œuvre et maintenu
- [ ] Amélioration continue du SMSI
- [ ] Processus SMSI documentés

**Preuves:** ________________________________  
**Commentaires:** ________________________________

---

### CLAUSE 5: LEADERSHIP

#### 5.1 Leadership et Engagement

- [ ] Direction démontre leadership et engagement
- [ ] Politique et objectifs de sécurité établis
- [ ] Ressources nécessaires allouées
- [ ] Importance du SMSI communiquée
- [ ] SMSI atteint les résultats escomptés
- [ ] Personnel dirigé et soutenu pour contribuer
- [ ] Amélioration continue promue
- [ ] Autres rôles de management supportent le SMSI

**Preuves de l'engagement de la direction:**
- [ ] Participation aux revues de direction
- [ ] Allocation de budget pour la sécurité
- [ ] Approbation de la politique de sécurité
- [ ] Communications sur l'importance de la sécurité

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 5.2 Politique de Sécurité de l'Information

- [ ] Politique de sécurité établie
- [ ] Politique appropriée à l'objectif de l'organisation
- [ ] Politique inclut les objectifs de sécurité
- [ ] Politique inclut l'engagement d'amélioration continue
- [ ] Politique communiquée dans l'organisation
- [ ] Politique disponible aux parties intéressées
- [ ] Politique revue périodiquement (au moins annuelle)

**Document de politique:**
- [ ] Version actuelle: ________
- [ ] Date d'approbation: ________
- [ ] Approuvé par: ________
- [ ] Prochaine revue: ________

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 5.3 Rôles, Responsabilités et Autorités Organisationnelles

- [ ] Responsabilités de sécurité assignées et communiquées
- [ ] Responsable SMSI désigné et ses responsabilités définies
- [ ] Autorités clairement définies
- [ ] Rôles documentés (organigramme, fiches de poste)

**Rôles clés ICookForms:**
- [ ] Responsable SMSI: ________
- [ ] Responsable Sécurité Technique: ________
- [ ] DPO (si applicable): ________
- [ ] Lead Developer: ________
- [ ] DevOps Lead: ________

**Preuves:** ________________________________  
**Commentaires:** ________________________________

---

### CLAUSE 6: PLANIFICATION

#### 6.1 Actions à Mettre en Œuvre Face aux Risques et Opportunités

##### 6.1.1 Généralités

- [ ] Processus d'appréciation des risques établi
- [ ] Critères d'acceptation des risques définis
- [ ] Appréciations répétées produisent des résultats cohérents

**Preuves:** ________________________________

##### 6.1.2 Appréciation des Risques de Sécurité de l'Information

- [ ] Méthodologie d'appréciation établie et maintenue
- [ ] Critères de risque établis
- [ ] Identification des risques (perte de CIA)
- [ ] Propriétaires des risques identifiés
- [ ] Analyse des risques (conséquences + probabilité)
- [ ] Évaluation des risques (comparaison aux critères)
- [ ] Résultats de l'appréciation conservés

**Risques identifiés pour ICookForms:**
- [ ] Vulnérabilités logicielles non découvertes
- [ ] Violation de données personnelles
- [ ] Indisponibilité du service
- [ ] Perte d'intégrité des résultats d'analyse
- [ ] Compromission des secrets/clés API
- [ ] Attaque DDoS
- [ ] Supply chain attack (dépendances compromises)

**Preuves:** ________________________________  
**Commentaires:** ________________________________

##### 6.1.3 Traitement des Risques de Sécurité de l'Information

- [ ] Plan de traitement des risques défini
- [ ] Options de traitement sélectionnées (accepter, éviter, transférer, réduire)
- [ ] Contrôles Annex A nécessaires sélectionnés
- [ ] Justification des inclusions/exclusions (SoA)
- [ ] Approbation du plan par les propriétaires
- [ ] Risques résiduels acceptés par les propriétaires
- [ ] Résultats du traitement conservés

**Statement of Applicability (SoA):**
- [ ] Contrôles applicables sélectionnés
- [ ] Justification pour chaque contrôle
- [ ] Statut d'implémentation documenté

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 6.2 Objectifs de Sécurité de l'Information et Plans pour les Atteindre

- [ ] Objectifs de sécurité établis
- [ ] Objectifs cohérents avec la politique
- [ ] Objectifs mesurables
- [ ] Objectifs tiennent compte des exigences et résultats d'appréciation
- [ ] Objectifs surveillés
- [ ] Objectifs communiqués
- [ ] Objectifs mis à jour si approprié
- [ ] Plans pour atteindre les objectifs définis

**Objectifs de sécurité ICookForms (exemples):**
- [ ] Zéro vulnérabilité critique en production
- [ ] Temps de réponse aux incidents < 4h
- [ ] 100% des développeurs formés à la sécurité
- [ ] Couverture de tests > 90%
- [ ] Conformité GDPR/CCPA à 100%

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 6.3 Planification des Modifications

- [ ] Modifications du SMSI planifiées et contrôlées
- [ ] Intégrité du SMSI maintenue lors des modifications

**Preuves:** ________________________________

---

### CLAUSE 7: SUPPORT

#### 7.1 Ressources

- [ ] Ressources pour établir le SMSI déterminées et fournies
- [ ] Ressources pour maintenir le SMSI déterminées et fournies
- [ ] Ressources pour améliorer le SMSI déterminées et fournies

**Ressources allouées:**
- [ ] Personnel (nombre): ________
- [ ] Budget annuel sécurité: ________
- [ ] Outils de sécurité: ________
- [ ] Infrastructure: ________

**Preuves:** ________________________________

#### 7.2 Compétence

- [ ] Compétences nécessaires déterminées
- [ ] Personnel compétent (éducation, formation, expérience)
- [ ] Actions pour acquérir les compétences prises si nécessaire
- [ ] Efficacité des actions évaluée
- [ ] Preuves de compétence conservées

**Compétences clés ICookForms:**
- [ ] Rust secure coding
- [ ] OWASP Top 10
- [ ] Privacy & GDPR
- [ ] DevSecOps
- [ ] ISO 27001

**Formations suivies:** ________________________________  
**Certifications:** ________________________________  
**Preuves:** ________________________________

#### 7.3 Sensibilisation

- [ ] Personnel sensibilisé à la politique de sécurité
- [ ] Personnel conscient de sa contribution au SMSI
- [ ] Personnel conscient des conséquences de non-conformité

**Programme de sensibilisation:**
- [ ] Onboarding sécurité pour nouveaux arrivants
- [ ] Formations trimestrielles
- [ ] Tests de phishing simulés
- [ ] Communications sécurité régulières
- [ ] Taux de participation: ________%

**Preuves:** ________________________________

#### 7.4 Communication

- [ ] Communications internes et externes déterminées
- [ ] Sujets de communication définis
- [ ] Moments de communication définis
- [ ] Communicants définis
- [ ] Destinataires définis
- [ ] Processus de communication établi

**Canaux de communication ICookForms:**
- [ ] Email interne
- [ ] Slack/Teams
- [ ] Réunions d'équipe
- [ ] Intranet/Wiki
- [ ] Portail client (externe)

**Preuves:** ________________________________

#### 7.5 Informations Documentées

##### 7.5.1 Généralités

- [ ] SMSI inclut informations documentées requises par ISO 27001
- [ ] SMSI inclut informations documentées nécessaires à l'efficacité
- [ ] Étendue de la documentation appropriée

**Documents SMSI ICookForms:**
- [ ] Politique de sécurité
- [ ] Statement of Applicability (SoA)
- [ ] Analyse de risques
- [ ] Plan de traitement des risques
- [ ] Objectifs de sécurité
- [ ] Procédures opérationnelles
- [ ] Registre des actifs
- [ ] Registre des risques
- [ ] Registre des incidents

**Preuves:** ________________________________

##### 7.5.2 Création et Mise à Jour

- [ ] Identification et description des documents appropriées
- [ ] Format et support appropriés
- [ ] Revue et approbation définies
- [ ] Contrôle des versions

**Preuves:** ________________________________

##### 7.5.3 Maîtrise des Informations Documentées

- [ ] Documents disponibles et appropriés
- [ ] Documents protégés (confidentialité, intégrité, disponibilité)
- [ ] Distribution contrôlée
- [ ] Accès contrôlé
- [ ] Stockage et préservation assurés
- [ ] Maîtrise des modifications
- [ ] Conservation et élimination définies
- [ ] Documents d'origine externe identifiés et maîtrisés

**Système de gestion documentaire:**
- [ ] SharePoint/Confluence/Wiki configuré
- [ ] Droits d'accès définis
- [ ] Versioning activé
- [ ] Rétention définie

**Preuves:** ________________________________

---

### CLAUSE 8: FONCTIONNEMENT

#### 8.1 Planification et Maîtrise Opérationnelles

- [ ] Processus nécessaires planifiés, mis en œuvre et maîtrisés
- [ ] Modifications planifiées maîtrisées
- [ ] Conséquences de modifications non planifiées revues
- [ ] Processus externalisés maîtrisés
- [ ] Critères pour les processus établis
- [ ] Informations documentées conservées

**Processus opérationnels ICookForms:**
- [ ] Développement sécurisé (SDLC)
- [ ] Gestion des changements
- [ ] Gestion des incidents
- [ ] Gestion des vulnérabilités
- [ ] Sauvegarde et restauration
- [ ] Surveillance et monitoring

**Preuves:** ________________________________

#### 8.2 Appréciation des Risques de Sécurité de l'Information

- [ ] Appréciations à intervalles planifiés
- [ ] Appréciations lors de changements significatifs
- [ ] Résultats conservés

**Fréquence d'appréciation:**
- [ ] Annuelle (complète)
- [ ] Lors de changements majeurs
- [ ] Après incidents de sécurité

**Dernière appréciation:** ________________________________  
**Prochaine appréciation:** ________________________________  
**Preuves:** ________________________________

#### 8.3 Traitement des Risques de Sécurité de l'Information

- [ ] Plan de traitement mis en œuvre
- [ ] Résultats conservés

**Preuves:** ________________________________

---

### CLAUSE 9: ÉVALUATION DE LA PERFORMANCE

#### 9.1 Surveillance, Mesure, Analyse et Évaluation

- [ ] Méthodes de surveillance et mesure définies
- [ ] Ce qui doit être surveillé et mesuré déterminé
- [ ] Moments de surveillance et mesure déterminés
- [ ] Moments d'analyse et évaluation déterminés
- [ ] Résultats conservés

**KPI de sécurité ICookForms:**
- [ ] Nombre de vulnérabilités critiques: ________
- [ ] Temps moyen de résolution d'incident: ________
- [ ] Taux de conformité GDPR: ________%
- [ ] Couverture de tests: ________%
- [ ] Disponibilité du service: ________%
- [ ] Nombre d'incidents de sécurité: ________

**Preuves:** ________________________________  
**Commentaires:** ________________________________

#### 9.2 Audit Interne

##### 9.2.1 Généralités

- [ ] Programme d'audit interne établi
- [ ] Audits à intervalles planifiés (au moins annuel)
- [ ] Critères et périmètre d'audit définis
- [ ] Auditeurs objectifs et impartiaux
- [ ] Résultats rapportés à la direction
- [ ] Résultats conservés

**Programme d'audit ICookForms:**
- [ ] Audit Q1: Clauses 4-7
- [ ] Audit Q2: Clause 8 + Annex A Technological
- [ ] Audit Q3: Clauses 9-10 + ISO 27701
- [ ] Audit Q4: Audit complet + suivi

**Dernier audit:** ________________________________  
**Prochain audit:** ________________________________  
**Preuves:** ________________________________

##### 9.2.2 Programme d'Audit Interne

- [ ] Fréquence, méthodes, responsabilités définis
- [ ] Planification et reporting définis
- [ ] Importance des processus considérée
- [ ] Résultats d'audits précédents considérés

**Preuves:** ________________________________

#### 9.3 Revue de Direction

##### 9.3.1 Généralités

- [ ] Revues à intervalles planifiés (au moins annuelle)
- [ ] Convenance, adéquation et efficacité du SMSI évaluées

**Dernière revue:** ________________________________  
**Prochaine revue:** ________________________________  
**Preuves:** ________________________________

##### 9.3.2 Éléments d'Entrée de la Revue

- [ ] État des actions des revues précédentes
- [ ] Changements des enjeux internes/externes
- [ ] Retours sur la performance du SMSI (KPI)
- [ ] Retours des parties intéressées
- [ ] Résultats de l'appréciation des risques
- [ ] État du traitement des risques
- [ ] Résultats d'audit
- [ ] État des actions correctives
- [ ] Opportunités d'amélioration continue
- [ ] Événements de sécurité significatifs

**Preuves:** ________________________________

##### 9.3.3 Résultats de la Revue

- [ ] Décisions sur l'amélioration continue
- [ ] Décisions sur les modifications nécessaires
- [ ] Besoins en ressources identifiés
- [ ] Résultats conservés

**Preuves:** ________________________________

---

### CLAUSE 10: AMÉLIORATION

#### 10.1 Amélioration Continue

- [ ] Amélioration continue de la convenance, adéquation et efficacité
- [ ] Opportunités d'amélioration identifiées et sélectionnées
- [ ] Actions nécessaires mises en œuvre

**Améliorations réalisées cette année:** ________________________________  
**Améliorations planifiées:** ________________________________  
**Preuves:** ________________________________

#### 10.2 Non-Conformité et Action Corrective

- [ ] Processus de gestion des non-conformités établi
- [ ] Réaction à la non-conformité rapide
- [ ] Évaluation du besoin d'action corrective
- [ ] Action corrective mise en œuvre
- [ ] Efficacité de l'action évaluée
- [ ] SMSI mis à jour si nécessaire
- [ ] Causes similaires dans d'autres domaines considérées
- [ ] Résultats conservés

**Registre des non-conformités:**
- [ ] Nombre de NC cette année: ________
- [ ] NC critiques: ________
- [ ] NC majeures: ________
- [ ] NC mineures: ________
- [ ] Taux de résolution: ________%

**Preuves:** ________________________________

---

## PARTIE 2: ANNEX A - CONTRÔLES DE SÉCURITÉ

### A.5 CONTRÔLES ORGANISATIONNELS (37 contrôles)

#### A.5.1 Politiques de Sécurité de l'Information

**A.5.1.1 Politiques pour la sécurité de l'information**
- [ ] Ensemble de politiques de sécurité défini
- [ ] Politiques approuvées par la direction
- [ ] Politiques publiées et communiquées
- [ ] Politiques reconnues par les parties intéressées

**A.5.1.2 Revue des politiques pour la sécurité de l'information**
- [ ] Politiques revues à intervalles planifiés
- [ ] Politiques revues en cas de changements significatifs
- [ ] Fréquence: Annuelle minimum

**Preuves:** ________________________________

#### A.5.2 Rôles et Responsabilités de la Sécurité

**A.5.2.1 Rôles et responsabilités de sécurité de l'information**
- [ ] Rôles et responsabilités définis
- [ ] Rôles et responsabilités alloués
- [ ] Rôles et responsabilités communiqués

**A.5.2.2 Séparation des tâches**
- [ ] Tâches conflictuelles séparées
- [ ] Risque de modification non autorisée réduit
- [ ] Risque de mauvaise utilisation réduit

**Preuves:** ________________________________

#### A.5.3 Responsabilités en Matière de Séparation

**A.5.3.1 Contact avec les autorités**
- [ ] Contacts appropriés maintenus
- [ ] Liste des autorités pertinentes maintenue

**A.5.3.2 Contact avec les groupes d'intérêt spéciaux**
- [ ] Contacts avec groupes d'intérêt maintenus
- [ ] Participation à forums de sécurité

**Preuves:** ________________________________

#### A.5.4 Sécurité dans la Gestion de Projet

**A.5.4.1 Sécurité de l'information dans la gestion de projet**
- [ ] Sécurité intégrée dans la gestion de projet
- [ ] Security requirements dans les projets
- [ ] Threat modeling réalisé

**Preuves:** ________________________________

#### A.5.5 Sécurité dans les Relations avec les Fournisseurs

**A.5.5.1 Sécurité dans les accords avec les fournisseurs**
- [ ] Exigences de sécurité établies avec fournisseurs
- [ ] SLA incluant clauses de sécurité
- [ ] DPA (Data Processing Agreement) signés

**A.5.5.2 Gestion de la prestation de services par des fournisseurs**
- [ ] Performance des fournisseurs surveillée
- [ ] Performance revue régulièrement
- [ ] Audits de fournisseurs réalisés

**Preuves:** ________________________________

#### A.5.6 Traitement des Incidents

**A.5.6.1 Responsabilités et procédures**
- [ ] Responsabilités de gestion des incidents établies
- [ ] Procédures de gestion des incidents établies
- [ ] Processus de réponse rapide et efficace

**A.5.6.2 Apprentissage des incidents**
- [ ] Analyse des incidents réalisée
- [ ] Connaissances utilisées pour réduire risques futurs
- [ ] Post-mortems documentés

**A.5.6.3 Collecte de preuves**
- [ ] Preuves identifiées et collectées
- [ ] Preuves acquises et préservées
- [ ] Chain of custody maintenue

**Preuves:** ________________________________

#### A.5.7 Sécurité Pendant la Perturbation

**A.5.7.1 Planification de la continuité de la sécurité**
- [ ] Exigences de continuité planifiées
- [ ] BCP/DRP en place
- [ ] Tests de continuité réalisés

**A.5.7.2 Disponibilité de la sécurité en période de crise**
- [ ] Niveau de disponibilité vérifié
- [ ] Niveau de disponibilité maintenu en crise

**Preuves:** ________________________________

#### A.5.8 Gestion de la Sécurité Physique

**A.5.8.1 Périmètres de sécurité physique**
- [ ] Périmètres de sécurité définis
- [ ] Périmètres utilisés pour protéger zones sensibles

**A.5.8.2 Entrée physique sécurisée**
- [ ] Zones sécurisées protégées
- [ ] Contrôles d'entrée en place

**A.5.8.3 Sécurisation des bureaux, salles et installations**
- [ ] Sécurité physique conçue
- [ ] Sécurité physique implémentée

**A.5.8.4 Surveillance de la sécurité physique**
- [ ] Locaux surveillés en continu
- [ ] Surveillance contre accès non autorisé

**A.5.8.5 Protection contre les menaces physiques et environnementales**
- [ ] Protection contre incendie
- [ ] Protection contre inondation
- [ ] Protection contre autres menaces

**A.5.8.6 Travail dans les zones sécurisées**
- [ ] Mesures de sécurité appliquées
- [ ] Procédures pour zones sécurisées

**Preuves:** ________________________________

#### A.5.9 Gestion des Actifs

**A.5.9.1 Inventaire des actifs**
- [ ] Inventaire des actifs établi
- [ ] Inventaire des actifs maintenu
- [ ] Actifs informationnels identifiés

**A.5.9.2 Propriété des actifs**
- [ ] Actifs dans l'inventaire ont un propriétaire
- [ ] Propriétaire identifié et responsable

**A.5.9.3 Utilisation acceptable des actifs**
- [ ] Règles d'utilisation identifiées
- [ ] Règles d'utilisation documentées
- [ ] Règles d'utilisation implémentées

**A.5.9.4 Retour des actifs**
- [ ] Personnel retourne actifs lors de départ
- [ ] Processus de retour défini

**Preuves:** ________________________________

#### A.5.10 Contrôle de l'Information

**A.5.10.1 Classification de l'information**
- [ ] Information classifiée selon besoins
- [ ] Schéma de classification défini

**A.5.10.2 Étiquetage de l'information**
- [ ] Étiquettes appliquées à l'information
- [ ] Étiquettes appropriées au schéma

**A.5.10.3 Gestion de l'information**
- [ ] Information gérée selon classification
- [ ] Procédures de gestion documentées

**A.5.10.4 Traitement de l'information**
- [ ] Information traitée selon classification
- [ ] Contrôles appliqués selon niveau

**Preuves:** ________________________________

#### A.5.11 Conformité Légale et Contractuelle

**A.5.11.1 Identification des exigences légales et contractuelles**
- [ ] Exigences légales identifiées
- [ ] Exigences statutaires identifiées
- [ ] Exigences réglementaires identifiées
- [ ] Exigences contractuelles identifiées
- [ ] Exigences documentées et maintenues

**A.5.11.2 Protection des droits de propriété intellectuelle**
- [ ] Procédures pour protéger PI établies
- [ ] Licences logicielles gérées

**A.5.11.3 Protection des enregistrements**
- [ ] Enregistrements protégés contre perte
- [ ] Enregistrements protégés contre destruction
- [ ] Enregistrements protégés contre falsification

**A.5.11.4 Confidentialité et protection des informations personnelles**
- [ ] Confidentialité assurée
- [ ] Protection des PII assurée
- [ ] Conformité GDPR/CCPA

**A.5.11.5 Revue indépendante de la sécurité**
- [ ] Approche de sécurité revue indépendamment
- [ ] Revue à intervalles planifiés

**Preuves:** ________________________________

---

### A.6 CONTRÔLES DE PERSONNEL (8 contrôles)

#### A.6.1 Filtrage

**A.6.1.1 Filtrage**
- [ ] Vérifications des antécédents effectuées
- [ ] Conformité aux lois et réglementations
- [ ] Conformité à l'éthique

**Preuves:** ________________________________

#### A.6.2 Termes et Conditions d'Emploi

**A.6.2.1 Termes et conditions d'emploi**
- [ ] Accords contractuels incluent responsabilités sécurité
- [ ] Responsabilités de l'organisation définies
- [ ] Responsabilités du personnel définies

**Preuves:** ________________________________

#### A.6.3 Sensibilisation, Éducation et Formation

**A.6.3.1 Sensibilisation, éducation et formation à la sécurité**
- [ ] Personnel reçoit sensibilisation appropriée
- [ ] Personnel reçoit éducation appropriée
- [ ] Personnel reçoit formation appropriée
- [ ] Formation régulière et mise à jour

**A.6.3.2 Processus disciplinaire**
- [ ] Processus disciplinaire formel établi
- [ ] Processus communiqué pour actions contre politiques

**Preuves:** ________________________________

#### A.6.4 Responsabilités de Fin ou Changement d'Emploi

**A.6.4.1 Responsabilités de fin ou changement d'emploi**
- [ ] Responsabilités valides après fin d'emploi
- [ ] Responsabilités valides après changement d'emploi
- [ ] Processus de départ défini

**A.6.4.2 Accords de confidentialité ou de non-divulgation**
- [ ] Accords de confidentialité reflètent besoins
- [ ] Accords de non-divulgation reflètent besoins
- [ ] NDA signés

**Preuves:** ________________________________

---

### A.7 CONTRÔLES PHYSIQUES (14 contrôles)

#### A.7.1 Sécurité Physique des Locaux

**A.7.1.1 Périmètres de sécurité physique**
- [ ] Périmètres définis et utilisés
- [ ] Protection des zones sensibles

**A.7.1.2 Entrée physique sécurisée**
- [ ] Zones protégées par contrôles d'entrée

**A.7.1.3 Sécurisation des bureaux, salles et installations**
- [ ] Sécurité physique conçue et implémentée

**Preuves:** ________________________________

#### A.7.2 Équipement

**A.7.2.1 Emplacement et protection du matériel**
- [ ] Équipement situé ou protégé pour réduire risques

**A.7.2.2 Services d'alimentation**
- [ ] Équipement protégé contre pannes
- [ ] UPS/générateurs en place

**A.7.2.3 Sécurité du câblage**
- [ ] Câbles protégés contre interception
- [ ] Câbles protégés contre interférence

**A.7.2.4 Maintenance de l'équipement**
- [ ] Équipement maintenu correctement
- [ ] Maintenance préventive planifiée

**A.7.2.5 Élimination sécurisée des équipements**
- [ ] Équipements traités de manière sécurisée
- [ ] Données effacées avant élimination

**A.7.2.6 Sécurité des équipements hors des locaux**
- [ ] Actifs hors locaux protégés
- [ ] Politique clear desk/clear screen

**A.7.2.7 Réutilisation ou élimination sécurisée des dispositifs**
- [ ] Dispositifs vérifiés pour suppression sécurisée

**Preuves:** ________________________________

#### A.7.3 Utilisation Sécurisée des Supports

**A.7.3.1 Gestion des supports amovibles**
- [ ] Procédures pour supports amovibles
- [ ] USB gérées et contrôlées

**A.7.3.2 Élimination des supports**
- [ ] Supports éliminés de manière sécurisée

**A.7.3.3 Supports physiques en transit**
- [ ] Supports protégés durant transport

**Preuves:** ________________________________

---

### A.8 CONTRÔLES TECHNOLOGIQUES (34 contrôles)

#### A.8.1 Dispositifs de Point de Terminaison

**A.8.1.1 Gestion des dispositifs**
- [ ] Informations sur dispositifs protégées
- [ ] MDM implémenté

**A.8.1.2 Accès privilégié**
- [ ] Droits privilégiés restreints et gérés
- [ ] MFA pour accès privilégié

**A.8.1.3 Restriction d'accès à l'information**
- [ ] Accès restreint conformément à la politique

**A.8.1.4 Accès au code source**
- [ ] Accès en lecture/écriture géré
- [ ] Branch protection activée

**Preuves:** ________________________________

#### A.8.2 Droits d'Accès Privilégiés

**A.8.2.1 Gestion des droits d'accès privilégiés**
- [ ] Allocation restreinte
- [ ] Utilisation gérée

**A.8.2.2 Revue des droits d'accès**
- [ ] Propriétaires examinent droits régulièrement
- [ ] Revue trimestrielle

**A.8.2.3 Retrait ou ajustement des droits**
- [ ] Droits retirés lors de fin d'emploi
- [ ] Droits ajustés lors de changement

**Preuves:** ________________________________

#### A.8.3 Restriction d'Accès à l'Information

**A.8.3.1 Restriction d'accès**
- [ ] Accès restreint conformément à politique

**A.8.3.2 Procédures de connexion sécurisée**
- [ ] Connexion sécurisée implémentée
- [ ] MFA activée

**A.8.3.3 Système de gestion des mots de passe**
- [ ] Systèmes assurent mots de passe de qualité
- [ ] Politique de mot de passe forte

**Preuves:** ________________________________

#### A.8.4 Accès au Code Source

**A.8.4.1 Accès au code source**
- [ ] Accès géré de manière appropriée
- [ ] Protected branches configurées

**Preuves:** ________________________________

#### A.8.5 Authentification Sécurisée

**A.8.5.1 Authentification sécurisée**
- [ ] Technologies d'authentification implémentées

**A.8.5.2 Authentification multifactorielle**
- [ ] MFA implémentée
- [ ] MFA obligatoire pour production

**Preuves:** ________________________________

#### A.8.6 Gestion des Capacités

**A.8.6.1 Gestion des capacités**
- [ ] Utilisation des ressources surveillée
- [ ] Utilisation ajustée selon besoins

**Preuves:** ________________________________

#### A.8.7 Protection contre les Maliciels

**A.8.7.1 Protection contre les programmes malveillants**
- [ ] Protection implémentée
- [ ] Antivirus/EDR installé
- [ ] Sensibilisation des utilisateurs

**Preuves:** ________________________________

#### A.8.8 Gestion des Vulnérabilités Techniques

**A.8.8.1 Gestion des vulnérabilités**
- [ ] Informations sur vulnérabilités obtenues
- [ ] Évaluation de l'exposition effectuée
- [ ] Mesures prises en temps opportun

**A.8.8.2 Prévention du vol d'information**
- [ ] Mesures DLP implémentées

**Preuves:** ________________________________

#### A.8.9 Logging et Surveillance

**A.8.9.1 Journalisation**
- [ ] Logs produits, stockés et revus
- [ ] Événements de sécurité journalisés

**A.8.9.2 Surveillance des activités**
- [ ] Réseaux surveillés
- [ ] Systèmes surveillés
- [ ] Applications surveillées

**A.8.9.3 Protection des logs**
- [ ] Logs protégés contre falsification
- [ ] Logs protégés contre accès non autorisé

**A.8.9.4 Synchronisation des horloges**
- [ ] Horloges synchronisées avec source approuvée
- [ ] NTP configuré

**Preuves:** ________________________________

#### A.8.10 Gestion de la Configuration

**A.8.10.1 Suppression des fonctionnalités non nécessaires**
- [ ] Fonctionnalités non nécessaires désactivées
- [ ] Ports non nécessaires fermés

**A.8.10.2 Lignes de base sécurisées**
- [ ] Baselines établies
- [ ] CIS Benchmarks appliqués

**A.8.10.3 Revue des configurations**
- [ ] Configurations revues à intervalles définis

**Preuves:** ________________________________

#### A.8.11 Contrôle des Changements

**A.8.11.1 Gestion des changements**
- [ ] Changements gérés via procédures
- [ ] CI/CD implémenté

**A.8.11.2 Test des changements**
- [ ] Changements testés avant implémentation
- [ ] Tests automatisés

**Preuves:** ________________________________

#### A.8.12 Information Leakage

**A.8.12.1 Prévention de la fuite d'information**
- [ ] Mesures de prévention implémentées
- [ ] Secrets scanning activé

**Preuves:** ________________________________

#### A.8.13 Sauvegarde de l'Information

**A.8.13.1 Sauvegarde**
- [ ] Copies de sauvegarde maintenues
- [ ] Sauvegardes testées régulièrement

**Preuves:** ________________________________

#### A.8.14 Redondance

**A.8.14.1 Redondance des installations**
- [ ] Installations avec redondance suffisante
- [ ] Multi-AZ deployment

**Preuves:** ________________________________

#### A.8.15 Journalisation (duplicate A.8.9.1)

**A.8.15.1 Journalisation**
- [ ] Voir A.8.9.1

#### A.8.16 Surveillance (duplicate A.8.9.2)

**A.8.16.1 Activités de surveillance**
- [ ] Voir A.8.9.2

#### A.8.17 Synchronisation (duplicate A.8.9.4)

**A.8.17.1 Synchronisation des horloges**
- [ ] Voir A.8.9.4

#### A.8.18 Programmes Utilitaires Privilégiés

**A.8.18.1 Utilisation de programmes utilitaires privilégiés**
- [ ] Utilisation restreinte et contrôlée

**Preuves:** ________________________________

#### A.8.19 Installation de Logiciels

**A.8.19.1 Installation de logiciels**
- [ ] Procédures et mesures pour gérer installation
- [ ] Whitelist d'applications

**Preuves:** ________________________________

#### A.8.20 Sécurité des Réseaux

**A.8.20.1 Sécurité des réseaux**
- [ ] Réseaux protégés et gérés
- [ ] Firewall configuré

**A.8.20.2 Services réseau sécurisés**
- [ ] Mécanismes de sécurité dans services réseau

**Preuves:** ________________________________

#### A.8.21 Sécurité des Services Réseau

**A.8.21.1 Sécurité des services réseau**
- [ ] Mécanismes de sécurité implémentés

**Preuves:** ________________________________

#### A.8.22 Ségrégation des Réseaux

**A.8.22.1 Ségrégation**
- [ ] Groupes ségrégués sur réseaux
- [ ] VPC/subnets configurés

**Preuves:** ________________________________

#### A.8.23 Filtrage Web

**A.8.23.1 Filtrage web**
- [ ] Accès aux sites web géré
- [ ] Web filtering activé

**Preuves:** ________________________________

#### A.8.24 Utilisation de la Cryptographie

**A.8.24.1 Utilisation de la cryptographie**
- [ ] Règles pour cryptographie définies
- [ ] Règles implémentées
- [ ] TLS 1.3 minimum

**Preuves:** ________________________________

#### A.8.25 Cycle de Vie de Développement Sécurisé

**A.8.25.1 Règles de développement sécurisé**
- [ ] Règles établies et appliquées
- [ ] Secure SDLC implémenté

**A.8.25.2 Contrôle des changements d'application**
- [ ] Changements contrôlés via procédures

**A.8.25.3 Examen technique après changements**
- [ ] Applications revues après changements de plate-forme

**Preuves:** ________________________________

#### A.8.26 Exigences de Sécurité des Applications

**A.8.26.1 Exigences de sécurité**
- [ ] Exigences identifiées
- [ ] Exigences spécifiées
- [ ] Exigences approuvées

**Preuves:** ________________________________

#### A.8.27 Architecture et Principes Sécurisés

**A.8.27.1 Principes d'ingénierie de la sécurité**
- [ ] Principes établis, documentés, maintenus
- [ ] Principes appliqués

**Preuves:** ________________________________

#### A.8.28 Codage Sécurisé

**A.8.28.1 Codage sécurisé**
- [ ] Principes de codage sécurisé appliqués
- [ ] OWASP guidelines suivis

**Preuves:** ________________________________

#### A.8.29 Tests de Sécurité

**A.8.29.1 Tests de sécurité**
- [ ] Processus de test défini
- [ ] Processus implémenté dans cycle dev

**Preuves:** ________________________________

#### A.8.30 Développement Externalisé

**A.8.30.1 Développement externalisé**
- [ ] Activités externalisées supervisées
- [ ] Activités externalisées surveillées

**Preuves:** ________________________________

#### A.8.31 Séparation des Environnements

**A.8.31.1 Séparation des environnements**
- [ ] Environnements dev, test, prod séparés
- [ ] Environnements sécurisés

**Preuves:** ________________________________

#### A.8.32 Gestion des Changements (duplicate A.8.11.1)

**A.8.32.1 Gestion des changements**
- [ ] Voir A.8.11.1

#### A.8.33 Information de Test

**A.8.33.1 Information de test**
- [ ] Données de test sélectionnées avec soin
- [ ] Données de test protégées
- [ ] Anonymisation appliquée

**Preuves:** ________________________________

#### A.8.34 Protection Durant Tests d'Audit

**A.8.34.1 Protection des systèmes durant tests d'audit**
- [ ] Tests planifiés et convenus
- [ ] Backup avant tests

**Preuves:** ________________________________

---

## SCORE DE CONFORMITÉ

### Calcul du Score

**Clauses 4-10 (10 clauses):**
- Conformes: _____ / 10
- Score Clauses: _____% 

**Annex A (93 contrôles):**
- A.5 Organizational (37): _____ / 37
- A.6 People (8): _____ / 8
- A.7 Physical (14): _____ / 14
- A.8 Technological (34): _____ / 34
- **Total Annex A: _____ / 93**
- **Score Annex A: _____%**

**SCORE GLOBAL ISO 27001: _____%**

### Interprétation

- **≥95%:** ⭐⭐⭐ Excellent - Prêt pour certification
- **90-94%:** ⭐⭐ Très Bon - Corrections mineures nécessaires
- **80-89%:** ⭐ Bon - Corrections modérées nécessaires
- **70-79%:** Acceptable - Améliorations importantes requises
- **<70%:** Insuffisant - Travail majeur nécessaire

---

## PLAN D'ACTION

### Non-Conformités Identifiées

| ID | Contrôle | Sévérité | Action | Responsable | Date Limite | Status |
|----|----------|----------|--------|-------------|-------------|--------|
| NC-001 | | | | | | ⏳ |
| NC-002 | | | | | | ⏳ |
| NC-003 | | | | | | ⏳ |

### Observations et Recommandations

| ID | Contrôle | Observation | Recommandation | Priorité |
|----|----------|-------------|----------------|----------|
| OBS-001 | | | | |
| OBS-002 | | | | |
| OBS-003 | | | | |

---

## VALIDATION

**Complété par:** ________________________________  
**Date:** ________________________________  
**Signature:** ________________________________

**Revu par (Responsable SMSI):** ________________________________  
**Date:** ________________________________  
**Signature:** ________________________________

**Approuvé par (Direction):** ________________________________  
**Date:** ________________________________  
**Signature:** ________________________________

---

**Document créé le:** 1er Novembre 2025  
**Version:** 1.0.0  
**Prochaine revue:** 1er Février 2026  
**Propriétaire:** Responsable SMSI

**© 2025 ICookForms - All Rights Reserved**
