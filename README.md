# Ajaia AI-Native Assessment

**Candidate:** Jaden Mascarenhas
**Role:** Information Security Analyst
**Ajaia:** https://ajaia.ai

> **Submission note:** This document is structured for direct Markdown submission. I state assumptions where evidence is incomplete and prioritise practical execution for Ajaia's 20-person, regulated-industry environment. Regulatory citations are to primary sources (45 CFR, 34 CFR, AICPA TSC).

---

# Module 1 — Security Architecture & Cloud Infrastructure

## 1. Five Most Critical Security Risks

| Rank | Severity | Risk | Why Critical | Exact Remediation |
|---|---|---|---|---|
| 1 | Critical | Public Cloud SQL exposure | Harmoni PHI and client project data sit on Cloud SQL with a public IP and an authorised-networks list containing `0.0.0.0/0`. This is a direct, unauthenticated-at-the-network-layer path from the internet to regulated data, and it is the same database the Module 2 incident was executed against. | Remove `0.0.0.0/0` from authorised networks immediately; disable public IP; migrate to Private IP via Private Service Access; permit access only from the application subnet and named service identities using VPC firewall rules; enable Cloud SQL Auth Proxy or IAM database authentication; enable Cloud Audit Logs (Data Access) and review historic access. |
| 2 | Critical | Exposed and unrotated credentials | API keys are committed in `.env` files in repos, personal SSH keys sit in a shared Drive folder, and FileVault recovery keys are in a Sheet shared with all 20 employees. A service-account key was also published to a public GitHub repo and never rotated. Any single leak yields production access. | Revoke and rotate every exposed key; treat all repo-committed secrets as burned. Migrate GCP secrets to Secret Manager and Azure secrets to Key Vault. Replace shared SSH keys with OS Login + IAP TCP forwarding (no public SSH). Remove recovery keys from Sheets into MDM escrow. Purge secrets from Git history (`git filter-repo` / BFG) and force-push. Enable Secret Manager rotation schedules and GitHub push protection / secret scanning org-wide. |
| 3 | Critical | Excessive standing privilege in GCP and AKS | Project-level service accounts hold `roles/owner`, every employee has Editor on all GCP projects, and five developers hold `cluster-admin` on AKS. One compromised identity equals full environment control — which is precisely what made the Module 2 incident a project-wide event rather than a single-database event. | Remove `roles/owner` from service accounts and Editor from users; create per-workload service accounts with narrowly scoped roles; use Workload Identity Federation for GCP and Workload Identity for AKS so no static keys exist. Remove standing `cluster-admin`; bind developers to namespace-scoped roles via Azure RBAC for Kubernetes. Use Entra Privileged Identity Management for time-bound elevation. Enable IAM Recommender to drive role right-sizing. |
| 4 | High | Unmanaged, unverifiable endpoints | 20 remote staff, no MDM, 6 personal Linux machines, FileVault self-reported on 11 of 20 and unverified. Staff working on Harmoni handle PHI on devices Ajaia cannot attest to. The Module 2 stolen laptop shows the exposure is real, not theoretical. | Enrol all 14 company MacBooks in MDM; enforce and attest FileVault with escrowed keys, screen-lock timeout, and a strong passphrase policy (see the 4-digit PIN finding below); deploy endpoint protection. Require compliant/hybrid-joined devices for access to production and PHI via Entra Conditional Access. Either enrol the 6 personal Linux devices or move them to a browser-only/VDI path with no local sync of regulated data. |
| 5 | High | Inadequate backup, retention and recovery | Harmoni PHI: daily backups, 7-day retention, **no PITR**. General client data: weekly, 7-day. GCS deliverables: single region, no versioning, no backup. Ransomware, malicious deletion, or a regional failure produces unrecoverable loss of regulated client data, and 7 days is shorter than the dwell time of the incident in Module 2. | Enable Cloud SQL Point-in-Time Recovery on Harmoni and extend backup retention to a defined, documented period. Enable GCS Object Versioning plus a Bucket Lock / retention policy on backup buckets, and replicate to a second region. Hold immutable copies outside the primary failure domain and outside the production project's IAM boundary. Define RPO/RTO per dataset and evidence a tested restore quarterly. |

**Prioritisation rationale**

These five outrank the remaining issues because each creates a direct path to compromise of regulated data, production systems, or the ability to recover. Ranks 1–3 are chained: the public database is reachable, the credentials to it are exposed, and the identities holding those credentials are over-privileged. That chain is exactly what executed in Module 2. Ranks 4–5 govern whether an endpoint compromise becomes a PHI disclosure and whether Ajaia can recover if it does.

**Deliberately ranked below the top five — and why they still matter**

- **30-day log retention.** Important, and I flag a direct conflict with Module 2: my incident response depends on establishing when the service-account key was first exposed and everything it touched. If exposure predates the 30-day window, that question is unanswerable and the HIPAA four-factor assessment becomes materially harder to document. I would extend security and Data Access log retention as part of the Days 0–30 work even though it is not a top-five *exposure*, because it is a top-five *evidence* dependency. HIPAA §164.312(b) requires audit controls, and §164.316(b)(2)(i) requires six-year retention of required documentation.
- **Docker Hub `latest` tags and GCR rather than Artifact Registry.** Mutable tags mean no reproducible builds and no supply-chain provenance; GCR is deprecated in favour of Artifact Registry. Remediate by pinning image digests, mirroring base images into Artifact Registry, enabling vulnerability scanning, and enforcing Binary Authorization.
- **AKS default namespace, no Pod Security Standards.** No workload isolation and no admission control. Remediate with `prod`/`dev`/`ops` namespaces, PSS in `restricted` mode, and default-deny Network Policies.
- **Shared VPN pre-shared key across all tunnels.** One PSK disclosure compromises every tunnel and defeats per-tunnel revocation. Remediate with unique PSKs per tunnel and rotation.
- **Default auto-mode VPC.** Auto-created subnets in every region with no trust separation. Addressed in the redesign below.

---

## 2. Target-State Network Security Architecture

**Design principle:** private by default, least privilege, centralised identity, short-lived credentials, strong segmentation, auditable access — sized so that a 20-person company can actually run it.

**Why:** Ajaia today has public database exposure, standing over-privilege, shared static secrets, unmanaged endpoints and no meaningful segmentation. This design reduces attack surface, limits lateral movement, and makes access reviewable.

### VPC redesign

Replace the GCP default auto-mode VPC with a **custom-mode VPC**, with subnets separated by trust level.

- Dedicated subnets for **ingress**, **application**, **data**, and **management/CI** workloads, with explicitly assigned non-overlapping ranges.
- Application and data workloads on **private IPs only**; no external addresses.
- **Hierarchical firewall policies** at the folder level plus VPC firewall rules, default-deny egress, allowing only required flows between subnets, expressed by service account rather than IP where possible.
- **Cloud NAT** for controlled, logged outbound access; **Private Google Access** so workloads reach Google APIs without egressing.
- **VPC Service Controls** perimeter around the projects holding Harmoni and Ethos data, so that even a valid stolen credential cannot pull data to an outside project. This is the single control that would most have limited the Module 2 blast radius.
- Restrict advertised routes across the GCP–Azure VPN to the specific ranges each side needs, and issue a **unique PSK per tunnel** with a rotation schedule.

### Private Cloud SQL connectivity

- Remove `0.0.0.0/0` from authorised networks **immediately** — this is a same-day action, not a project.
- Disable the **public IP**.
- Move Cloud SQL to **Private IP via Private Service Access**.
- Require connections through **Cloud SQL Auth Proxy** with **IAM database authentication**, so database access is tied to an IAM identity that can be revoked centrally rather than to a static password.
- Permit connections only from the application subnet and named service identities.
- Enable **Cloud Audit Logs (Admin Activity and Data Access)** and Cloud SQL logging; Data Access logs are off by default and must be explicitly enabled — without them the Module 2 query-level evidence does not exist.
- Enable **Point-in-Time Recovery** on Harmoni and extend retention.
- Enforce **CMEK** via Cloud KMS for the PHI instance so key access is separately governed and revocable.

### Identity federation: Microsoft Entra ID ↔ GCP

**Choice and justification.** Ajaia runs both Google Workspace and Entra ID, already synced, so either could serve as the workforce IdP. I would designate **Entra ID as the authoritative workforce IdP** for three reasons specific to this environment: the Azure/AKS estate already authenticates natively against it; Conditional Access is the only control in the current stack that can enforce *device compliance* as a condition of access to PHI, which is the fix for Risk 4; and Privileged Identity Management provides time-bound elevation, which is the fix for Risk 3. Google Cloud Identity has no equivalent to PIM. Standardising on Entra therefore removes two named risks rather than merely relocating the login page. Google Workspace remains the collaboration suite, consuming Entra as its SAML IdP.

- Configure **GCP Workforce Identity Federation** with Entra ID as the SAML/OIDC provider.
- Map Entra security groups to GCP IAM roles; group membership becomes the only grant mechanism, so there are no individual bindings to audit.
- Enforce **MFA** and **Conditional Access**: compliant device required for production and any project holding PHI or education records; phishing-resistant MFA (FIDO2/passkeys) for Tier 0 admin roles; block legacy authentication.
- Remove broad Editor/Owner bindings; grant via group only.
- Use **Entra PIM** for time-bound, approval-gated, fully logged administrative elevation.
- Apply a formal joiner–mover–leaver process. Note that the Module 2 attacker attempted a former employee's credentials — that account should not have been in a state where an authentication attempt was possible at all.

**Cost and licensing — stated explicitly.** Conditional Access requires Entra ID P1; PIM requires Entra ID P2. At 20 seats this is a real line item (verify current list pricing; P2 has historically been in the region of USD 9/user/month, so roughly USD 2,000–2,200/year), plus MDM licensing. I am recommending it anyway because Conditional Access and PIM each directly retire a top-five risk, but I would present it to the CEO as a priced decision rather than an assumed one. If only one tier can be funded initially, I would take P1 for Conditional Access first — device compliance for PHI access is the higher-value control — and manage privileged elevation through a manual, logged break-glass process until P2 is affordable.

### Secrets-management migration plan

**Phase 1 — Contain (Days 0–7).** Inventory every secret in repos, Drive and Sheets. Treat all as compromised. Revoke and rotate: GCP service-account keys, API keys, SSH keys, database credentials, VPN PSKs, FileVault recovery keys. Enable GitHub secret scanning with push protection across the org.

**Phase 2 — Migrate (Days 7–45).** GCP secrets to **Secret Manager**; Azure secrets to **Key Vault**. Grant access to workloads by service identity, not to humans. Enable versioning, rotation schedules, access logging and alerting on secret access. Cloud Build pulls from Secret Manager at build time; nothing is written to `.env` in a repo.

**Phase 3 — Eliminate static credentials (Days 45–90).** Replace service-account *keys* with **Workload Identity Federation** (for CI/CD and any external system) and **Workload Identity** (for AKS/GKE), so no downloadable key material exists to leak. Replace shared SSH keys with **OS Login + IAP TCP forwarding**, removing public SSH exposure entirely and tying VM access to IAM identity. Move FileVault recovery keys into MDM escrow, accessible only to IT.

**Phase 4 — Sustain.** Pre-commit hooks and CI secret scanning; quarterly secret inventory; alerting on any new long-lived key creation.

**Why this ordering:** rotation without migration recreates the same exposure within weeks, and migration without eliminating static keys leaves a downloadable artifact that can be committed again. The Module 2 incident is precisely the failure mode Phase 3 removes.

### Supporting controls

**AKS hardening.** Remove standing `cluster-admin`; integrate with Entra ID and Azure RBAC for Kubernetes; separate `prod`, `dev` and `ops` namespaces; enforce Pod Security Standards in `restricted` mode; default-deny Network Policies; secrets from Key Vault via the CSI driver, not Kubernetes Secrets; private API server endpoint; Defender for Containers.

**Logging and detection.** Extend security and Data Access log retention well beyond 30 days; centralise GCP and Azure logs into a single sink; alert on IAM policy changes, service-account key creation, secret access, `0.0.0.0/0` firewall rules, impossible-travel authentication and anomalous database query volume. Retain documentation for six years per §164.316(b)(2)(i).

**Endpoints.** MDM enrolment for company devices; enforced and attested FileVault with escrowed keys; **passphrase policy that prohibits 4- or 6-digit numeric PINs**; short screen-lock timeout; remote wipe; Conditional Access device-compliance gating for PHI and production.

**Backup and recovery.** Cloud SQL PITR; extended retention; GCS Object Versioning; cross-region, immutable, separately-permissioned backup copies; documented RPO/RTO; quarterly evidenced restore tests. This also supports SOC 2 A1.2.

### 90-Day Remediation Plan

| Timeline | Priority actions | Owner | Evidence of completion |
|---|---|---|---|
| Days 0–30 | Remove `0.0.0.0/0`; disable Cloud SQL public IP; rotate all exposed credentials and purge Git history; remove `roles/owner` and standing `cluster-admin`; enforce MFA and initial Conditional Access; enable Harmoni PITR; enable Data Access audit logs and extend retention; begin MDM enrolment | IT & Security Lead with Cloud/Engineering leads | Cloud SQL config export, rotated-credential inventory, IAM policy diff (before/after), MFA/CA coverage report, PITR enabled screenshot, log-retention config |
| Days 31–60 | Build custom-mode VPC and migrate workloads; Cloud SQL to Private IP + Auth Proxy + IAM auth; deploy Workforce Identity Federation with Entra; complete Secret Manager / Key Vault migration; AKS namespaces, PSS and Network Policies; unique VPN PSKs; pin image digests and move to Artifact Registry | Cloud/Platform Lead with Security | Private-connectivity test results, federation login evidence, secrets migration report, AKS RBAC and policy export, tunnel config, registry/digest evidence |
| Days 61–90 | Complete MDM rollout and FileVault attestation; enable Workload Identity Federation to eliminate static keys; VPC Service Controls perimeter; GCS versioning and cross-region immutable backups; tested restore; centralised alerting; first quarterly access recertification | Security with IT Operations | MDM compliance report, zero-remaining-SA-keys report, perimeter config, restore-test record with RTO achieved, alert test evidence, signed access review |

**Architecture diagram:** [Supplementary material link](https://drive.google.com/file/d/1jX_9WJuNviDXhmqqTWuyawwRaPwRrPPm/view?usp=sharing)

---

# Module 2 — Incident Response & Crisis Management

## 1. First 60 Minutes

### 0–10 minutes — Validate and contain

**Actions**

1. Declare a **P0 incident**; open the incident record; start a timestamped log of every action and who took it.
2. Confirm the alert is not a false positive (verify the source IP is genuinely outside all employee and contractor geographies, and that no VPN or third-party integration explains it).
3. **Disable, then delete, the compromised service-account key.** Disable first so the key metadata is preserved for forensics.
4. Identify which production workloads authenticate with that key before disabling the *account*, so containment does not cause an unplanned outage.
5. Issue a clean, minimally-scoped replacement identity only where service continuity requires it.
6. Assign responders and a communications owner.

**Owner:** IT & Security Lead, supported by Cloud/Platform Engineering.

**Why:** There is confirmed unauthorised use of a credential with access to a database containing PHI. The priority is stopping further access while avoiding a self-inflicted outage that would complicate the response.

### 10–30 minutes — Preserve evidence, hunt for persistence, establish scope

**Actions**

1. **Preserve evidence before changing state:** export Cloud Audit Logs (Admin Activity and Data Access), Cloud SQL logs, the current IAM policy, service-account metadata and key-creation history, VPC Flow Logs, application and API logs, Entra sign-in logs, and the GitHub repository and commit history. Record hashes, collection times and collector for each item.
2. **Hunt for persistence — this is the step that most often gets missed.** The compromised account carried project-level Owner, so revoking one key proves nothing on its own. Check for: newly created service accounts; additional keys minted on any service account; new or modified IAM policy bindings; new firewall rules or authorised networks; new Cloud SQL users or altered database grants; modified Cloud Build triggers or CI service accounts; new VM instances, SSH keys or OS Login grants; scheduled jobs or Cloud Functions. Anything created since the key's first suspected use is suspect.
3. Establish the exposure window. The key was published to a **public GitHub repository four days ago**; making the repo private afterwards does not un-publish it — it must be assumed harvested by automated scanners within minutes. Reconcile the GitHub commit timestamp against the first anomalous authentication.
4. Enumerate every resource the key could reach and review all activity performed under that identity.
5. Investigate the Entra ID authentication attempt from the same IP using a former employee's credentials. Confirm that account is fully disabled, sessions and refresh tokens revoked, and check whether any other dormant accounts remain enabled. Treat the shared credential store (Drive/Sheets) as a plausible source of that credential.

**Owner:** Security/Incident Lead with Cloud Engineering support.

**Why:** I need trustworthy evidence before making wider changes, and I need to know whether the attacker still holds access through a second door. Establishing the timeline also determines whether the 30-day log retention window is sufficient to cover the full exposure period — if it is not, that limitation must be documented in the breach assessment rather than glossed over.

### 30–60 minutes — Blast radius, exfiltration analysis, regulatory clock

**Actions**

1. Reconstruct the **14 SELECT queries** in full: exact tables, columns, WHERE clauses, and row counts returned. Identify the specific patient records reached — symptom descriptions and provider notes are clinical PHI.
2. Analyse the application layer for exfiltration paths, since no Cloud Storage or BigQuery export was observed: review API access logs, response sizes and egress volume in VPC Flow Logs for the relevant window. Document what can and cannot be determined from available telemetry.
3. Pivot on all indicators — source IP, ASN, user agent, credential — across GCP and Azure to find other touched resources.
4. Rotate any additional credentials the compromised identity could have read (Secret Manager entries, database passwords, downstream API keys).
5. Reduce the replacement identity to least privilege and confirm no `roles/owner` bindings remain on any service account.
6. **Start the HIPAA breach-risk assessment and notify Privacy/Legal.** The regulatory clock runs from *discovery*, so this begins now, not after the technical investigation closes.
7. Notify the CEO within the policy's one-hour window with a factual status: what is confirmed, what is contained, what is unknown, and when the next update comes.

**Owner:** Security Lead, Cloud/Platform Lead, Privacy/Legal.

---

## 2. Handling the Stolen Laptop Report (03:30)

**Actions**

1. Open a **second incident** with its own record and its own responder. Do not fold it into the P0 — merged incidents produce merged, unreliable timelines.
2. **Revoke sessions and tokens first, before password resets.** Password resets alone do not terminate live OAuth/refresh tokens. Revoke Google Workspace sessions, Slack sessions, Entra ID refresh tokens (`Revoke-MgUserSignInSession` or equivalent), GCP credentials, and any cached CLI credentials.
3. Reset the user's credentials and revoke any SSH or API keys associated with them — noting that under the current environment those keys live in a shared Drive folder, so the exposure is not limited to this one user.
4. Determine what Harmoni PHI was **locally synced or cached**: Google Drive local sync contents, Slack local message cache and downloaded files, browser-stored credentials and sessions, any local database exports or notebooks.
5. Review authentication, Drive, Slack, GCP and application logs from the theft time forward for any activity from an unexpected location or device.
6. Attempt remote lock/wipe — and document whether it was possible. **Without MDM, it very likely was not.** That gap is itself a finding for the breach assessment and for Module 1 Risk 4.
7. File a police report and record the crime reference; preserve all access evidence for the HIPAA assessment.

**The FileVault and 4-digit PIN point.** FileVault was enabled, but two facts defeat it here. First, the laptop was **stolen open and unlocked**, so full-disk encryption was in its unlocked state and the data was live — encryption protects data at rest, and this data was not at rest. Second, the user protected the device with a **4-digit PIN**, giving a keyspace of 10,000; that is trivially brute-forceable and means even a subsequently-locked device offers little resistance. Encryption cannot be cited as a mitigating factor on these facts.

**Owner:** An IT/Security responder handles endpoint containment while the incident lead stays on the cloud compromise.

---

## 3. Prioritisation Between the Two Incidents

**P0 — service-account compromise.** Confirmed unauthorised access, confirmed queries against PHI, an active adversary with a credential that carried project-level Owner, and possible persistence across the environment. Ongoing, environment-wide, and confirmed.

**P1 (high, worked in parallel) — stolen laptop.** Serious and time-sensitive, but the exposure is bounded to one user's access, and the most effective containment step (session and token revocation) takes minutes and can be executed by a second responder immediately.

**Why this order:** severity is driven by scope and confirmation. The cloud incident is confirmed and unbounded; the laptop is bounded and, at this point, potential. I would not serialise them — I would assign a separate responder to the laptop within minutes of the Slack message so that containment of one never waits on the other, with both reporting into a single incident commander maintaining one master timeline. If evidence emerged that the two are linked (for example, post-theft activity from the same IP), I would merge them into a single P0.

---

## 4. HIPAA Breach Determination

### Incident A — Service-account compromise

**Regulatory standard.** HIPAA Breach Notification Rule, **45 CFR §§164.400–414**. The definition of "breach" and the four-factor risk assessment are at **§164.402**; business-associate notification to the covered entity is at **§164.410**; the burden of proof is at **§164.414(b)**. Ajaia is a business associate to Harmoni under a signed BAA.

**Burden of proof.** Under §164.402, an impermissible acquisition, access, use or disclosure of protected health information **is presumed to be a breach** unless the covered entity or business associate demonstrates a **low probability that the PHI has been compromised**, based on a documented risk assessment of at least four factors. Under §164.414(b), the burden of demonstrating that is on Ajaia. Ajaia cannot rely on "we cannot prove exfiltration" — the default is breach, and the burden runs against us.

**Four-factor assessment (§164.402(2))**

1. **Nature and extent of the PHI, including identifiers and likelihood of re-identification.** High concern. Patient symptom descriptions and provider notes are sensitive clinical narrative. Free-text provider notes routinely contain direct identifiers regardless of schema design, and narrative clinical detail carries high re-identification potential.
2. **The unauthorised person who used the PHI or to whom the disclosure was made.** The credential was used from an IP in a geography where Ajaia has no employees or contractors, following publication of the key to a public GitHub repository. This indicates an external, unknown, unaccountable party — the least favourable finding available on this factor. The same IP also attempted credential-based authentication against Entra ID using a former employee's account, indicating deliberate, targeted intrusion rather than incidental access.
3. **Whether the PHI was actually acquired or viewed.** **Yes.** Fourteen SELECT queries executed successfully against tables containing PHI and returned result sets to the unauthorised party. The regulatory test is *acquired or viewed* — not exported, not proven exfiltrated. A successful query that returns rows to an external actor is acquisition. Whether results were additionally moved through the application layer goes to the *extent* of the disclosure, not to whether it occurred.
4. **The extent to which the risk has been mitigated.** Limited. The key was created 90 days ago, never rotated, and had been public for four days before detection. Containment occurred only after the fact. There are no assurances of destruction or confidentiality from the recipient, which is the mitigation ordinarily contemplated by this factor.

**Recommendation.** This is a **reportable breach**. Three of four factors weigh clearly against a low-probability finding, and factor 3 is affirmatively established. I would not characterise this as merely "presumptive pending assessment" — the assessment can be run, but on these facts it does not reach a low probability of compromise, and manufacturing a contrary conclusion would not survive scrutiny.

**Timing.** Notify Harmoni under §164.410 **without unreasonable delay and in no case later than 60 calendar days after discovery**, and per whatever shorter period the BAA specifies. BAAs commonly contract this down to 5–10 days; the BAA governs and must be read before committing to a date. Discovery is the date the incident was known or should reasonably have been known — 2:00 AM Tuesday. Harmoni, as covered entity, then carries the §164.404/§164.406/§164.408 obligations to individuals, media (if 500+ residents of a State or jurisdiction) and HHS.

---

### Incident B — Stolen laptop

**Regulatory standard.** The same framework: **§164.402** for the breach definition and four-factor assessment, **§164.410** for BA-to-CE notification.

**The encryption safe harbour, and why it does not apply.** HIPAA's breach rule reaches only **unsecured PHI** — PHI not rendered unusable, unreadable or indecipherable to unauthorised persons through a technology specified in HHS guidance. For data at rest, that guidance points to encryption consistent with **NIST SP 800-111**. Two facts defeat the safe harbour here:

- The device was **stolen open and unlocked**. Full-disk encryption protects data *at rest*; a running, authenticated session means the volume is mounted and decrypted. The PHI was not in a protected state at the moment of loss.
- The device was secured with a **4-digit PIN** — a 10,000-value keyspace. Even had the device locked, that does not constitute a control rendering the data indecipherable to an unauthorised person.

So this is not a "lost encrypted laptop" case, which would ordinarily fall outside the breach definition. It is an unsecured-PHI case.

**Four-factor assessment**

1. **Nature and extent.** Determine precisely what Harmoni PHI was locally synced via Google Drive, cached in Slack, downloaded, or reachable through the live authenticated session. The employee works on Harmoni, so the working assumption is that clinical data was reachable.
2. **Unauthorised person.** Unknown. A coffee-shop theft is more likely opportunistic than targeted, which is the one factor that may weigh mildly in Ajaia's favour — but "probably a thief who wanted the hardware" is an assumption, not evidence, and cannot carry the burden alone.
3. **Actually acquired or viewed.** Reviewable. Examine post-theft authentication events, Drive and Slack activity, and cloud/application access. If logs show no activity after the theft and sessions were revoked promptly, this factor may weigh toward low probability. If any post-theft access appears, the determination is settled.
4. **Mitigation.** Turns on how quickly sessions and tokens were revoked relative to the theft, and on whether remote wipe was possible. **The absence of MDM means remote wipe likely was not available**, which materially weakens this factor and should be recorded honestly.

**Recommendation.** Treat as a **potential breach requiring completed documented assessment**. Unlike Incident A, the outcome here genuinely depends on the log review: a clean post-theft log record combined with prompt session revocation could support a documented low-probability determination. But that determination must be evidenced and written down under §164.414(b), not assumed. Absent that evidence, notify. I would also note for the record that the gap between theft and report (the laptop was stolen "earlier today" and reported at 03:30) is itself a factor, and points to a missing incident-reporting expectation in training.

---

## 5. Response to the CEO at 09:00

> **CEO:** "Can we just not tell the healthcare client? We don't know for sure data was taken, and the laptop was encrypted."

**My response:**

"I understand the instinct, and I want to give you a straight answer rather than a reassuring one.

On the database: an unauthorised party outside every geography we operate in used a service-account key — one that had been sitting in a public GitHub repository for four days — to run fourteen successful queries against tables holding Harmoni patient symptom descriptions and provider notes. Those queries returned data to them. Under HIPAA the test at 45 CFR §164.402 is whether PHI was *acquired or viewed*, not whether we can prove it was subsequently exported. A successful query returning rows to an unauthorised person is acquisition. So we are not in 'we don't know if data was taken' territory; we are in 'data was accessed, and we don't yet know the full extent of what was done with it' territory. Those are very different positions.

On the burden: HIPAA presumes a breach and puts the burden on **us** to demonstrate a low probability of compromise, documented, under §164.414(b). Uncertainty does not work in our favour — it works against us. We cannot decline to notify because the investigation is incomplete.

On the laptop: it was encrypted, but it was stolen open and unlocked, and the user's device passcode was a four-digit PIN. FileVault protects data at rest. The data was not at rest — it was in a live, authenticated session. And we have no MDM, so we could not remotely wipe it. That one is genuinely still open pending log review, and it may come out better than the database incident, but the encryption argument specifically does not hold.

On the decision: we have a signed BAA with Harmoni. §164.410 requires us to notify them without unreasonable delay and no later than 60 days from discovery, and our BAA very likely contracts that to a shorter window — Legal is confirming that this morning. Harmoni then has their own obligations to their patients and to HHS running off *our* notification date. If we sit on this and it surfaces later — through their audit, through a regulator, or through the data appearing somewhere — we have converted a security incident into a wilful-neglect finding and, more to the point, we have destroyed the client relationship and our ability to sell to any other regulated buyer. The reputational damage from disclosing well is far smaller than the damage from being caught disclosing late.

What I recommend: we notify Harmoni today, and we do it precisely. We tell them exactly what is confirmed, exactly what is still under investigation, what we have already contained, what we have changed, and when their next update is. Being early and precise, with a credible remediation plan already underway, is the strongest position available to us. I have a draft ready for you and Legal within the hour.

And I want to be clear about my own role: I am not able to recommend non-disclosure here, and if the decision goes the other way I will need that recorded."

---

# Module 3 — Compliance Governance & Policy

## Part A — Compliance Program Design

### 1. One unified program, or three?

**Recommendation.** Build **one integrated control framework**, not three parallel programs. Implement shared controls once, map each control to HIPAA, FERPA and SOC 2, then add framework-specific overlays only where obligations genuinely diverge. For a 20-person company with no existing policies, three separate programs would be unmaintainable and would produce contradictory evidence.

### Where the frameworks overlap

| Shared control area | HIPAA | FERPA | SOC 2 |
|---|---|---|---|
| Access control / least privilege | §164.308(a)(4) workforce access management; §164.312(a)(1) access control | §99.31(a)(1)(i)(A) legitimate educational interest | CC6.1, CC6.2, CC6.3 |
| Authentication and MFA | §164.312(d) person or entity authentication | Implied by "reasonable methods" | CC6.1 |
| Risk assessment | §164.308(a)(1)(ii)(A) risk analysis | Not prescribed | CC3.2, CC3.4 |
| Incident response | §164.308(a)(6) security incident procedures | Not prescribed | CC7.3, CC7.4, CC7.5 |
| Workforce training | §164.308(a)(5) security awareness and training | Reasonable methods for school-official access | CC1.4 |
| Audit logging and monitoring | §164.312(b) audit controls | Supports access limitation | CC7.2 |
| Vendor / third-party management | §164.308(b)(1) business associate contracts | §99.33 redisclosure limits | CC9.2 |
| Encryption | §164.312(a)(2)(iv), §164.312(e)(2)(ii) (both addressable) | Not prescribed | CC6.7 |
| Documented policies and evidence | §164.316 policies, procedures and documentation | Annual notification, §99.7 | CC1.x, CC2.x |
| Data retention and disposal | §164.316(b)(2)(i) six-year retention | Not prescribed | C1.1, C1.2 |

Implementing these once, with one owner and one evidence set per control, produces a single consistent operating model and one audit trail that serves all three.

### Where they genuinely diverge

**HIPAA** is a security-and-privacy regulation covering PHI/ePHI, enforced by HHS OCR with civil monetary penalties. It requires a formal risk analysis, minimum-necessary access (§164.502(b)), a documented breach-risk assessment (§164.402), business associate agreements (§164.308(b)(1), §164.504(e)), and breach notification within defined timeframes. It distinguishes *required* from *addressable* implementation specifications — addressable does not mean optional; it means implement, or document why not and implement an equivalent alternative.

**FERPA** is an education-privacy statute governing student education records, enforced by the U.S. Department of Education's Student Privacy Policy Office, whose ultimate sanction is withdrawal of federal funding from the *school*, not a fine against Ajaia. Three consequences follow: (a) obligations flow from the school's designation and contract, not directly from statute onto Ajaia; (b) **FERPA has no breach-notification requirement at all** — a critical asymmetry with HIPAA that Ajaia's incident-response policy must handle deliberately rather than by accident; and (c) improper redisclosure under §99.33 can result in the school being barred from disclosing to Ajaia for **five years** under §99.67(c) — which is an existential commercial risk, not merely a compliance one.

**SOC 2 Type I** is not a law at all. It is an **AICPA attestation report** on whether controls are *suitably designed* at a point in time against the selected Trust Services Criteria. It is not a certification, and no one is "SOC 2 certified" (a point that recurs in Module 4). Type I assesses design only; Type II assesses operating effectiveness over a period, which is what enterprise buyers ultimately ask for.

**The key structural difference:** HIPAA and SOC 2 largely define *what controls must exist*. FERPA primarily defines *who may access data and for what purpose*, and binds Ajaia through the school's designation. So FERPA obligations surface as data-flow and contractual constraints rather than as technical control requirements — which is exactly why they get missed by control-centric programs, and why the misclassification identified in Part C happened.

### Recommended operating model

**One control backbone → shared controls implemented once → framework-specific overlays → centralised evidence and gap tracking.**

Maintain a single **control-to-requirement matrix**:

| Control ID | Control | HIPAA ref | FERPA ref | SOC 2 TSC | Owner | Evidence | Frequency | Status | Due |
|---|---|---|---|---|---|---|---|---|---|

Sequencing for a 20-person company: (1) data inventory and flow mapping — you cannot control what you have not located, and this directly surfaces the shadow-AI PHI risk in Module 5; (2) the shared control backbone; (3) HIPAA overlay, since PHI carries the highest penalty exposure; (4) FERPA overlay, focused on data flows and contracts; (5) SOC 2 Type I readiness, which by then is largely evidence collection over controls that already exist. Assign a named owner per control. In a 20-person company that will be a small number of people wearing several hats — that is fine, provided it is documented and provided no one approves their own work.

---

## Part B — PHI and Student-Data Determinations

### 2. Memo to the CEO — Harmoni / Claude API

**To:** CEO
**From:** Information Security
**Subject:** Whether HIPAA applies to Harmoni's Claude API calls
**Recommendation:** Legal's interpretation is incorrect as stated. Treat the prompts as PHI.

**The claim.** Legal has advised engineering that "since we strip PII, HIPAA doesn't apply to the API calls," on the basis that prompts include patient symptoms and medication names but never patient names or dates of birth.

**Why that is not sufficient.** PHI is individually identifiable health information held or transmitted by a covered entity or business associate. Symptoms and medication names **are** health information — that part is not in question. The question is whether the information identifies the individual, or whether there is a **reasonable basis to believe it can be used to identify** the individual. Removing two identifiers does not answer that question.

**The de-identification standard (45 CFR §164.514).** HIPAA provides exactly two routes:

- **Safe Harbor — §164.514(b)(2).** Requires removal of **all eighteen** enumerated identifier categories, *and* that the entity has no actual knowledge that the remaining information could be used alone or in combination to identify an individual. The eighteen include names and dates, but also: geographic subdivisions smaller than a state, all elements of dates other than year (including admission and service dates), telephone and fax numbers, email addresses, SSNs, medical record numbers, health-plan beneficiary numbers, account numbers, certificate/licence numbers, vehicle and device identifiers, URLs, IP addresses, biometric identifiers, full-face photographs, and **any other unique identifying number, characteristic or code**. Stripping names and DOB satisfies two of eighteen.
- **Expert determination — §164.514(b)(1).** A qualified statistician documents that the re-identification risk is very small.

Ajaia has done neither.

**Why free-text clinical narrative fails Safe Harbor in practice.** Patient-facing symptom descriptions are unstructured natural language. Patients routinely embed identifiers in their own words — locations, dates, ages, employer, family relationships, rare conditions, treating clinician names. Safe Harbor requires removal of identifiers from the actual content, not from a schema. Redacting a `name` column while forwarding free text is not de-identification, and the "no actual knowledge" prong is difficult to satisfy once we know the content is unstructured narrative. Combinations of rare condition, medication and implied location can be re-identifying even with every enumerated identifier removed.

**The medical-translation context makes this worse, not better.** Translation requires full semantic content to be useful; aggressive redaction would degrade the product. That is a genuine tension, and it is a reason to get the contractual position right rather than a reason to argue the data is not PHI.

**BAA implications (§164.308(b)(1), §164.502(e), §164.504(e)).** If Anthropic creates, receives, maintains or transmits ePHI on Ajaia's behalf in providing this service, Anthropic is a business associate (Ajaia's subcontractor, given Ajaia is itself Harmoni's business associate) and a compliant BAA is required. Encryption in transit does not remove that obligation — the "conduit exception" is narrow and applies to transmission-only services such as ISPs and postal carriers, not to services that process and generate content from the data. **Action required:** confirm in writing whether a BAA is in place with Anthropic covering this use, and confirm the specific service tier and configuration it covers, since BAA coverage is typically tied to particular enterprise offerings rather than to consumer or default API access. Do not assume coverage.

**Recommendation**

1. Treat Harmoni prompts as PHI until a documented §164.514 de-identification is achieved.
2. Confirm and execute the appropriate BAA with Anthropic covering this specific service and configuration before further production use.
3. Apply minimum necessary (§164.502(b)) — send only the clinical content the translation requires.
4. Confirm contractual terms on retention, no training on inputs, subprocessors and deletion.
5. Document a HIPAA risk analysis for this data flow under §164.308(a)(1)(ii)(A).
6. Have Legal reconsider the "PII stripped" position in writing, so the record reflects the corrected analysis.

**Residual risk if we do not act:** unauthorised disclosure of PHI to a subcontractor without a BAA is an impermissible disclosure in its own right, independent of any security incident. That is a self-inflicted, entirely avoidable exposure.

---

### 3. Ethos / FERPA — student data to OpenAI's API

**Does it violate FERPA?** Not automatically — but on the facts as they stand today, I would not approve it.

FERPA restricts disclosure of **personally identifiable information from education records** without consent, unless an exception applies. Quiz responses and performance data generated by a school-provided learning product are education records. So the question is whether a valid exception covers the disclosure to OpenAI.

**Ajaia's obligation as a designated "school official" (34 CFR §99.31(a)(1)(i)(B)).** The exception permits disclosure to a contractor or consultant to whom the school has outsourced an institutional service or function, provided the party:

1. **performs a function the school would otherwise use its own employees to perform;**
2. **is under the direct control of the school with respect to the use and maintenance of education records;**
3. **is subject to §99.33(a) requirements governing use and redisclosure;** and
4. **has a legitimate educational interest** in the information accessed.

Two additional conditions are commonly overlooked and both apply here:

- **§99.7 annual notification.** The school-official exception only operates if Ethos has, in its FERPA annual notification, specified the criteria for who constitutes a school official and what constitutes a legitimate educational interest, **in terms that actually cover outside service providers**. If Ethos's notification does not do this, Ajaia's "designation" does not carry the exception. **This must be verified with Ethos in writing** — it is not something Ajaia can assume from the fact of being called a school official in a contract.
- **§99.31(a)(1)(ii) reasonable methods.** The school must use reasonable methods to ensure school officials access only records in which they have a legitimate educational interest. Physical or technological access controls are the expected mechanism.

**The specific problem with the OpenAI flow.** Ajaia's designation is not transitive. Ethos designated *Ajaia* as a school official. That does not automatically extend to Ajaia's own subprocessors. For the disclosure onward to OpenAI to be permissible, Ajaia must remain able to demonstrate that Ethos retains **direct control** over the use and maintenance of those records at OpenAI, and that OpenAI is bound by §99.33(a) redisclosure limits. A standard commercial API terms-of-service does not establish either. If OpenAI can use the data for any purpose of its own — including model improvement — direct control is broken and the exception fails.

**§99.33 and the five-year bar.** Under §99.33(a), a party receiving PII from education records may not redisclose it without consent, and may use it only for the purposes for which the disclosure was made. Under **§99.67(c)**, where a third party improperly rediscloses, the school may be prohibited from providing that party access to education records **for at least five years**. For Ajaia, a FERPA failure is therefore not primarily a fine — it is potential exclusion from the education market and immediate termination by Ethos.

**Required controls before I would approve**

1. **Verify** Ethos's §99.7 annual notification criteria cover outside service providers, and obtain the designation in writing.
2. **Data minimisation** — send only the minimum performance data the recommendation function requires. Strip direct identifiers; use pseudonymous internal IDs with the mapping held only by Ajaia and never transmitted.
3. **Contractual terms with OpenAI** confirming: use limited solely to providing the service; **no training or secondary use** on inputs or outputs; no redisclosure; defined retention and deletion; subprocessor disclosure and flow-down; and terms consistent with Ethos's direct control. Confirm which OpenAI product tier these terms attach to — default consumer/API terms and enterprise/zero-retention terms differ materially.
4. **Technical controls** — least privilege, encryption in transit, full request logging, and auditability sufficient for Ethos to exercise control.
5. **Retention and deletion** — defined periods with evidence of deletion on request or termination.
6. **Documented vendor assessment and FERPA basis** completed *before* production use.
7. **Ethos's informed agreement** to the data flow. Where a school's contract requires it, obtain written approval for the subprocessor.
8. **Incident handling** — note that FERPA imposes no breach-notification duty, so the obligation here is contractual. Ajaia's IR policy and the Ethos contract must define notification expressly, or a student-data incident will fall into a gap between a policy that keys on "confirmed breach" and a statute that requires nothing.

**Recommendation.** Do not send identifiable Ethos student data to the API until conditions 1–3 are demonstrably satisfied. If they cannot be met, de-identify to the point where the data is no longer PII from education records, or obtain written parental/eligible-student consent under §99.30.

---

## Part C — Policy Gap Analysis

### 4. Draft Incident Response Policy — gaps

| # | Gap | Requirement not met | Consequence | Remediation |
|---|---|---|---|---|
| 1 | Blanket "contain all incidents within 4 hours" | §164.308(a)(6)(ii) requires identifying, responding to, **mitigating** and **documenting** incidents; SOC 2 CC7.3/CC7.4 require evaluation and a response proportionate to the event | Responders rush containment, destroy volatile evidence, and miss scope. In Module 2, a rigid 4-hour containment clock would have driven key deletion before evidence preservation and before persistence hunting — destroying the very evidence needed for the §164.402 assessment | Replace with **severity-based SLAs** (P0/P1/P2/P3) covering time-to-acknowledge, time-to-contain and time-to-resolve, with explicit evidence-preservation gates that must complete before state-changing containment actions |
| 2 | Client notification only after a "confirmed breach" | §164.402 presumes breach absent a documented low-probability determination; §164.414(b) places the burden on Ajaia | "Confirmed" inverts the regulatory default. Ajaia would wait for certainty that HIPAA does not require and may never arrive, and would blow the notification window while investigating | Define **"discovery"** as the trigger, mandate the documented four-factor assessment, and require Privacy/Legal engagement at discovery rather than at confirmation |
| 3 | Blanket 96-hour client notification | §164.410 requires notice without unreasonable delay and **no later than 60 calendar days after discovery**, subject to the BAA — which commonly contracts to 5–10 days | 96 hours is simultaneously arbitrary and dangerous: it may **exceed** a stricter BAA term (contractual breach) while being presented internally as compliant | Make notification timing driven by **statute, BAA and client contract**, whichever is shortest, with Privacy/Legal approval. Maintain a per-client notification-obligation register |
| 4 | No FERPA notification path at all | FERPA imposes no breach-notification duty, so obligations arise only from the Ethos contract; §99.33 governs use and redisclosure | A student-data incident falls into a gap — no statutory trigger, and a policy that only speaks to "confirmed breach" | Add a client-obligation matrix covering HIPAA (statutory + BAA), FERPA (contractual), and state student-privacy and breach-notification laws |
| 5 | No evidence preservation or forensic procedure (explicitly absent) | §164.308(a)(6)(ii) requires documenting incidents and their outcomes; §164.316(b)(2)(i) requires six-year retention; SOC 2 CC7.3 requires evaluation to determine whether an event is an incident and its impact | No chain of custody; inability to prove scope, impact or breach determination. Directly undermines the §164.414(b) burden of proof | Mandate log export and hashing, snapshots, forensic images, timestamped action logs, named collectors, chain-of-custody records, and evidence retention aligned to the six-year documentation requirement |
| 6 | No severity classification | SOC 2 CC7.3 requires evaluation of security events to determine whether they constitute incidents | Inconsistent prioritisation. Module 2 required simultaneously ranking two live incidents with no policy basis for doing so | Define **P0–P3** with criteria based on data sensitivity, confirmation status, scope and regulatory trigger, plus explicit parallel-incident handling |
| 7 | No defined roles beyond "notify the CEO within 1 hour" | SOC 2 CC7.4 requires assigned responsibilities; §164.308(a)(2) requires an assigned security official | Unclear accountability during a live incident; single-threaded response. Module 2 needed at least two responders and a commander | Define Incident Commander, Technical Lead, Forensics, Privacy/Legal, Communications and Executive Sponsor, with named primaries, deputies and 24/7 contact paths |
| 8 | No eradication or recovery criteria | SOC 2 CC7.5 addresses recovery from identified incidents | Systems restored before the adversary is removed. Module 2's persistence risk is exactly this failure mode | Add explicit eradication (including persistence hunting), recovery, validation and return-to-service criteria, with sign-off required before closure |
| 9 | Post-incident review in 7 days, but no remediation tracking | §164.308(a)(6)(ii) requires documenting outcomes; §164.308(a)(8) requires periodic evaluation; SOC 2 expects corrective action and monitoring | Lessons are recorded and never actioned; the same root cause recurs | Track root cause, corrective actions, owners and due dates to closure in a register, with overdue items escalated |
| 10 | No breach-risk-assessment procedure | §164.402 four-factor assessment; §164.414(b) burden of proof | Assessments are ad hoc and undocumented, so a low-probability determination cannot be defended to OCR | Add a mandatory documented four-factor template with Privacy/Legal sign-off and retention |
| 11 | Scope says "all Ajaia systems and data" but no vendor/subprocessor incidents | §164.308(b)(1) and §164.410 obligations flow through subcontractors; SOC 2 CC9.2 | A breach at the medical-LLM vendor or an AI subprocessor has no defined path | Extend scope to third parties; require vendor notification SLAs in contract and define Ajaia's onward obligations |
| 12 | No incident-reporting expectation for employees | §164.308(a)(5)(ii)(A) security reminders; §164.308(a)(6)(i) requires reporting of suspected incidents | The Module 2 laptop was stolen "earlier today" and reported at 03:30 — hours of avoidable exposure | Define an explicit, blameless, 24/7 reporting duty with a target time, communicated in training |

### Draft Data Classification Policy — gaps

| # | Gap | Requirement not met | Consequence | Remediation |
|---|---|---|---|---|
| 1 | **Student education records classified as "Internal"** | §99.31(a)(1)(i)(A)–(B) limits access to school officials with a legitimate educational interest and requires direct school control; §99.31(a)(1)(ii) requires reasonable methods to enforce that limitation | See "Immediate regulatory risk" below | Reclassify identifiable education records to **Restricted** |
| 2 | Only three tiers; PHI sits at the same level as ordinary confidential business data | §164.312(a)(1) access control and §164.502(b) minimum necessary imply differentiated handling for ePHI | Client contracts and PHI receive identical treatment, so minimum-necessary cannot be enforced by classification | Add a fourth **Restricted / Regulated** tier for PHI, student PII, credentials and secrets |
| 3 | No handling procedures for any tier (explicitly absent) | §164.316(a) requires policies and procedures; §164.310(d)(1) device and media controls; SOC 2 C1.1, C1.2 | Labels with no rules change no behaviour. Employees cannot know that PHI must not go into an unapproved AI tool — which is Module 5's shadow-AI problem, caused here | Define per-tier rules for access, storage, transmission, sharing, third-party disclosure, AI-tool use, retention and disposal |
| 4 | Encryption required only for Confidential | §164.312(a)(2)(iv) and §164.312(e)(2)(ii) (addressable) | Student records, classified Internal, escape the encryption requirement entirely via the misclassification in gap 1 | Require encryption at rest and in transit for Confidential and Restricted; document addressable-specification decisions |
| 5 | No access mapping by classification | §164.308(a)(4) access management; SOC 2 CC6.1–CC6.3 | Classification does not drive entitlements, so it has no operational effect | Bind each tier to RBAC roles, need-to-know and review cadence (see Module 4 Part B) |
| 6 | No third-party or AI-tool sharing rules | §164.308(b)(1) BAAs; §99.33 redisclosure; SOC 2 CC9.2 | PHI and student data can be sent to any vendor or AI service without review — the Module 3 Part B and Module 5 scenarios | Require security/privacy review, BAA where applicable, FERPA analysis and subprocessor review before any Confidential or Restricted data leaves Ajaia |
| 7 | No retention or disposal rules | §164.310(d)(2)(i) disposal; §164.316(b)(2)(i) six-year documentation retention; SOC 2 C1.2 | Regulated data persists indefinitely, increasing breach scope | Set retention periods and secure-disposal requirements per tier |
| 8 | No data owners or review cadence | §164.308(a)(2) assigned security responsibility; SOC 2 CC1.3 | Classifications drift and are never corrected — how student records came to be "Internal" and stayed there | Assign owners per data type; annual and event-driven review |
| 9 | No labelling or discovery mechanism | §164.308(a)(1)(ii)(A) risk analysis presupposes knowing where ePHI resides | Ajaia cannot locate its regulated data, so it cannot protect or produce it | Data inventory and flow mapping; labelling in Workspace and cloud storage; DLP where available |

### Immediate regulatory risk

**The classification of student education records as "Internal."**

**Why this specific decision.** It fails in two directions simultaneously, and its effects compound.

*Access.* "Internal" ordinarily means accessible to all employees. Under §99.31(a)(1)(i)(A) and §99.31(a)(1)(ii), access to education records must be limited to school officials with a **legitimate educational interest**, and the school must use reasonable methods to enforce that limit. Combined with the current access model — where every employee has Editor on all GCP projects and Member on every GitHub repo — the classification does not merely permit over-broad access; it *authorises* it as policy. Twenty employees, most with no connection to Ethos, are entitled by written policy to student records.

*Encryption.* The policy requires encryption only for Confidential. Because student records are Internal, FERPA-protected data is the **only regulated data at Ajaia with no encryption requirement** — an outcome produced purely by a labelling error.

**Consequences.** Ethos's ability to rely on the school-official exception depends on Ajaia limiting access to legitimate educational interest. A written policy granting company-wide access is direct evidence that this condition is not met. If an employee with no Ethos role accesses those records, that is an unauthorised disclosure. Under §99.33 and §99.67(c), improper use or redisclosure can result in Ethos being barred from disclosing to Ajaia **for at least five years** — commercially terminal for that line of business. It also disqualifies Ajaia in any K-12 procurement due diligence, and it is a straightforward SOC 2 CC6.1/CC6.3 design deficiency.

**Immediate remediation**

1. Reclassify identifiable Ethos education records as **Restricted** today.
2. Restrict access to the named individuals with a documented legitimate educational interest; revoke everyone else.
3. Apply encryption at rest and in transit.
4. Define handling, sharing, retention and disposal rules for the Restricted tier.
5. Require documented FERPA review before disclosure to any vendor or AI service, including the OpenAI flow in Part B.
6. Review access logs for the period the misclassification was in effect and assess whether any inappropriate access already occurred.

---

# Module 4 — Vendor Risk, IAM & IT Operations

## Part A — Vendor Security Assessment

### 1. Medical LLM vendor — gaps, red flags and questions

**Decision: do not approve for production.** The vendor may prove suitable, but nothing supplied constitutes evidence, and the system would process Harmoni PHI.

**The threshold problem: "We are SOC 2 Type II certified."** There is no such thing as SOC 2 certification. SOC 2 is an **AICPA attestation report** issued by a licensed CPA firm, not a certificate. A vendor selling to healthcare that describes itself as "SOC 2 certified" and supplies no report is either using the term loosely or has never read one. Either way it recalibrates how much of the rest of the summary I take at face value — every remaining claim is unevidenced assertion.

| # | Red flag / gap | Why it matters | Questions and evidence required |
|---|---|---|---|
| 1 | "SOC 2 Type II certified," no report | A claim is not evidence. Scope, period, auditor, subservice organisations and exceptions are all unknown — and SOC 2 is not a certification | Provide the full Type II report under NDA, with a bridge letter if the period ended >3 months ago. Which TSC were in scope (Security only, or Confidentiality/Availability/Privacy)? Which systems were in scope? Which CPA firm? Were there qualified opinions or exceptions, and what is the remediation status? What are the CUECs we must implement? |
| 2 | BAA only promised, not provided | A vendor processing ePHI on our behalf is a business associate/subcontractor; a compliant BAA is required under §164.308(b)(1) and §164.504(e) **before** any PHI is transmitted | Provide the proposed BAA now for Legal and Security review. Does it address permitted uses, safeguards, subcontractor flow-down, breach notification timing, and return/destruction on termination? |
| 3 | 90-day logging of prompts **and outputs** | For a medical LLM, prompts and outputs *are* PHI. This is a 90-day PHI retention we did not ask for, held for debugging convenience, expanding breach blast radius | Can retention be reduced or disabled for Harmoni? Where are logs stored and are they encrypted with what key control? Which vendor personnel can read them, and is that access logged? What is the deletion process and can you evidence deletion? Are logs included in the SOC 2 scope? |
| 4 | "We do not use customer data for model training" | Narrow wording. Silent on evaluation, fine-tuning, abuse monitoring, human review, QA, and product analytics — all of which are secondary uses of PHI | Contractually prohibit use of prompts, outputs, embeddings and metadata for training, fine-tuning, evaluation, benchmarking or any purpose beyond providing the service. Is any human review performed, by whom, and under what safeguards? |
| 5 | Penetration test from **2023**, conducted **internally** | Two independent failures: stale (2–3 years old for a startup that has certainly changed materially) and not independent (self-assessment is not assurance) | Provide the most recent **independent third-party** penetration test executive summary: date, scope, methodology, tester, critical/high findings and evidence of closure with retest. What is your ongoing testing cadence? |
| 6 | "AES-256 at rest, TLS 1.2 in transit" | Algorithm names are not a key-management programme. TLS 1.2 is acceptable but dated; TLS 1.3 has been standard for years | Describe key management: KMS/HSM, ownership, rotation cadence, separation of duties, whether customer-managed keys are supported. Is TLS 1.3 supported and is 1.2 the floor or the default? How are internal service-to-service communications protected? How are application secrets managed? |
| 7 | "AWS us-east-1" and nothing else | A region name answers nothing about resilience, backup, DR or residency — and single-region means a regional failure is an availability incident for Harmoni | Describe HA architecture, backup frequency and retention, RPO/RTO, DR testing and last test date, replication, and whether PHI ever leaves the stated region (including logs, backups, support access and monitoring) |
| 8 | **Subprocessors not disclosed at all** | A fine-tuned medical LLM startup is very likely built on a foundation-model provider and various SaaS. Those parties may receive PHI. Undisclosed subprocessors break the BAA chain and our own disclosure obligations | Provide a complete subprocessor list with function, location and data accessed. Which foundation model underlies the fine-tune, and what are that provider's terms? Do you hold BAAs with each subprocessor handling PHI? What is your notification process for adding one, and can we object? |
| 9 | No incident/breach notification terms | We need rapid notice to meet §164.410 and our own BAA with Harmoni; their delay becomes our violation | What is your security-incident notification SLA in hours? What triggers notification? What information is provided? Will you support our forensic investigation and provide logs? Have you had a security incident or breach in the last 24 months? |
| 10 | No access-control detail | Vendor staff may hold broad access to PHI | Describe SSO/MFA, RBAC, privileged access management, JIT elevation, access reviews, background checks, security training, and offboarding. Can any employee access customer prompt data, and under what approval and logging? |
| 11 | No customer-facing audit logging | We need traceability of PHI access for our own §164.312(b) obligations and for incident response | What logs are available to us? Can we export them to our SIEM? What is the retention? Are administrative actions and support access to our data logged and visible to us? |
| 12 | No vulnerability management | A single 2023 pen test is not a programme | Describe scanning cadence (infrastructure, application, dependency, container), patch SLAs by severity, remediation tracking, and secure SDLC/code review practices |
| 13 | No deletion or termination process | PHI may persist after contract end, in backups indefinitely | How is data returned or destroyed on termination? Timeframe? Does it include backups and logs? Do you provide a certificate of destruction? |
| 14 | No AI-specific security controls | A fine-tuned medical LLM introduces prompt injection, training-data leakage, cross-tenant leakage, model inversion and unsafe clinical output — none of which SOC 2 addresses | Describe prompt-injection defences; tenant isolation at inference; whether our data influences any shared model artifact; guardrails and output filtering; red-teaming and clinical evaluation; hallucination monitoring; model versioning and change notification. What clinical validation exists, and what is the intended-use statement? |
| 15 | Clinical/regulatory posture unaddressed | A medical LLM may implicate FDA considerations depending on its claims, and creates clinical liability exposure for Harmoni | What are the documented intended use and limitations? Have you assessed device/CDS classification with counsel? What indemnities do you offer for clinical error? |
| 16 | No corporate or viability due diligence | A startup holding 90 days of PHI logs presents a real continuity risk; acquisition or failure creates data-disposition questions | Funding stage, runway, headcount, insurance (cyber and E&O with limits), and what happens to customer data on acquisition or wind-down |

**Regulatory basis.** HHS guidance on cloud computing confirms that where a service provider creates, receives, maintains or transmits ePHI on behalf of a covered entity or business associate, it is a business associate, a compliant BAA is required, and the arrangement must be covered by risk analysis and risk management under §164.308(a)(1). The BAA and SLA should address safeguards, availability, retention, return or destruction, and permitted uses.

**Conditions for approval**

1. Full SOC 2 Type II report reviewed, exceptions assessed, CUECs implemented on our side.
2. Executed BAA acceptable to Legal, with subprocessor flow-down and a defined breach-notification SLA.
3. Prompt/output retention reduced, or contractually constrained with access controls and evidenced deletion.
4. Written prohibition on training, fine-tuning, evaluation and secondary use.
5. Current independent penetration test with findings closed.
6. Full subprocessor disclosure, including the underlying foundation model, with BAAs in place.
7. Customer-accessible audit logging and export.
8. AI-specific control evidence, including tenant isolation and prompt-injection defences.
9. Documented residual risk formally accepted by the named business owner, not by Security.
10. Pilot restricted to synthetic or de-identified data until 1–9 are satisfied.

---

### 2. "We've already built the integration. We just need your sign-off."

**Position.** Sunk engineering effort changes the delivery cost of saying no. It does not change the risk, and it is not a reason to approve. If prior implementation could compel approval, the review process would be decorative — and everyone would learn to build first.

**Immediate actions**

1. **Block production and block PHI.** The integration does not go live and no real Harmoni data flows through it until review completes. This is not negotiable, because sending PHI to a subcontractor without a BAA is an impermissible disclosure under §164.502 in its own right — a violation on day one, independent of any vendor security failing.
2. **Enable the team to keep moving.** Approve testing immediately with synthetic or properly de-identified data so engineering is not idle while the assessment runs.
3. **Run an expedited assessment,** not a slow one. Commit to a specific turnaround — I would target 5 working days for the initial gap list — and hold myself to it.
4. **Publish a blocker list** distinguishing hard blockers (BAA, subprocessor disclosure, SOC 2 report) from conditions that can be remediated in parallel, each with an owner and a date.
5. **Escalate to the CEO with options,** not with a veto: approve with conditions, delay pending specific items, or reject and identify alternatives — with the risk of each stated plainly.
6. **Check what has already happened.** Has any real PHI been sent during development? If so, that is an incident to be assessed under Module 2's framework, and I need to know now rather than later.

**What I would say to the engineering lead**

> "I want this shipped, and I'm not going to slow-walk it. But I can't sign off on something that would put PHI with a subcontractor before we have a BAA — that's a violation the day we turn it on, regardless of how good their security is. Here's what I'll do: you'll have my full blocker list within five working days, split into hard blockers and parallel items, with owners. In the meantime, keep testing with synthetic data so you're not blocked. Most of what's missing is paperwork the vendor should be able to produce quickly — if they can't produce a SOC 2 report or a BAA, that tells us something important about whether we want them near patient data at all."

**Process fix.** The real failure is that the integration reached completion before Security saw the vendor. I would introduce a lightweight, fast intake at design time — a short form, a two-day SLA for a first response — so that review is cheap and early rather than expensive and late. If review is slow, teams will keep routing around it, and they will be right to.

---

## Part B — Access Control Redesign

### 3. Ajaia RBAC model

**Current state.** Every employee: admin on Google Workspace, Editor on all GCP projects, Member on every GitHub repo. No SSO. MFA on Google Workspace only. Three GitHub users on **personal accounts that are also connected to side projects and a previous employer's organisation.**

**Why the personal GitHub accounts are the most urgent item here.** These accounts are outside Ajaia's control entirely: Ajaia cannot enforce MFA on them, cannot audit them, cannot revoke them at offboarding, and cannot prevent the same credential from being used across a previous employer's org and personal side projects. Client source code — including, per Module 5, code the team is already pasting into unapproved AI tools — sits behind a credential Ajaia does not own. Offboarding one of these three people today would leave their access intact. This is remediated in week one, not in the quarterly plan.

**Design principles.** Least privilege; company-managed identities only; SSO with MFA everywhere; no standing privilege at Tier 0; time-bound elevation; access granted through groups, never individually; every grant reviewable.

### Access tiers

| Tier | Description | Examples | Controls |
|---|---|---|---|
| **Tier 0 — Privileged** | Administrative control over identity, production or security | GCP Organisation/Project admin, Workspace Super Admin, Entra Global Admin, AKS cluster admin, GitHub org owner | Smallest possible group (2–3 named people). No standing access — PIM/JIT with approval and expiry. Phishing-resistant MFA. Full session logging. Separate admin identity from daily-use account. Quarterly recertification |
| **Tier 1 — Regulated & Production** | Access to PHI, student records, secrets, production systems | Harmoni Cloud SQL, Ethos data, Secret Manager, Key Vault, production AKS namespaces | Named individual approval with documented business need. Minimum necessary (§164.502(b)) and legitimate educational interest (§99.31). Compliant device required via Conditional Access. MFA. Access logged. Quarterly recertification |
| **Tier 2 — Standard business** | Day-to-day work systems and non-production development | Workspace, Slack, M365, dev/staging GCP projects, assigned repos | Role-based default entitlements. SSO + MFA. Annual recertification |
| **Tier 3 — Low risk** | Public or non-sensitive resources | Public docs, marketing site, public repos | Standard authentication |

### Role matrix

| Role | Google Workspace | GCP | GitHub | Azure / Entra / AKS | Regulated data | Privileged access |
|---|---|---|---|---|---|---|
| **Executive** | Standard user; no admin | Viewer on billing and summary dashboards only | No repo access by default | Standard user; no admin | Business and client metadata only; no PHI or student records by default | None |
| **Engineering** | Standard user | Developer roles on assigned projects only (`roles/run.developer`, `roles/cloudsql.client`); no Editor, no Owner | Write on assigned repos via team membership; no org admin; protected `main` with required review | Namespace-scoped RBAC on `dev`; no standing `cluster-admin` | None by default; Tier 1 by named exception | Time-bound PIM elevation with approval |
| **Engineering Lead** | Standard user | Developer plus limited approver rights on owned projects | Maintainer on owned repos; no org owner | Namespace admin on owned namespaces | By exception with documented need | PIM elevation; approver for team requests |
| **Security / IT** | Delegated admin roles scoped to function (user management, security settings); not Super Admin for daily use | Security Admin, Logging Viewer, Security Reviewer; IAM Admin via PIM only | Security and infrastructure repos; secret-scanning and org security settings | Security Reader, Defender, Sentinel; Global Admin via PIM only | Need-to-know for investigation and compliance, logged and justified | Tier 0 via PIM, approved and fully logged |
| **AI / Data** | Standard user | Access to approved AI/data projects and specific datasets only | Assigned AI/data repos | Workload-specific access | Minimum necessary only, with documented approval; explicit approval required before any regulated data reaches an AI tool | None standing |
| **Contractor** | Restricted account with expiry date set at creation | Named resources on one project only; time-bound | Specific repos only; outside-collaborator with expiry | Assigned namespace only if required | Prohibited unless explicitly approved with a BAA/contract in place | None |

### System-specific remediation

**Google Workspace.** Remove admin rights from all employees. Retain **exactly two Super Admins** (a primary and one backup — never zero, and never twenty), on separate dedicated admin accounts with hardware-key MFA, with a documented break-glass account held offline. Create delegated admin roles for routine IT tasks. Enforce MFA org-wide. Company-managed accounts only.

**GCP.** Remove Editor from all users. Remove `roles/owner` from service accounts. Grant via Entra-synced groups mapped to project-scoped roles. Per-workload service accounts with narrow roles. Workload Identity Federation to eliminate downloadable keys. Organisation policy constraints to block service-account key creation and public IP assignment. IAM Recommender to drive right-sizing. PIM/JIT for admin.

**GitHub.** **Immediately** offboard the three personal accounts: transfer any owned resources, revoke their access, and re-onboard those users on company-managed accounts. Enforce SAML SSO with SCIM provisioning against Entra so access is centrally granted and automatically revoked. Team-based repo access; no individual grants. Restrict org-owner to two people. Protected branches with required review. Secret scanning with push protection. Disable forking of private repos. Audit-log streaming to the SIEM.

**Azure / Entra / AKS.** Entra as authoritative IdP with Conditional Access (compliant device required for Tier 1). Remove standing `cluster-admin`; Azure RBAC for Kubernetes with namespace-scoped roles. PIM for all privileged roles. Disable and fully deprovision former-employee accounts — the Module 2 incident showed an attacker attempting exactly one of these.

### Lifecycle controls

**Joiner.** Access provisioned from a role template on the first day, via group membership only. Company-managed identity on every system. Manager approval recorded. Any Tier 1 access separately justified and approved.

**Mover.** Role change triggers a full entitlement review. **Old access is removed, not merely supplemented** — accumulated privilege from prior roles is the most common source of over-entitlement in small companies.

**Leaver.** Same-day: disable identity in Entra (which cascades via SSO), revoke all sessions and refresh tokens, revoke SSH and API keys, transfer data ownership, rotate any shared credentials the person could access. Account fully deprovisioned, not merely disabled, after a defined retention period.

**Recertification.** Quarterly for Tier 0 and Tier 1, annually for Tier 2, with manager attestation. Automatic expiry on contractor accounts. Monthly review of privileged-role assignments and service-account key inventory (target: zero).

**Why this model.** The current environment grants nearly everyone the ability to compromise everything, which is why the Module 2 incident had unbounded blast radius. This redesign removes standing privilege, makes access reviewable and revocable from one place, fixes offboarding, and brings Ajaia into line with §164.308(a)(3)–(4), §164.312(a)(1), §99.31(a)(1) and SOC 2 CC6.1–CC6.3.

---

# Module 5 — AI-Native Security & Operations

## Part A — My AI Workflow

### Workflow 1 — Vulnerability analysis and triage

**Tool and model:** Claude (Sonnet tier) alongside my own Python vulnerability scanner and NVD data.

**Input:** Sanitised scan output — detected service and version, CVE identifiers, port and configuration context, asset criticality and network exposure. No hostnames, internal IPs, credentials or client identifiers.

**Process:** I provide asset context, the CVE evidence and environmental constraints, with a fixed output schema. I require the model to separate **confirmed facts, assumptions, and recommendations**, and to flag anything it cannot verify from the input rather than filling the gap. I then challenge its severity reasoning against the actual environment — a CVSS 9.8 on an internal-only service behind authentication is not the same risk as a 7.5 on an internet-facing endpoint, and base scores routinely mislead if taken at face value.

**Output:** Prioritised remediation list with environmental context, exploitability assessment, remediation steps and post-fix validation checks.

**What I do not trust it to do:** decide that a vulnerability is or is not exploitable in my environment; assign final severity; or trigger any remediation action. It does not have network context it has not been given, and CVSS base scores are not risk.

**Validation:** I verify every CVE ID, affected version range and mitigation against **NVD and the vendor advisory**, and against the raw scanner evidence. Any CVE I cannot independently confirm is discarded — hallucinated or misattributed CVE identifiers are a known failure mode and I check for it every time.

**Time saved:** roughly 30–45 minutes down to 10–15 for a moderate scan. The saving is in synthesis and drafting, not in verification, which stays manual.

---

### Workflow 2 — Log analysis and incident timeline reconstruction

**Tool and model:** Claude (Opus tier, where deeper multi-source correlation justifies it) alongside Splunk, Windows Security logs and Sysmon.

**Input:** Sanitised event records — timestamps, Event IDs, process-creation events, PowerShell activity, authentication events, network indicators. Usernames pseudonymised; no client identifiers; no PHI or student data under any circumstances.

**Process:** I ask for a chronological reconstruction, correlation of related events across sources, mapping of observed behaviour to **MITRE ATT&CK** techniques, and a set of competing investigative hypotheses rather than a single conclusion. My prompt explicitly instructs it not to infer events that are not in the data and to label every uncertainty. Asking for alternatives rather than an answer is deliberate: a single confident narrative is exactly what produces tunnel vision in an investigation.

**Output:** Timeline, correlated event clusters, ATT&CK mapping, ranked hypotheses, and the specific Splunk searches that would confirm or refute each.

**What I do not trust it to do:** declare activity malicious or benign; close an alert; take containment action; or determine incident scope. It sees the window I gave it and nothing else — absence of evidence in that window is not evidence of absence, and the model will not reliably make that distinction unless forced to.

**Validation:** I return to the raw logs and run the suggested searches myself. Every claim that would inform a decision is confirmed against primary telemetry before it goes into an incident record.

**Time saved:** roughly 30 minutes of manual correlation down to 10–15 for a focused investigation. On a live P0 like Module 2 I would use it for timeline structuring while doing containment decisions myself.

---

### Workflow 3 — Security documentation and incident reporting

**Tool and model:** Claude (Sonnet tier) for drafting and restructuring already-verified content.

**Input:** Sanitised, already-validated investigation notes — established timeline, confirmed impact, evidence references, remediation decisions I have already made. The facts are settled before the model sees them.

**Process:** I supply a fixed structure (executive summary → timeline → impact → evidence → remediation → lessons learned), specify the audience and the required register, and instruct the model explicitly **not to fill factual gaps** — where information is missing it must mark it as missing rather than produce plausible filler. I then produce audience-specific versions: a technical account for engineering, a decision-focused summary for the CEO.

**Output:** Structured incident reports, remediation plans, policy drafts, risk-register entries and client communications.

**What I do not trust it to do:** make the breach determination; interpret a regulatory requirement; accept residual risk; or decide what a client is told. In Module 2 terms, it can help me structure the HIPAA four-factor write-up, but the four-factor *conclusion* is mine and carries my name.

**Validation:** I read the draft against the original evidence line by line and remove anything unsupported, overstated or ambiguous. I check every regulatory citation against the primary source — CFR sections are exactly the kind of specific-looking detail that models get subtly wrong, and a wrong citation in a breach assessment is worse than no citation.

**Time saved:** a 30–40 minute first draft down to about 10–15 minutes. Review time is unchanged, and deliberately so.

---

### My operating principle

**AI proposes → I challenge → primary evidence verifies → I decide.**

I select model tier by task: faster models for structured drafting and routine analysis, stronger reasoning models where genuine multi-source correlation justifies the cost. I structure prompts with explicit context, constraints, evidence boundaries and required output format, and I ask for alternatives and disconfirming evidence rather than a single answer.

Three rules I hold to without exception: **no PHI, student records, credentials, client-identifying data or proprietary source code goes into any AI tool that is not contractually approved for that data class**; **any output that would inform a security or regulatory decision is verified against primary evidence**; and **accountability does not delegate** — if a report goes out under my name, I own every claim in it regardless of what drafted it.

---

## Part B — AI Risk & Governance

### 2. AI risk register

**Why a separate register.** LLM usage creates failure modes a generic IT risk register does not model: data disclosure through prompts, non-deterministic and confidently wrong output, prompt injection as a novel attack surface, model-behaviour drift, opaque vendor data handling, and agentic tools that can take real actions. These are structurally different from "unpatched server."

**Current shadow-AI position.** Nine AI vendors are being paid for; three are approved. The six unapproved are **ChatGPT Plus, Midjourney, Cursor, Jasper, Otter.ai, and a medical transcription API startup.** Two of those six require immediate attention on the facts given, and they are not the obvious ones:

- **The medical transcription API startup** is, by function, a service that would process clinical audio or text. Given Ajaia's Harmoni relationship, the probability that PHI is flowing to an unassessed vendor with no BAA is high. This is potentially an active, ongoing impermissible disclosure — not a policy violation to be handled at the next review, but something to investigate today.
- **Otter.ai** records and transcribes meetings. Meetings at Ajaia discuss Harmoni PHI, Ethos student data and client confidential material. Transcripts are stored by the vendor, often with sharing and retention defaults that are not conservative.

| # | AI / LLM risk | L | I | Current control | Recommended mitigation |
|---|---|---|---|---|---|
| 1 | **Developer pastes client source code into ChatGPT to debug integrations** (the required scenario) | H | H | None effective. ChatGPT Plus is not approved but is expensed; no DLP, no enforcement, no detection until expense review | Treat as a data-handling incident, not a policy footnote. Stop the practice today; establish what code was submitted, over what period, and whether it contained secrets, PHI, student data or client-proprietary logic; rotate any credentials found; assess client contractual disclosure obligations; migrate the developer to GitHub Copilot (already approved and licensed for exactly this use); implement DLP and browser controls; brief the team without singling the individual out |
| 2 | **PHI sent to an unapproved medical transcription API with no BAA** | H | H | None. The vendor was discovered through expense reports | Immediate investigation: what data, whose, for how long. If PHI is involved this is an impermissible disclosure under §164.502 requiring assessment under §164.402 and likely notification to Harmoni. Suspend use; demand deletion evidence; either onboard properly with a BAA and full vendor assessment or terminate |
| 3 | **Meeting transcription (Otter.ai) capturing PHI, student data and client confidential material** | H | H | None. Unapproved and unassessed | Suspend use pending assessment. Determine what has been recorded and retained, and who it was shared with. Assess against HIPAA and the Ethos contract. If retained, require deletion evidence. Any approved future tool must have a BAA, disable auto-join, and be prohibited from meetings involving regulated data |
| 4 | **Hallucinated AI output drives an incorrect security or compliance decision** | M | H | Informal human review only | Mandatory verification against primary sources for any AI-assisted output informing a security, regulatory or client decision. Prohibit AI-generated regulatory citations without source verification. Document, in incident and compliance records, where AI assisted and what was verified |
| 5 | **Prompt injection via untrusted content manipulates an AI workflow** | M | H | None. No AI-specific controls exist | Separate trusted instructions from untrusted content in all prompts and product code; treat all model output as untrusted input to downstream systems; validate and sanitise before any output triggers an action; least-privilege scoping of any tool the model can invoke; sandbox and human approval for consequential actions. Applies to Ajaia's own AI products, not only internal use |
| 6 | **Vendor retains prompts, or uses them for training or secondary purposes** | M | H | Approved-tool list exists but vendor terms are not centrally reviewed; tier and configuration are unverified | Central review of retention, training, human review, subprocessors and deletion terms for every approved tool. Contractually prohibit secondary use where regulated data is involved. Verify the specific product tier — enterprise/zero-retention terms differ materially from default terms, and paying for a consumer plan does not get you enterprise terms. Maintain a register mapping each tool to its data-handling terms |
| 7 | **Shadow AI adoption across the workforce** | H | M/H | Discovered only via expense reports — i.e. after the fact, and only for tools with a corporate card | Approved-tool catalogue with a genuinely fast approval path; monthly SaaS and expense review; DLP/CASB and browser controls; enterprise-tenant enforcement where available. Note that expense review misses free tiers entirely, which is where most shadow AI actually lives |
| 8 | **Over-privileged AI agents and coding assistants taking unintended actions** | M | H | None. No agent privilege model | Scoped, least-privilege service identities for every agent; no standing production or regulated-data access; human approval gates for consequential actions; rate limiting; full audit logging of agent actions; sandboxed execution. Especially relevant to Cursor, which can execute and modify code |
| 9 | **Training-data or cross-tenant leakage from a fine-tuned vendor model** | L/M | H | None. The Module 4 vendor has disclosed no controls | Require tenant-isolation evidence, confirmation that customer data does not influence shared model artifacts, and red-team/evaluation results before any PHI reaches a fine-tuned model |
| 10 | **Client or regulatory restrictions on AI processing breached** | M | H | Not assessed against Harmoni's BAA or Ethos's contract | Review both contracts for AI-specific restrictions, consent requirements and notification duties. Some healthcare and education clients prohibit AI processing outright or require prior written approval. Confirm before assuming permission |

**Risk treatment.** Every entry gets an owner, a review date, a mitigation status and a residual rating. Any residual High involving PHI, student records, client code or autonomous action requires documented acceptance by the business owner — not by Security, and not by default.

### The developer scenario, addressed directly

The developer's position is "it's fine, OpenAI doesn't train on API inputs." Three problems with that.

**First, the factual premise doesn't match what happened.** The statement is about the **API**. The developer used **ChatGPT Plus**, a consumer product with different terms, different retention and — historically — settings-dependent handling of conversation data. Applying API terms to a consumer subscription is a category error, and it is the single most common way well-intentioned engineers get this wrong.

**Second, training is not the risk that matters here.** Even accepting the premise entirely, the disclosure already occurred. Client source code left Ajaia's control and went to a third party with no contract, no security review, no confidentiality commitment and no deletion guarantee. Whether it is subsequently used for training is a secondary question about what happens to data that should never have been sent. Client agreements almost certainly restrict disclosure of client code to third parties regardless of what those third parties do with it.

**Third, the residual exposures are concrete.** Source code frequently contains embedded credentials, API keys, internal endpoints, database schemas, business logic and — in Ajaia's case, given the integration work described — potentially PHI or student data in test fixtures and sample payloads.

**My response.** Stop the practice immediately. Establish scope: what was submitted, over what period, and whether it contained secrets, regulated data or client-proprietary logic. Rotate anything exposed. Assess client contractual disclosure obligations and whether notification is owed. Move the developer to **GitHub Copilot**, which Ajaia already licenses for engineering and which exists precisely for this use case — the tool gap was Ajaia's failure, not the developer's. Document as a data-handling incident. Brief the team on the consumer-versus-enterprise-terms distinction, which is genuinely non-obvious, without naming the individual.

I would not treat this as misconduct. A developer trying to debug an integration reached for the best available tool. That the best available tool was unapproved reflects a governance gap, not bad faith — and if the response is punitive, the next person simply will not tell me.

---

### 3. AI tool governance framework

**Governance principle.** Enable fast AI adoption, with controls scaling to the sensitivity of the data and the autonomy of the tool. Ajaia builds AI products and expects every employee to use AI in their workflow — a restrictive framework would be ignored, and ignored controls are worse than no controls because they produce false assurance.

### Approval process

1. **Request** — a short form (target: under 10 minutes to complete): tool, business purpose, data types involved, whether it can take actions or access systems, integrations, and which existing approved tool was considered first.
2. **Triage** — Security assigns a risk tier within **1 business day**.
3. **Review** — proportionate to tier. Low: same-day approval. Medium: vendor and data-handling review, target 3 business days. High: full assessment (the Module 4 questionnaire), BAA/contract review, Privacy and Legal sign-off, target 10 business days.
4. **Decision** — approve, approve with conditions, or reject, with reasons given in writing.
5. **Register** — approved tools enter a central **AI inventory** with owner, permitted data classes, prohibited uses, configuration requirements, contract terms and review date.
6. **Periodic re-review** — annually, or on any material change to the vendor's terms, model or subprocessors.

**Why speed is a control, not a courtesy.** Ajaia currently discovers AI usage through expense reports — months after the fact, and only for tools someone put on a card. The reason people route around approval is that approval is slow or absent. A 1-day triage and a 3-day standard review are what make the process usable, and a usable process is what generates visibility.

### Risk tiers

| Tier | Criteria | Examples | Review |
|---|---|---|---|
| **Low** | Public or non-sensitive data; no system access; no regulated data; no action-taking | Marketing copy generation, public research, image generation for marketing | Lightweight registration; same-day approval |
| **Medium** | Internal business data or code assistance; no regulated data; limited system integration | Coding assistants on non-client repos, internal document drafting, meeting notes for internal-only meetings | Security review of vendor terms, retention and training; configuration requirements; 3-day target |
| **High** | PHI, student records, confidential client code or data; production system access; autonomous action; or any tool embedded in an Ajaia product | Medical LLM vendor, transcription tools where PHI may be discussed, agents with cloud access, any client-facing AI feature | Full vendor assessment, BAA or data-processing terms, Privacy/Legal approval, documented risk acceptance by the business owner; 10-day target |

Any tool that can **take actions** rather than only produce text is automatically at least Medium, and High if it touches production or regulated data — autonomy is a risk dimension independent of data sensitivity.

### Data classification rules for AI tools

Mapped directly to the corrected classification policy from Module 3 Part C:

| Classification | AI tool rule |
|---|---|
| **Public** | Permitted in any approved tool |
| **Internal** | Approved tools only; no unnecessary disclosure; verify retention terms |
| **Confidential** | Only tools specifically approved for that data class, with contractual retention and no-training terms verified. Client-specific restrictions checked first |
| **Restricted / Regulated** (PHI, student PII, credentials, secrets, sensitive client source code) | Explicit written approval required; BAA or equivalent contract in place; minimum-necessary data only; enterprise tier with zero or minimal retention; use logged. **Default is prohibited** |

**Absolute prohibitions, no exceptions and no approval path:** credentials, API keys, private keys, secrets or access tokens must never be entered into any AI tool. Regulated data must never be entered into any tool lacking a BAA or equivalent. Client data must never be entered where the client contract prohibits it.

### Monitoring for unauthorised usage

- **Approved-tool catalogue** published where people will actually see it — not buried in a policy document.
- **Monthly expense and SaaS review** for unrecognised AI vendors. This is how the current nine were found; it stays, but it is a backstop, not a control.
- **DLP and browser controls** to detect and block regulated-data uploads to unapproved destinations — the only control that catches **free-tier tools**, which expense review structurally cannot see and which is where most shadow AI actually lives.
- **Enterprise tenant enforcement** where the vendor supports it, so corporate accounts cannot be used outside the approved configuration.
- **Audit-log review** for approved enterprise AI tools.
- **Periodic anonymous survey** asking what people actually use. Self-report catches what tooling misses, and it costs nothing.
- **Client-facing AI inventory** so Ajaia can answer a client's "which AI tools touch our data" question in minutes rather than weeks — a question Harmoni and Ethos are both likely to ask.

### Consequences

Proportionate, and explicitly separated from the incident-response process:

- **Accidental first-time misuse, self-reported:** contain, assess, coach. No disciplinary consequence. Self-reporting is what we want to reinforce.
- **Accidental misuse, discovered by monitoring:** contain, assess, coach, and a documented refresher. Focus on why the approved path was not used.
- **Repeated misuse after coaching:** manager involvement, restricted access, formal record.
- **Deliberate circumvention, or misuse concealed after discovery:** formal disciplinary escalation. Concealment is the aggravating factor, not the mistake.
- **Any suspected exposure of PHI, student data, secrets or client code:** triggers the incident-response process regardless of intent, and that assessment is entirely separate from any personnel question.

### Communicating this without a blame dynamic

The framing is **guardrails, not a ban**. Ajaia sells AI products; a security function that treats AI use as suspicious would have no credibility and would simply be routed around.

What I would say to the team:

> "We build AI products, and I want everyone using AI in their work — that's the job. What I need is for us to know which tools we're using and what data goes into them, because we hold patient records and children's school records, and some of those tools will use whatever we send them in ways we haven't agreed to.
>
> So: here's the approved list, here's what you can put into each one, and here's a form that takes ten minutes if you want something new. I'll get back to you in a day. If approval is slow, tell me — that's a bug on my side.
>
> And if you've already put something into a tool you shouldn't have, tell me today. You will not be in trouble for telling me. I need to know so I can contain it and protect the client. The only version of this that goes badly is the one where I find out in six months from a client's auditor."

Supporting material: a one-page approved-tool list with plain-language do/don't examples; a short training on the three AI-specific risks that are genuinely non-obvious (prompt injection, confident hallucination, and the consumer-versus-enterprise-terms distinction that caused the developer incident); a visible fast path for new tool requests; and quarterly updates on what has been approved.

**Framework in one line:** **Approve quickly → tier by data and autonomy → constrain data → monitor continuously → respond proportionately → make reporting safe.**

---

# AI Workflow Disclosure

I used AI as a structured analyst, challenger and reviewer — not as the decision-maker. My working loop:

**Frame the problem → generate options → challenge assumptions → verify against primary sources → override or correct → finalise.**

| Tool / model | How I used it | What I independently verified | What I changed or rejected |
|---|---|---|---|
| **ChatGPT** | Decomposed the scenarios into decision points, stress-tested my risk prioritisation, compared remediation options, and challenged my incident-response sequencing | Every CFR and TSC citation against the primary source (eCFR, HHS, U.S. Dept. of Education SPPO, AICPA); GCP and Azure service capabilities against current vendor documentation; every scenario fact against the assignment text | Rejected generic cloud-security recommendations and rewrote them against Ajaia's specific exposures. Corrected an initial framing that treated "no confirmed exfiltration" as weighing against breach — the §164.402 test is *acquired or viewed*. Removed controls that did not map to a stated risk |
| **Claude (Sonnet and Opus)** | Second-pass review, red-teaming of my conclusions, alternative interpretations of the FERPA school-official analysis, and structural editing | Compared outputs against scenario evidence and primary sources rather than accepting conclusions; cross-checked the two models against each other where they disagreed | Rejected unsupported severity claims and assumptions about data exposure not present in the facts. Rejected enterprise-scale control recommendations that a 20-person company could not realistically operate |

*(Note: specify the exact model versions used before submitting.)*

### Specific instances where I overrode the AI

- **Risk ranking.** Initial output surfaced technically valid issues in roughly severity order. I re-ranked around the *chain* — reachable database, exposed credential, over-privileged identity — because that chain is what actually executed in Module 2, and it argues for a different remediation sequence than a flat severity list.
- **Log retention.** AI treated 30-day retention as a routine gap. I elevated it after noticing it directly conflicts with the Module 2 investigation, which depends on establishing an exposure window that may predate the logs. That connection is only visible when the modules are read against each other, which the model did not do unprompted.
- **HIPAA determination.** I rejected the framing that lack of confirmed exfiltration supports a low-probability finding. Fourteen successful SELECTs returning PHI to an external party is acquisition under §164.402 factor 3. I also corrected an initial output that stopped at "presumptive breach pending assessment" — on these facts the assessment does not reach low probability, and hedging would be misleading.
- **Persistence hunting.** No initial draft included checking for attacker-created service accounts, keys or IAM bindings. Revoking one key on an account that held project-level Owner proves nothing; I added this as a required step in the first 30 minutes.
- **The 4-digit PIN.** AI treated the stolen laptop as a standard "encrypted device" case. I rejected that: the device was stolen unlocked, and a 4-digit PIN is a 10,000-value keyspace. The encryption safe harbour turns on whether data was rendered unusable, and on these facts it was not.
- **Licensing cost.** I added explicit Entra P1/P2 licensing costs and a fallback if only one tier can be funded. Recommending PIM and Conditional Access to a 20-person company without pricing them is not a practical recommendation.
- **Shadow AI.** Initial output treated the six unapproved tools as a uniform list. I re-triaged: Otter.ai and the medical transcription API are materially more urgent than Midjourney, because of what they process and who Ajaia's clients are. I also rejected a blanket "block unapproved AI" approach in favour of risk tiering and a fast approval path, because a slow process is what created the shadow AI in the first place.
- **FERPA.** I added the §99.7 annual-notification prerequisite and the §99.67(c) five-year bar, neither of which appeared in initial output, and both of which change the risk calculus from "compliance gap" to "commercial exposure."
- **Tone on the developer scenario.** I rejected a punitive framing. The governance failure was Ajaia's — Copilot was licensed and the developer was not directed to it — and a punitive response guarantees the next incident is concealed.

**My position.** AI accelerated research, structure and drafting, and improved this document. Every risk ranking, architecture decision, compliance conclusion, breach determination and recommendation is mine. Where AI output conflicted with the scenario facts or with primary sources, I corrected it rather than adjusting my answer to fit the output — and the cases above are the ones where that mattered most.

---

# Supplementary Materials

**Google Drive folder (anyone with the link):** `[https://drive.google.com/drive/folders/1gqECqCVjNVHmyPQXz02S7NnSiYJZQV97?usp=sharing]`

Contents:

- Target-state multi-cloud security architecture diagram
- 90-day remediation roadmap 
- HIPAA / FERPA / SOC 2 control crosswalk
- Incident-response decision flow and Module 2 timeline


---


---

*Ajaia AI-Native Assessment — https://ajaia.ai*
