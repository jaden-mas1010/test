# Ajaia AI-Native Assessment — Director of IT & Security

**Candidate:** Jaden Mascarenhas  
**Role:** Information Security Analyst  
**Ajaia:** https://ajaia.ai  

> **Submission note:** This document is structured for direct Markdown submission. I state assumptions where evidence is incomplete and prioritize practical execution for Ajaia's 20-person, regulated-industry environment.

---

# Module 1 — Security Architecture & Cloud Infrastructure

## 1. Five Most Critical Security Risks

| Rank | Severity | Risk | Why Critical | Exact Remediation |
|---|---|---|---|---|
| 1 | Critical | Public Cloud SQL exposure | Harmoni PHI and client data are on Cloud SQL with public IP enabled and 0.0.0.0/0 allowed, creating a direct internet attack path to regulated data. | Immediately remove 0.0.0.0/0, disable public IP, move Cloud SQL to Private IP using Private Service Access, restrict access through VPC firewall rules, and review Cloud SQL/Audit logs for suspicious access. |
| 2 | Critical | Exposed secrets and privileged credentials |API keys are committed to repos, SSH keys are in shared Google Drive, and recovery keys are in a sheet shared with everyone, so one leak could give an attacker direct access to production. | Revoke and rotate all exposed credentials, move secrets into Google Secret Manager and Azure Key Vault, replace shared SSH keys with Google OS Login/IAP, and remove secrets from Git history. |
| 3 | Critical/High | Excessive privilege in GCP and AKS | Project-level service accounts have Owner, and five developers have cluster-admin, so one compromised account could control large parts of the environment. | Remove Owner and cluster-admin, create workload-specific service accounts, enforce least privilege with GCP IAM and Azure RBAC, and use Entra Privileged Identity Management for temporary admin elevation. |
| 4 | High | Unmanaged remote endpoints | Ajaia handles PHI and student records, but there is no MDM, six personal Linux devices are used, and encryption is only self-reported, so endpoint compromise could expose regulated data. | Enroll company devices into an MDM, enforce FileVault and endpoint protection, require compliant devices through Entra Conditional Access, and restrict production/PHI access from unmanaged BYOD. |
| 5 | High | Weak backup and recovery | PHI databases have only seven days of backup retention and no PITR, while GCS deliverables have no versioning or backup, so ransomware, deletion, or regional failure could cause unrecoverable client data loss. | Enable Cloud SQL Point-in-Time Recovery, increase retention, enable GCS Object Versioning, create protected cross-region backup copies, and regularly test restores against defined RPO/RTO targets. |

**Prioritization rationale:**  
These five outrank the other issues because they create the most direct paths to compromise of regulated data, production systems, or recovery capability. They combine high impact with current exposure: internet-accessible Cloud SQL containing PHI, exposed credentials, excessive administrative privileges, unmanaged endpoints, and weak recovery controls. Other issues such as use of latest container tags, GCR migration, 30-day log retention, AKS namespace design, and reused VPN PSKs are still important, but I would address them after the risks that could most immediately lead to unauthorized access, data loss, or major compliance impact.

## 2. Target-State Network Security Architecture

**Design principle:**  
Private-by-default, least privilege, centralized identity, short-lived credentials, strong segmentation, and auditable access.

**Why:**  
Ajaia currently has public database exposure, excessive privileges, shared secrets, unmanaged endpoints, and weak segmentation. This design reduces attack surface, limits lateral movement, and improves accountability across both clouds.

### **VPC redesign**

Replace the GCP default auto-mode VPC with a **custom-mode VPC** and separate workloads by trust level.

- Create dedicated subnets for **ingress, application, data, and management/CI** workloads.
- Keep application and data workloads on **private IPs**.
- Use **VPC firewall rules / hierarchical firewall policies** to permit only required traffic between subnets.
- Use **Cloud NAT** for controlled outbound internet access.
- Restrict GCP–Azure VPN routes and use a **unique PSK per tunnel**.

**Why:**  
The current default VPC and shared VPN configuration make lateral movement easier. Segmentation limits the blast radius if one workload is compromised.

### **Private Cloud SQL connectivity**

- Remove `0.0.0.0/0` immediately.
- Disable **public IP**.
- Move Cloud SQL to **Private IP using Private Service Access**.
- Allow database access only from approved application subnets and service identities.
- Enable **Cloud Audit Logs / Cloud SQL logs**.
- Enable **Point-in-Time Recovery** for Harmoni.

**Why:**  
Cloud SQL contains Harmoni PHI and client data. Public exposure creates a direct internet attack path to regulated data, so private connectivity is a priority.

### **Azure AD / Microsoft Entra ID ↔ GCP federation**

Use **Microsoft Entra ID as the central workforce identity provider**.

- Configure **GCP Workforce Identity Federation** with Entra ID.
- Map Entra groups to GCP IAM roles.
- Enforce **MFA and Conditional Access**.
- Remove broad Editor/Owner permissions.
- Use **Entra PIM** for time-bound administrative access.
- Apply a formal joiner-mover-leaver process.

**Why:**  
Centralized identity reduces account sprawl and makes access easier to revoke, review, and audit across both clouds.

### **Secrets-management migration**

- Revoke and rotate API keys, SSH keys, and recovery credentials that are currently exposed.
- Move GCP secrets to **Google Secret Manager**.
- Move Azure secrets to **Azure Key Vault**.
- Replace shared SSH keys with **Google OS Login + IAM-based access**.
- Remove recovery keys from shared Google Sheets.
- Give workloads access through service identities instead of static credentials.
- Enable logging and rotation.

**Why:**  
Secrets are currently stored in repositories, Drive, and Sheets. One compromise could expose production access, so eliminating long-lived shared credentials directly reduces credential-theft risk.

### **Supporting controls**

**AKS hardening**
- Remove standing `cluster-admin`.
- Integrate AKS with **Entra ID and Azure RBAC**.
- Separate `prod`, `dev`, and `ops` namespaces.
- Enforce **Pod Security Standards** and **Network Policies**.
- Use **Azure Key Vault** for sensitive secrets.

**Why:**  
Current AKS permissions are too broad. Least privilege and namespace separation reduce the impact of a compromised developer account or workload.

**Logging**
- Increase security-log retention beyond 30 days.
- Centralize GCP and Azure security/audit logs.
- Alert on privileged changes, secret access, and unusual authentication.

**Why:**  
Thirty days may be insufficient to investigate delayed or persistent attacks. Better retention and alerting improve detection and forensic capability.

**Endpoints**
- Enroll company MacBooks in MDM.
- Enforce and verify FileVault.
- Restrict PHI and production access from unmanaged BYOD.
- Apply Conditional Access based on device compliance.

**Why:**  
Ajaia cannot currently verify whether remote endpoints handling regulated data are secure. Device compliance reduces the chance of endpoint-driven data exposure.

**Backup and recovery**
- Enable **Cloud SQL PITR**.
- Increase retention.
- Enable **GCS Object Versioning**.
- Maintain protected backup copies outside the primary failure domain.
- Test restores regularly.

**Why:**  
Current backups are short-lived and concentrated in one place. Ransomware, deletion, or regional failure could cause unrecoverable client-data loss.

### **90-Day Remediation Plan**

| Timeline | Priority Actions | Owner | Evidence of Completion |
|---|---|---|---|
| Days 0–30 | Remove `0.0.0.0/0`, rotate exposed secrets, remove Owner/cluster-admin, enable MFA/Conditional Access, enable Harmoni PITR | IT & Security Lead + Cloud/Engineering Leads | Cloud SQL access review, rotated-key inventory, IAM diff, MFA/CA reports, PITR enabled |
| Days 31–60 | Build custom VPC, migrate Cloud SQL to Private IP, deploy Workforce Identity Federation, migrate secrets, harden AKS | Cloud/Platform Lead + Security | Private-IP tests, federation login tests, secrets migration report, AKS RBAC review |
| Days 61–90 | Complete MDM rollout, extend logging, enable GCS versioning/resilient backups, test restores, perform access recertification | Security + IT Operations | MDM compliance report, alert tests, restore-test evidence, access-review sign-off |

**Architecture diagram:** [[Supplementary-material link](https://drive.google.com/file/d/1UA8ra2IhBg9xYC-wT0q3nkP0Hg5kfxwX/view?usp=sharing)]

---

# Module 2 — Incident Response & Crisis Management

## **1. First 60 Minutes**

### **0–10 minutes — Validate and contain**

**Actions:**
1. Declare a **P0 incident**.
2. Revoke/disable the compromised GCP service-account key.
3. Confirm which workloads depend on that key.
4. Issue a clean replacement identity only if needed for service continuity.
5. Open an incident record and assign responders.

**Owner:**  
IT & Security Lead, supported by Cloud/Platform Engineering.

**Why:**  
There is confirmed unauthorized use of a credential linked to Cloud SQL containing PHI. The first priority is to stop further access without unnecessarily breaking production.

---

### **10–30 minutes — Preserve evidence and establish scope**

**Actions:**
1. Preserve **Cloud Audit Logs, Cloud SQL logs, IAM state, service-account metadata, source IPs, alert details, GitHub history, and application logs**.
2. Record timestamps and who collected each evidence source.
3. Determine when the key was exposed and every resource it could access.
4. Review all activity performed using that identity.
5. Investigate the related Entra ID login attempt and verify the former employee account is fully disabled.

**Owner:**  
Security/Incident Lead with Cloud Engineering support.

**Why:**  
I need trustworthy evidence before making wider changes. This establishes the timeline, blast radius, and whether the attacker reached systems beyond Cloud SQL.

---

### **30–60 minutes — Investigate blast radius and maintain service**

**Actions:**
1. Review the 14 `SELECT` queries and identify exactly which Harmoni tables and records were accessed.
2. Check application/API logs for possible exfiltration paths.
3. Search for the same IP, credential, or related indicators across other GCP and Azure resources.
4. Rotate any additional credentials the compromised service account could access.
5. Reduce the replacement identity to **least privilege**.
6. Begin the HIPAA breach-risk assessment and involve privacy/legal.

**Owner:**  
Security Lead, Cloud/Platform Lead, and Privacy/Legal.

**Why:**  
At this stage the key is contained, so the priority shifts to proving the true impact, maintaining business service safely, and determining whether PHI exposure triggers notification obligations.

---

### **3:30 AM — Stolen Laptop**

**Actions:**
1. Open a second high-severity incident.
2. Revoke the employee's **Google Workspace, Slack, Entra ID, GCP, and other active sessions/tokens**.
3. Reset credentials and revoke exposed SSH/API credentials.
4. Determine what Harmoni data was synced or cached locally.
5. Review cloud and authentication logs from the theft time onward.
6. Preserve the device/user access evidence for the HIPAA assessment.

**Owner:**  
IT/Security responder handles endpoint containment while the incident lead remains focused on the cloud compromise.

**Why:**  
The laptop was open and unlocked, so FileVault does not remove the risk of someone using the active authenticated session.

---

### **Prioritization**

**P0:** Service-account compromise.  
**High severity in parallel:** Stolen laptop.

**Why:**  
The cloud incident has confirmed unauthorized database queries against PHI, while the laptop currently represents potential exposure. I would assign separate responders so containment of one incident does not delay the other.

## 2. HIPAA Breach Determination

### Service-account compromise

**Regulatory standard:**  
HIPAA Breach Notification Rule, **45 CFR §§164.400–414**, especially **§164.402** for the breach risk assessment and **§164.410** for business-associate notification. :contentReference[oaicite:0]{index=0}

**Nature and extent of PHI:**  
High concern. The queries targeted patient symptom descriptions and provider notes, so sensitive PHI was involved.

**Unauthorized person:**  
The credential was used from an IP/geography where Ajaia has no employees or contractors, strongly indicating unauthorized access.

**Actually acquired/viewed:**  
Fourteen successful `SELECT` queries are evidence that PHI was accessed/viewed. The remaining uncertainty is whether the returned data was further exfiltrated through the application layer.

**Mitigation:**  
Revoke the key, rotate related credentials, restrict replacement access, preserve evidence, investigate application-layer exfiltration, and monitor for continued attacker activity.

**Burden of proof:**  
An impermissible use/disclosure is presumed to be a breach unless Ajaia can document a **low probability that the PHI was compromised** using the four-factor assessment. Ajaia therefore cannot rely on "we cannot prove exfiltration." :contentReference[oaicite:1]{index=1}

**Recommendation:**  
Treat this as a **presumptive HIPAA breach pending completion of the documented risk assessment**. If Ajaia cannot demonstrate a low probability of compromise, notify Harmoni under the BAA and §164.410 without unreasonable delay. :contentReference[oaicite:2]{index=2}

---

### **Stolen laptop**

**Regulatory standard:**  
Apply the same HIPAA breach framework under **45 CFR §164.402** if PHI was accessible from the device or its active sessions. :contentReference[oaicite:3]{index=3}

**Four-factor assessment:**  
1. **Nature/extent:** Determine what Harmoni PHI was stored, synced, cached, or accessible.  
2. **Unauthorized person:** Assess who could use the stolen unlocked device.  
3. **Actually acquired/viewed:** Review post-theft authentication, Drive, Slack, cloud, and application activity.  
4. **Mitigation:** Evaluate the effectiveness and timing of session revocation, credential resets, and access containment. :contentReference[oaicite:4]{index=4}

**Effect of FileVault/open-unlocked state:**  
I would not dismiss the incident because FileVault was enabled. Since the device was already open and authenticated, data available through the active session may have been accessible to the thief.

**Recommendation:**  
Treat it as a **potential HIPAA breach** until the investigation establishes what PHI was accessible and whether Ajaia can demonstrate a low probability of compromise.


## 3. Response to CEO

## **3. Response to CEO**

> "I understand the concern about notifying the client before we have complete certainty.
>
> What we know is that an unauthorized service-account key executed 14 queries against tables containing Harmoni PHI. We do not yet have evidence proving whether the returned data was further exfiltrated. Separately, the stolen laptop was encrypted, but it was open and unlocked, so encryption alone does not close that risk.
>
> Under HIPAA, we should not treat uncertainty as proof that no breach occurred. We need to complete the documented breach-risk assessment, preserve the evidence, and review our BAA obligations with privacy/legal.
>
> My recommendation is that we prepare to notify Harmoni based on the evidence we have, while being precise about what is confirmed and what is still under investigation. We should communicate the facts, the containment steps already taken, and the next investigation update time.
>
> I would avoid delaying disclosure simply because the investigation is incomplete; that creates greater regulatory and trust risk than transparent, evidence-based communication."
---

# **Module 3 — Compliance Governance & Policy**

## **Part A — Compliance Program Design**

### **1. Unified HIPAA, FERPA and SOC 2 Program**

**Recommendation:**  
I would build **one integrated compliance control framework**, not three disconnected programs. Ajaia should implement shared controls once, map them across HIPAA, FERPA and SOC 2, then add framework-specific overlays where the obligations differ.

### **Where they overlap**

The main shared control areas are:

- **Access control** — least privilege, MFA, role-based access and periodic reviews.
- **Risk management** — identify, assess, treat and track security/privacy risks.
- **Incident response** — defined escalation, investigation, evidence preservation and notification processes.
- **Training** — workforce awareness for security, privacy and data handling.
- **Logging and monitoring** — maintain evidence of access, changes and security events.
- **Vendor management** — assess third parties before they handle regulated or sensitive data.
- **Policy and evidence management** — documented controls, owners, review dates and audit evidence.

**Why:**  
Implementing these controls once reduces duplication and gives Ajaia one consistent operating model across regulated clients.

### **Where they diverge**

**HIPAA:**  
Focuses on PHI/ePHI. Ajaia must apply HIPAA-specific safeguards, risk analysis, minimum-necessary access, breach assessment, and BAAs where vendors create, receive, maintain or transmit PHI.

**FERPA:**  
Focuses on student education records. Ajaia must ensure access is limited to legitimate educational interests, use data only for the authorized school purpose, remain under the school's required control, and prevent unauthorized redisclosure.

**SOC 2 Type I:**  
Focuses on whether Ajaia's controls are suitably designed at a specific point in time against the applicable Trust Services Criteria. It is mainly about control design, evidence and auditability rather than a separate privacy law.

### **Operating model**

I would maintain a **control-to-requirement matrix** with:

- Control
- HIPAA / FERPA / SOC 2 mapping
- Control owner
- Evidence required
- Review frequency
- Current gap/status
- Remediation due date

This lets Ajaia implement a control once, show which frameworks it satisfies, identify remaining framework-specific gaps, and produce evidence quickly for clients or auditors.

**Final approach:**  
**One control backbone → shared controls → framework-specific overlays → centralized evidence and gap tracking.**
---

## Part B — PHI Determination

### 2. Memo to CEO — Harmoni / Claude

**To:** CEO  
**Subject:** HIPAA applicability to Harmoni Claude API calls

**Conclusion:**  
The statement that "HIPAA does not apply because names and DOB are removed" is **not sufficient**. Removing only those identifiers does not automatically make health information de-identified under HIPAA.

**PHI analysis:**  
Symptoms and medication information are health information. The question is whether the information identifies an individual or whether there is a reasonable basis to believe it could identify them. HIPAA's de-identification standard is defined at **45 CFR §164.514**. :contentReference[oaicite:3]{index=3}

**Safe Harbor analysis:**  
Safe Harbor requires removal of the specified HIPAA identifiers—not simply names and dates of birth—and the organization must have no actual knowledge that the remaining information could identify an individual. Ajaia therefore cannot treat "PII stripped" as equivalent to HIPAA de-identification. :contentReference[oaicite:4]{index=4}

**BAA implications:**  
If Claude creates, receives, maintains or transmits ePHI on behalf of Ajaia/Harmoni, the relevant cloud/AI provider relationship must be assessed as a business-associate/subcontractor relationship and a compliant BAA must be in place where required. Encryption or limited identifiers do not by themselves remove that obligation. :contentReference[oaicite:5]{index=5}

**Recommendation:**  
Until Ajaia can demonstrate valid de-identification, I would treat the prompts as **PHI**, minimize the data sent, confirm the applicable BAA and permitted-use terms, restrict retention/training, and document the HIPAA risk analysis.

### **3. Ethos / FERPA**

**Does sending student performance data to OpenAI's API violate FERPA?**  
Not automatically. The issue is whether the quiz responses/performance data contain **PII from education records** and whether the disclosure fits a FERPA exception. If Ajaia relies on the **school-official exception**, the AI provider must be used in a way that preserves the school's control over that data and limits use to the authorized educational purpose. :contentReference[oaicite:0]{index=0}

**Ajaia's obligation as a designated school official:**  
Ajaia must ensure that it performs an outsourced school function, remains under the school's **direct control** for use and maintenance of the records, limits access to legitimate educational interests, and prevents unauthorized use or redisclosure under **34 CFR §99.31(a)(1)(i)(B) and §99.33**. :contentReference[oaicite:1]{index=1}

**Required controls:**  
- Send only the **minimum student data necessary** for the learning function.  
- Confirm the provider is contractually restricted to the authorized educational purpose.  
- Prohibit unauthorized **training, secondary use, and redisclosure** of student data.  
- Define **retention and deletion** requirements.  
- Apply least-privilege access, encryption, logging, and auditability.  
- Review subprocessors and any onward data sharing.  
- Ensure the school retains required control and access to its education records.  
- Document the vendor assessment and FERPA basis before production use. :contentReference[oaicite:2]{index=2}

**Recommendation:**  
I would not approve identifiable Ethos student data being sent to the API until Ajaia can demonstrate that the school-official conditions and vendor controls are satisfied. If those conditions cannot be met, the data should be de-identified or another lawful basis obtained.
---

## **Part C — Policy Gap Analysis**

### **4. Incident Response Policy Gaps**

| Gap | Requirement not met | Consequence | Remediation |
|---|---|---|---|
| Fixed requirement to contain **all incidents within 4 hours** | HIPAA §164.308(a)(6) requires procedures to identify, respond to, mitigate and document incidents; SOC 2 CC7.3/CC7.4 expects defined analysis and response based on the incident | Teams may rush containment, destroy evidence, or miss the true scope | Replace the blanket 4-hour rule with **severity-based SLAs**, escalation paths and decision points |
| Client notification only after a **“confirmed breach”** | HIPAA breach analysis requires a documented risk assessment; uncertainty is not enough to avoid action | Ajaia could delay Harmoni notification while waiting for certainty that may never exist | Add a formal HIPAA breach-assessment workflow and BAA notification process |
| Blanket **96-hour client notification** rule | HIPAA §164.410 requires a business associate to notify the covered entity without unreasonable delay, subject to the BAA | Internal policy could conflict with contractual/regulatory obligations | Make notification timing dependent on **law, BAA and client contract**, with Privacy/Legal approval |
| No evidence-preservation or forensic procedure | HIPAA §164.308(a)(6)(ii) requires incidents and outcomes to be documented; HHS audit guidance specifically examines whether evidence is retained. SOC 2 CC7.3/CC7.4 expects incident analysis and response | Weak chain of custody; inability to prove scope, impact or breach determination | Require log preservation, snapshots, forensic copies, timestamps and chain-of-custody records |
| No defined incident severity/classification | SOC 2 CC7.3 requires evaluation of security events to determine whether they constitute incidents and their impact | Inconsistent prioritization and escalation | Introduce **P0–P3 severity levels** with response/escalation criteria |
| No defined roles beyond notifying the CEO | SOC 2 CC7.4 expects assigned responsibilities for incident response | Delays and unclear accountability during a live incident | Define Incident Lead, Cloud/Forensics, Privacy/Legal and Communications owners |
| No explicit recovery criteria | SOC 2 CC7.5 addresses recovery from identified incidents | Systems could return to service before risk is removed | Add eradication, recovery, validation and business-return criteria |
| Post-incident review exists, but no remediation tracking | HIPAA requires documentation of incidents/outcomes; SOC 2 expects corrective action and monitoring | Lessons are documented but weaknesses may remain unresolved | Track root cause, actions, owner and due date to closure |

HIPAA specifically requires incident procedures to identify and respond to incidents, mitigate harmful effects, and document incidents and outcomes. :contentReference[oaicite:0]{index=0} SOC 2 CC7.3 and CC7.4 similarly focus on evaluating security events and executing a defined incident-response program. :contentReference[oaicite:1]{index=1}

---

### **Data Classification Policy Gaps**

| Gap | Requirement not met | Consequence | Remediation |
|---|---|---|---|
| **Student education records classified as Internal** | FERPA §99.31(a)(1) requires access to education records to be limited to school officials with legitimate educational interests and third parties to remain under the school's direct control | “Internal” may permit unnecessarily broad employee/vendor access and unauthorized disclosure | Reclassify identifiable education records as **Confidential/Restricted** and map access to legitimate educational interest |
| No handling procedures for any tier | HIPAA requires reasonable policies/procedures for safeguarding ePHI; SOC 2 requires controls over protected/confidential information | Labels exist, but employees do not know how data may be stored, transmitted, shared or destroyed | Define handling rules for **access, storage, transmission, sharing, retention and disposal** |
| Encryption required only for Confidential data | Student records are currently “Internal,” so the draft does not require their encryption | FERPA-protected data could receive weaker protection simply because of a bad classification | Require encryption based on **data sensitivity**, including student records |
| No least-privilege/access mapping by classification | HIPAA access management and FERPA legitimate-educational-interest requirements | Excessive internal access to PHI or student records | Tie every tier to RBAC, need-to-know access and periodic access review |
| No vendor/third-party sharing rules | HIPAA BAA requirements; FERPA §§99.31 and 99.33 control third-party use/redisclosure | Sensitive data could be sent to AI/SaaS vendors without proper contractual controls | Require security/privacy review, BAA where applicable, FERPA use restrictions and subprocessor review |
| No retention/deletion rules | SOC 2 confidentiality lifecycle controls; FERPA requires third-party use to remain limited to authorized purposes | Data may remain available longer than necessary | Set retention periods and secure-deletion requirements by classification |
| No data owner or periodic review | SOC 2 governance/control-maintenance expectations | Classifications become stale or inconsistent | Assign data owners and require annual/event-driven review |
| PHI is only “Confidential,” with no higher restricted tier | HIPAA requires stronger controls around access to ePHI based on risk | PHI may be treated the same as ordinary confidential business information | Add a **Restricted/Regulated** tier for PHI, student PII, credentials and other regulated data |

FERPA's school-official exception requires the outside party to be under the school's direct control, limits use to the purpose of the disclosure, and requires reasonable methods to ensure access only where there is a legitimate educational interest. :contentReference[oaicite:2]{index=2}

### **Immediate regulatory risk**

The most immediate problem is classifying **student education records as “Internal.”**

**Why:**  
That label may allow broader internal or vendor access than FERPA permits. Ajaia is acting as a designated school official, so access must remain limited to legitimate educational interests and the use/redisclosure of the records must remain controlled. :contentReference[oaicite:3]{index=3}

**Consequence:**  
If the “Internal” label permits employees or third parties without a legitimate educational interest to access Ethos records, Ajaia could cause an unauthorized disclosure and jeopardize the school's ability to rely on the school-official exception.

**Immediate remediation:**  
Reclassify identifiable Ethos education records as **Restricted/Confidential**, enforce least privilege and encryption, define permitted sharing/retention rules, and require FERPA review before disclosure to any vendor or AI service.
---

# **Module 4 — Vendor Risk, IAM & IT Operations**

## **Part A — Vendor Security Assessment**

### **1. Medical LLM Vendor**

**Decision:**  
I would **not approve production use yet**. The vendor may ultimately be suitable, but the current evidence is insufficient for a system that will process Harmoni PHI.

### **Red flags and follow-up questions**

| Red Flag / Gap | Why It Matters | Question / Evidence Required |
|---|---|---|
| Claims “SOC 2 Type II certified” but provides no report | A claim is not evidence; I need to verify scope, auditor, period and exceptions | Provide the latest SOC 2 Type II report, bridge letter if needed, scope, subservice organizations and remediation status for exceptions |
| BAA only promised | A vendor processing ePHI on Ajaia's behalf is generally a business associate/subcontractor and needs a compliant BAA | Provide the proposed BAA for legal/security review before any PHI is sent |
| 90-day prompt/output logging | PHI may persist far longer than operationally necessary, increasing exposure and breach impact | Can retention be reduced or disabled for Harmoni? Who can access logs? How are they deleted and verified? |
| “No customer data used for training” is only a statement | Need to understand whether data is used for evaluation, tuning, abuse monitoring, or other secondary purposes | Confirm contractually that prompts, outputs and metadata are not used for training, fine-tuning or unrelated secondary use |
| Pen test is from 2023 and was internal | Evidence is stale and lacks independence | Provide the latest independent penetration-test executive report, date, scope, critical/high findings and closure evidence |
| Encryption statement is incomplete | AES-256/TLS 1.2 does not explain key ownership, rotation, secrets controls or internal access | Describe KMS/key management, rotation, privileged access, secrets handling and whether TLS 1.3 is supported |
| AWS `us-east-1` only stated | Region alone does not answer resilience, backup, DR or data residency | Describe HA architecture, backups, RPO/RTO, DR testing, replication and whether PHI leaves the approved region |
| Subprocessors not disclosed | Additional parties may receive or maintain PHI | Provide complete subprocessor list, locations, functions, notification process and BAA/subcontractor safeguards |
| Incident/breach notification terms missing | Ajaia needs rapid notice to meet BAA/client obligations | What is your security-incident notification SLA, escalation method and evidence-sharing process? |
| No access-control details | Vendor staff may have unnecessary access to PHI | Explain SSO/MFA, RBAC, privileged access, JIT access, access reviews and employee offboarding |
| No audit/logging detail | Ajaia needs traceability for PHI access and investigations | What customer/admin/access logs are available, how long are they retained and can Ajaia export them? |
| No vulnerability-management detail | A stale pen test is not continuous vulnerability management | Describe scanning cadence, patch SLAs, dependency/container scanning and remediation tracking |
| No secure deletion/termination process | PHI may remain after contract termination | How is customer data securely returned/deleted, including backups, and what deletion evidence is provided? |
| No AI-specific security evidence | Fine-tuned medical LLMs add prompt injection, leakage and model-behavior risks | Describe prompt-injection defenses, tenant isolation, model access controls, evaluation/red-team testing and output monitoring |

**Why this matters:**  
HHS guidance states that when a cloud provider creates, receives, maintains or transmits ePHI on behalf of a covered entity or business associate, a HIPAA-compliant BAA and appropriate risk analysis are required. The BAA/SLA should also address safeguards, availability, retention, return/deletion and permitted use of ePHI. :contentReference[oaicite:0]{index=0}



### **Approval conditions**

I would approve only after:

- satisfactory review of the SOC 2 report and current independent testing;
- execution of an acceptable **BAA**;
- reduction or contractual control of the 90-day PHI retention;
- verified no-training/secondary-use restrictions;
- subprocessor and breach-notification review;
- confirmation of access, logging, deletion, DR and AI-specific controls;
- documented residual-risk acceptance by the appropriate Ajaia owner.

---

### **2. Engineering: “We've already built the integration. We just need your sign-off.”**

**Response:**  
I would not treat security approval as a retrospective rubber stamp. The fact that development is complete changes the delivery pressure, not the risk.

**Immediate actions:**
1. Keep the integration out of production and prevent real Harmoni PHI from being sent until review is complete.
2. Allow testing only with synthetic or appropriately de-identified data.
3. Run an expedited vendor/security/privacy assessment using the gaps above.
4. Document blockers, remediation actions, owners and deadlines.
5. If critical requirements such as the BAA or PHI-use controls cannot be met, do not approve production deployment.

**Decision path:**  
**Assess → identify gaps → remediate → validate evidence → approve, conditionally approve, or reject.**

**Communication approach:**  
I would tell engineering:  
> “I want to help get this live, but production sign-off has to be evidence-based. Let's separate what is already technically built from what is safe to operate with PHI. I'll give you a short blocker list, owners and the fastest path to approval.”

**Why:**  
This protects Ajaia without creating a blame dynamic. Security remains a partner to engineering, but prior implementation does not justify accepting undocumented regulatory or client risk.
---

## **Part B — Access Control Redesign**

### **3. Ajaia RBAC Model**

**Design principle:**  
Least privilege, company-managed identities, MFA everywhere, no blanket access, and time-bound privileged elevation.

| Role | Google Workspace | GCP | GitHub | Azure / AKS | Sensitive Data | Privileged Access |
|---|---|---|---|---|---|---|
| Executive | Standard user; no admin by default | Read-only where justified | No repo access unless required | No AKS/admin access | Business/client data only as needed | None by default |
| Engineering | Standard user | Developer roles in assigned projects only; no blanket Editor/Owner | Assigned repos only; company-managed account | Namespace-scoped access; no standing `cluster-admin` | No PHI/student data unless approved | Temporary elevation with approval |
| Security / IT | Limited admin roles for security/IT functions | IAM, logging, security and investigation roles | Security/infra repos where needed | Monitoring + controlled admin access | Need-to-know for investigation/compliance | JIT, approved and fully logged |
| AI / Data | Standard user | Approved AI/data projects and datasets only | Assigned AI/data repos | Workload-specific access | Minimum necessary regulated data only | No standing admin |
| Contractor | Restricted account | Named resources only | Assigned repos only | Assigned namespace/workload only if required | No regulated data unless explicitly approved | None by default |

**Access tiers:**  
- **Tier 0 — Privileged/Admin:** IAM, production and security administration; smallest possible group, MFA + JIT + full logging.
- **Tier 1 — Production/Sensitive:** PHI, student records, secrets and production systems; need-to-know, approval required, frequent review.
- **Tier 2 — Standard Business:** Collaboration tools, normal SaaS and assigned development resources.
- **Tier 3 — Low Risk/Public:** Public or non-sensitive resources.

### **System-specific changes**

**Google Workspace:** Remove admin rights from all employees; create limited admin roles for IT/security; enforce MFA and company-managed accounts only.

**GCP:** Remove blanket Editor/Owner access; map users/groups to project-specific least-privilege IAM roles; use separate workload service accounts; require temporary elevation for sensitive admin tasks.

**GitHub:** Remove personal accounts; require company-managed accounts with SSO/MFA; grant repo access by team/project; restrict org/repo admin rights and protect main branches.

**Azure / AKS:** Integrate access with Entra ID and Azure RBAC; remove standing `cluster-admin`; scope developers to required namespaces; use PIM/JIT for privileged access.

### **Lifecycle controls**

Use a formal **Joiner–Mover–Leaver** process: grant access from approved role templates, remove old permissions during role changes, and disable identities/revoke sessions immediately on exit. Perform quarterly access reviews, with more frequent review for Tier 0/1 access.

**Why this model:**  
Ajaia's current model gives almost everyone broad administrative reach. This redesign removes standing privilege, limits blast radius, improves offboarding, and makes access auditable across the company's core systems.
---

# Module 5 — AI-Native Security & Operations

## **Part A — My AI Workflow**

### **1. Three AI-Assisted IT/Security Tasks**

#### **Workflow 1 — Vulnerability Analysis**

**Tool/model:** Claude Sonnet + my Python vulnerability scanner + NVD data.  

**Input:** Sanitized scan results, detected service/version, CVE identifiers and relevant configuration context.  

**Process:** I give the model the asset context, CVE evidence, constraints and a fixed output format. I ask it to separate **confirmed facts, assumptions and recommended remediation**, then challenge its severity reasoning against the actual environment.  

**Output:** Prioritized vulnerability summary with likely impact, exploitability, remediation steps and validation checks.  

**What I do NOT trust AI to do:** I do not let AI decide that a vulnerability is exploitable or critical by itself, and I do not let it trigger remediation automatically.  

**Validation:** I verify the CVE, affected version and mitigation against **NVD/vendor advisories and the raw scanner evidence** before accepting the recommendation.  

**Estimated time saved:** A task that takes roughly **30–45 minutes manually can often be reduced to 10–15 minutes**, depending on complexity.

---

#### **Workflow 2 — SOC / Log Analysis**

**Tool/model:** Claude Opus for deeper correlation when needed, alongside **Splunk, Windows Security and Sysmon logs**.  

**Input:** Sanitized event records such as timestamps, Event IDs, process creation, PowerShell activity, authentication events and network indicators.  

**Process:** I ask the model to reconstruct a timeline, correlate related events, map suspicious behavior to **MITRE ATT&CK**, and produce investigation hypotheses. My prompts explicitly tell it **not to invent missing events** and to label uncertainty.  

**Output:** Investigation timeline, suspicious-event correlations, ATT&CK mapping and next-step queries to validate the hypothesis in Splunk.  

**What I do NOT trust AI to do:** I do not trust it to declare an incident malicious, close an alert, or take containment action without evidence.  

**Validation:** I return to the **raw logs and Splunk searches** to confirm every important claim before making a security decision.  

**Estimated time saved:** Around **30 minutes of manual correlation can often become 10–15 minutes** for a focused investigation.

---

#### **Workflow 3 — Incident Reporting / Security Documentation**

**Tool/model:** Claude Sonnet for drafting and restructuring verified security information.  

**Input:** Sanitized, already-validated investigation notes, timeline, impact, evidence and remediation decisions.  

**Process:** I provide a defined structure such as **executive summary → timeline → impact → evidence → remediation**, specify the audience, and instruct the model not to fill factual gaps. I then refine the draft for technical or executive readers.  

**Output:** Structured incident reports, remediation summaries, risk-register entries or security documentation.  

**What I do NOT trust AI to do:** I do not delegate final breach determination, regulatory interpretation, risk acceptance or executive decisions to the model.  

**Validation:** I compare the draft against the original evidence and remove or rewrite anything that is unsupported, overstated or ambiguous.  

**Estimated time saved:** A **30–40 minute first draft can typically be reduced to around 10–15 minutes**, while final review remains manual.

---

### **My AI Operating Principle**

I use different models depending on the task: **Sonnet for fast structured analysis and drafting, and Opus when deeper correlation or reasoning is justified**. I structure prompts with context, constraints, evidence boundaries and a required output format.

I treat AI as an accelerator, not an authority: **AI proposes → I challenge → primary evidence verifies → I decide.** I also avoid placing client-sensitive data, PHI, credentials or proprietary source code into unapproved AI tools.
---

## **Part B — AI Risk & Governance**

### **2. AI Risk Register**

**Approach:**  
I would treat AI risk as a separate register because LLM usage creates risks that are not captured well by a generic IT risk register: prompt/data leakage, model hallucination, prompt injection, uncontrolled tool usage, vendor retention/training, and over-privileged AI agents.

| AI / LLM Risk | Likelihood | Impact | Current Control | Recommended Mitigation |
|---|---|---|---|---|
| Developer pastes client source code into ChatGPT | H | H | ChatGPT is not an approved tool; no effective enforcement | Treat as a data-handling incident; stop further use, assess what code/data was exposed, remove secrets if present, rotate affected credentials, use approved enterprise AI tools only, and enforce DLP/data-classification rules |
| PHI or student records entered into unapproved AI tools | M | H | Approved-tool list exists, but shadow AI usage shows weak enforcement | Block regulated data in unapproved tools; require privacy/security review, BAA/contract review where relevant, data minimization and approved-use rules |
| Hallucinated AI output drives a wrong security decision | M | H | Human review is informal | Require human approval for high-impact decisions; validate against raw logs, vendor documentation, regulations and primary evidence before action |
| Prompt injection or malicious retrieved content manipulates an AI workflow | M | H | No dedicated AI control stated | Separate trusted instructions from untrusted content, sanitize inputs, restrict tool permissions, validate outputs and sandbox high-risk agent actions |
| AI vendor retains prompts/outputs or uses them for secondary purposes | M | H | Some approved tools, but vendor terms are not centrally governed | Review retention, deletion, training, subprocessors and data-use terms; contractually prohibit unauthorized secondary use and define deletion requirements |
| Shadow AI / unapproved tools across the workforce | H | M/H | Expense reports reveal six unapproved tools | Maintain an approved tool catalogue; review SaaS/expense usage, implement DLP/CASB controls where available, and require lightweight tool registration |
| Over-privileged AI agents or copilots can take actions beyond intended scope | M | H | No agent-specific privilege model | Use least-privilege service identities, scoped tokens, approval gates for sensitive actions, rate limits and complete audit logging |

**Risk treatment:**  
Each risk should have an owner, review date, mitigation status and residual-risk rating. High residual risks involving PHI, student records, client code or autonomous actions should require Security/Privacy approval before acceptance.

**Developer scenario:**  
I would not accept the statement that "OpenAI does not train on API inputs" as sufficient. The developer used **ChatGPT Plus**, which is not on Ajaia's approved list, and the main issue is unauthorized disclosure of client source code into an unapproved service. I would stop the practice, assess the exposed code for secrets/client data, rotate anything sensitive, document the incident, and move debugging to an approved enterprise AI workflow.

---

### **3. AI Tool Governance Framework**

**Governance principle:**  
Enable fast AI adoption, but require stronger controls as the sensitivity of data and autonomy of the AI use case increase.

### **Approval process**

1. User/team submits a lightweight request describing the AI tool, business purpose, data types, model, integrations and whether it can take actions.
2. Security/Privacy performs vendor and data-use review: retention, training, subprocessors, security evidence, deletion and contractual terms.
3. Assign a risk tier.
4. Approve, conditionally approve, or reject.
5. Add approved tools to a central **AI inventory** with owner, permitted use, data restrictions and review date.

**Why:**  
Ajaia currently knows about AI usage only after seeing expense reports. Governance must move approval **before** sensitive data reaches a tool.

### **Risk tiers**

- **Low:** Public/non-sensitive content, no system access, no regulated data. Lightweight approval.
- **Medium:** Internal data or coding assistance with no sensitive client data. Security review and approved configuration required.
- **High:** PHI, student records, confidential client code, production access, automated decisions or AI agents with action-taking capability. Formal Security/Privacy/Legal approval required.

### **Data classification rules**

- **Public:** Allowed in approved AI tools.
- **Internal:** Approved tools only; no unnecessary sharing.
- **Confidential:** Only tools specifically approved for that data type, with retention/training restrictions.
- **Restricted/Regulated:** PHI, student PII, secrets, credentials and sensitive client source code require explicit approval, minimum-necessary data and contractual safeguards.
- Credentials, API keys and secrets should **never** be entered into general-purpose AI prompts.

### **Monitoring for unauthorized / shadow AI**

- Maintain an approved AI-tool catalogue.
- Review corporate expense reports and SaaS usage for unknown AI vendors.
- Use DLP/CASB/browser controls where appropriate to detect regulated-data uploads.
- Monitor enterprise AI audit logs where supported.
- Review new AI vendors and usage patterns periodically.

**Why:**  
The goal is visibility and early correction, not simply blocking everything.

### **Consequences**

- **Accidental first-time misuse:** contain, investigate, coach and retrain.
- **Repeated negligent misuse:** manager/security review and restricted access.
- **Deliberate or serious policy bypass:** formal disciplinary escalation.
- Any suspected exposure of PHI, student data, secrets or client code triggers the normal incident-response process.

### **Non-blaming communication**

I would communicate the framework as **guardrails for safe AI use, not an AI ban**.

> "If you accidentally put sensitive data into the wrong AI tool, report it immediately. Early reporting helps us contain the issue and protect the client. Hiding it creates the bigger risk."

I would give employees:
- a clear list of approved tools;
- simple examples of what data may or may not be entered;
- a fast path for requesting new tools;
- short training on AI-specific risks such as prompt injection, hallucination and data retention.

**Final approach:**  
**Approve deliberately → tier by risk → restrict data → monitor usage → respond proportionately → encourage fast reporting.**
---

# **AI Workflow Disclosure**

I used AI as a **structured analyst, challenger and reviewer — not as the final decision-maker**. My working loop was:

**Frame the problem → Generate options → Challenge assumptions → Verify against primary evidence → Override/correct → Finalize.**

| AI Tool / Model | How I Used It | What I Independently Validated | What I Changed / Rejected |
|---|---|---|---|
| **ChatGPT — GPT-5.6 Sol** | Broke complex scenarios into decision points, challenged prioritization, compared remediation options, stress-tested incident/compliance reasoning, and helped structure the final Markdown | Ajaia scenario facts; GCP/Azure service capabilities; HIPAA requirements using HHS; FERPA requirements using U.S. Dept. of Education guidance; SOC 2 terminology/criteria using AICPA sources | Rejected generic cloud recommendations and rewrote them around Ajaia's exact exposures. Corrected answers that treated "no confirmed exfiltration" as evidence of no breach. Removed controls that did not directly address the scenario |
| **Claude Sonnet / Opus** | Used as a second-pass reviewer for deeper reasoning, alternative interpretations, and red-teaming of security decisions; Sonnet for structured drafting and Opus where deeper correlation was useful | Compared outputs against scenario evidence and authoritative sources rather than accepting model conclusions | Rejected unsupported severity claims, assumptions about data exposure, and recommendations that added complexity without enough risk reduction for a 20-person company |

### **Examples of AI Override**

- **Cloud risk ranking:** AI initially surfaced several technically valid issues. I prioritized public Cloud SQL containing PHI, exposed credentials, excessive privilege, unmanaged endpoints, and recovery weakness because they represented the most immediate paths to material impact.
- **HIPAA incident:** I rejected the assumption that lack of confirmed exfiltration meant notification was unnecessary. I applied the HIPAA breach-risk assessment and treated uncertainty as something to investigate, not evidence of safety.
- **RBAC:** I moved away from a generic "least privilege + MFA" answer and built system-specific controls for Google Workspace, GCP, GitHub and AKS based on Ajaia's current access model.
- **AI governance:** I rejected a blanket "block unapproved AI" approach. I used risk tiers, approved-tool controls, monitoring and a non-blaming reporting path so governance supports AI adoption rather than driving usage underground.
- **Architecture:** I removed controls that added complexity without clear benefit and prioritized changes that a 20-person team could realistically implement within 90 days.

**My approach:**  
AI accelerated research, challenged my assumptions and improved structure, but **final risk ranking, architecture decisions, compliance conclusions, residual-risk acceptance and recommendations remained my decisions**. Where AI output conflicted with scenario evidence or primary sources, I corrected or rejected it rather than forcing the answer to fit the model output.
---

# Supplementary Materials

**Google Drive folder:** [Anyone-with-the-link URL]

Contents:
- Target-state multi-cloud security architecture diagram
- 90-day remediation roadmap
- Compliance control crosswalk
- Incident-response decision flow / timeline
- Supporting risk register, if applicable

All supplementary materials reference **https://ajaia.ai**.

---

# Video Walkthrough

**3–5 minute public video:** [Loom / YouTube unlisted / Google Drive URL]

**Walkthrough focus:**  
- My overall approach
- Highest-priority decisions
- Key security/compliance tradeoffs
- How I used and challenged AI
- Why the design is practical for Ajaia

I will reference **https://ajaia.ai** naturally in the walkthrough.

---

*Ajaia AI-Native Assessment — https://ajaia.ai*
