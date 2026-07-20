# ATT&CK coverage

Generated from `detections.yaml`. Regenerate after manifest changes:

```bash
uv run python -m agentdetect.attackdoc > docs/ATTACK.md
```

| Technique | Name | Detection | Rule |
|-----------|------|-----------|------|
| T1071.001 | Application Layer Protocol: Web Protocols | llm-api-egress | sigma |
| T1102 | Web Service | llm-api-egress | sigma |
| T1071.001 | Application Layer Protocol: Web Protocols | llm-sdk-user-agent | sigma |
| T1552.001 | Unsecured Credentials: Credentials In Files | credential-file-harvest | sigma |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | cloud-metadata-access | sigma |
| T1070.003 | Indicator Removal: Clear Command History | shell-history-tamper | sigma |
| T1562.003 | Impair Defenses: Impair Command History Logging | shell-history-tamper | sigma |
| T1082 | System Information Discovery | recon-breadth-burst | spl |
| T1057 | Process Discovery | recon-breadth-burst | spl |
| T1016 | System Network Configuration Discovery | recon-breadth-burst | spl |
| T1033 | System Owner/User Discovery | recon-breadth-burst | spl |
| T1518 | Software Discovery | recon-breadth-burst | spl |
| T1069 | Permission Groups Discovery | recon-breadth-burst | spl |
| T1059 | Command and Scripting Interpreter | agent-command-cadence | spl |
| T1102 | Web Service | agent-loop-interleave | spl |
| T1071.001 | Application Layer Protocol: Web Protocols | agent-loop-interleave | spl |
| T1059 | Command and Scripting Interpreter | agent-retry-storm | spl |
| T1567 | Exfiltration Over Web Service | sensitive-read-llm-exfil | spl |
| T1041 | Exfiltration Over C2 Channel | sensitive-read-llm-exfil | spl |
