---
"nansen-cli": patch
---

Render profiler perp positions as individual rows in table and CSV output while preserving the original JSON response and account summaries. Table and CSV output also falls back to showing the payload when a response's rows carry no fields, instead of printing blank lines.
