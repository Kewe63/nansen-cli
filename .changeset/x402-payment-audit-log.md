---
"nansen-cli": patch
---

Record x402 auto-payments in a local audit log at `~/.nansen/x402/payments.jsonl`: one line when a signed payment is sent and one for its outcome (accepted, rejected or ambiguous), with the amount, network, asset, recipient and request path. Signatures, request data and query strings are never written, and a failed write warns without blocking the payment.
