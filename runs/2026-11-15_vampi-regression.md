# VAmPI regression — 15 November 2026

Model `qwen2.5` via local Ollama; each instance reset with `/createdb` before the round (`run_attacker.py`).

| Check | Vulnerable (5002) | Secure (5001) |
|---|---|---|
| Debug endpoint leaks passwords (deterministic) | vulnerable | vulnerable (insecure by design) |
| Unauthenticated book listing (deterministic) | vulnerable | vulnerable (insecure by design) |
| Forged JWT with hardcoded secret (deterministic) | vulnerable | vulnerable (insecure by design) |
| Mass assignment on registration (LLM) | vulnerable | defended |
| Login user/password enumeration (LLM) | vulnerable | defended |
| SQL injection in username path (LLM) | vulnerable | defended |
| BOLA: read another user's book (LLM) | vulnerable | defended |
| BOLA: overwrite another user's password (LLM) | vulnerable | defended |

Result: 8/8 vulnerable on the vulnerable instance; all 5 LLM missions flip to defended on the secure instance; 0 inconclusive. Matches the baseline in the main README.
