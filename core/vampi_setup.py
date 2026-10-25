"""Restore and validate the disposable VAmPI benchmark before each round."""
import httpx


def prepare_vampi(base, reset=True):
    try:
        with httpx.Client(base_url=base, timeout=10) as client:
            if reset:
                client.get("/createdb").raise_for_status()
            for username, password in (("name1", "pass1"), ("name2", "pass2")):
                response = client.post("/users/v1/login", json={"username": username, "password": password})
                response.raise_for_status()
                if not response.json().get("auth_token"):
                    raise ValueError(f"Seeded login failed for {username}")
            response = client.get("/books/v1")
            response.raise_for_status()
            if not any(b.get("book_title") and b.get("user") != "name2" for b in response.json().get("Books", [])):
                raise ValueError("No seeded victim book available")
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(f"VAmPI preflight failed for {base}: {exc}. Check Docker and the seeded database; no attack round was started.") from exc
