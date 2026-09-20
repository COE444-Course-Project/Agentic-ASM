from mcp.server.fastmcp import FastMCP
import httpx

mcp = FastMCP("http-tools")

@mcp.tool()
def http_request(method: str, url: str, headers: dict | None = None,
                 json_body: dict | None = None, params: dict | None = None) -> dict:
    """Send an HTTP request to a target API endpoint and return the response.
    Use for enumerating and probing REST endpoints (GET/POST/PUT/DELETE)."""
    with httpx.Client(timeout=15, follow_redirects=True) as client:
        r = client.request(method.upper(), url, headers=headers,
                           json=json_body, params=params)
    return {"status_code": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:5000]}

if __name__ == "__main__":
    mcp.run(transport="stdio")