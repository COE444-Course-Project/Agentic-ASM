"""Public operation contracts, never vulnerability labels or private ground truth."""
TEMPLATES = {
    "B1": ("GET", "/documents/{id}", "Direct document read"),
    "B2": ("POST", "/exports", "Document export"),
    "B3": ("GET", "/projects/{project_id}/files/{file_id}", "Nested project file"),
    "B4": ("POST", "/documents/batch", "Batch document read"),
    "B5": ("PATCH", "/documents/{id}", "Document modification"),
    "B6": ("POST", "/documents/{id}/share", "Document sharing"),
    "B7": ("GET", "/organisations/{org_id}/invoices/{id}", "Tenant invoice access"),
    "V1": ("POST", "/admin/users/{id}/disable", "Administrator account disable"),
}
