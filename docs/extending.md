# Extending the System

This guide explains how to extend the Role Intelligence Service with new integrations, risk models, or API endpoints.

## Adding a New Adapter
1. Create a new adapter class in `role_intelligence/integrations/`.
2. Implement the common interface: `fetch_roles()`, `fetch_users()`, etc.
3. Register the adapter in the main service.

**Example:**
```python
class MyIAMAdapter(BaseAdapter):
    def fetch_roles(self):
        # Fetch roles from MyIAM
        pass
```

## Adding a New Risk Model
1. Create a new function or class in the risk evaluation module.
2. Integrate it into the risk calculation pipeline.

**Example:**
```python
def custom_risk(role):
    # Custom risk logic
    return score
```

## Adding a New API Endpoint
1. Open the FastAPI app (e.g., `run.py`).
2. Add a new route using `@app.get` or `@app.post`.
3. Implement the handler logic.

**Example:**
```python
@app.get("/custom-insight")
def custom_insight():
    return {"message": "Custom insight"}
``` 