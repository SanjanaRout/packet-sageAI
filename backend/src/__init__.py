def main() -> None:
    """Entry-point for the `backend` CLI script."""
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

