from fastapi import Depends, HTTPException, Request, status


def get_current_user(request: Request):
    """Simple mock authentication.
    Expects an Authorization header with a Bearer token.
    Token ``admin-token`` is treated as an admin user.
    """
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = auth.split(" ")[1]
    if token == "admin-token":
        return {"role": "admin", "token": token}
    # In a real implementation you would verify JWT and extract role claims.
    raise HTTPException(status_code=403, detail="Invalid or insufficient privileges")


def admin_required(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user
