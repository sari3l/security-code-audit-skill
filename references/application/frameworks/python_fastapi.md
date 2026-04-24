# FastAPI / Starlette Security Reference

## Identification Features

```bash
grep -r "from fastapi\|import fastapi" --include="*.py"
grep -r "FastAPI(" --include="*.py"
grep -r "@app\.\|@router\." --include="*.py"
grep -r "Depends(\|APIRouter\|BackgroundTasks" --include="*.py"
```

Common file patterns: `main.py`, `routers/`, `dependencies.py`, `schemas.py`, `models.py`.

---

## High-Risk Framework Surfaces

### 1. Dependency Injection Gaps

- `Depends(get_current_user)` present on read routes but missing on write routes
- custom auth dependencies returning decoded tokens without signature or claim checks
- admin-only endpoints relying on frontend visibility instead of a dependency or policy

### 2. Pydantic / Binding Overreach

- endpoints accepting raw `dict` instead of strict models
- response models omitted, leaking full ORM entities
- update DTOs exposing `role`, `is_admin`, `balance`, `tenant_id`

### 3. Background Task Abuse

- `BackgroundTasks.add_task` fed user-controlled commands, URLs, or filesystem paths
- report/export queues reusing untrusted values later in shell or SQL contexts

### 4. File and URL Features

- `UploadFile.filename` used directly in storage paths
- webhook, import, preview, and PDF routes making outbound requests from user URLs

---

## Dangerous Patterns

```python
@app.post("/users")
def create_user(data: dict):
    return User(**data)

@app.get("/me")
def me(token: str = Header(...)):
    return decode_token(token)

@app.post("/run")
def run(cmd: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(os.system, cmd)
```

### Safer Patterns

```python
class UserCreate(BaseModel):
    email: EmailStr
    password: constr(min_length=12)

@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate, current=Depends(get_current_user)):
    ...
```

---

## Detection Commands

```bash
grep -rn "Depends(\|get_current_user\|oauth2_scheme" --include="*.py"
grep -rn "@app\.\|@router\." --include="*.py" -A 3
grep -rn "BackgroundTasks\|add_task(" --include="*.py"
grep -rn "UploadFile\|file\.filename\|FileResponse\|StreamingResponse" --include="*.py"
grep -rn "response_model=" --include="*.py"
grep -rn "data:\s*dict\|payload:\s*dict\|body:\s*dict" --include="*.py"
```

---

## Audit Questions

- Does every sensitive route actually depend on auth, or only the obvious ones?
- Are Pydantic models narrow, or are plain dictionaries and ORM entities used directly?
- Are response models stripping internal fields?
- Do async/background paths reuse the same validation guarantees as synchronous request paths?
