from fastapi import FastAPI, HTTPException
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime
from firebase_admin import credentials, initialize_app, db
import logging

app = FastAPI()

logging.basicConfig(level=logging.DEBUG)

FIREBASE_CREDENTIALS_PATH = "driveaccess-33828-firebase-adminsdk-kqvc4-5d82e5ac2f.json"
FIREBASE_DATABASE_URL = "https://driveaccess-33828-default-rtdb.asia-southeast1.firebasedatabase.app/"

cred = credentials.Certificate(FIREBASE_CREDENTIALS_PATH)
initialize_app(cred, {"databaseURL": FIREBASE_DATABASE_URL})

def get_drive_service():
    credentials = service_account.Credentials.from_service_account_file(
        'gen-lang-client-0011460502-4337f1435b28.json',
        scopes=['https://www.googleapis.com/auth/drive']
    )
    service = build('drive', 'v3', credentials=credentials)
    return service

def log_permission_change(file_id, email, role, action):
    # Log historical changes
    ref = db.reference(f"permissions/{file_id}")
    entry = {
        "email": email,
        "role": role,
        "action": action,
        "timestamp": datetime.utcnow().isoformat()
    }
    ref.push(entry)

def update_current_status(file_id, email, role=None):
    ref = db.reference(f"current_status/{file_id}")    
    existing_status = ref.get() or {}

    user_entry_key = None
    for key, value in existing_status.items():
        if isinstance(value, dict) and value.get("email") == email:
            user_entry_key = key
            break

    if user_entry_key:
        db.reference(f"current_status/{file_id}/{user_entry_key}").delete()

    if role == "delete":
        return
    
    if role:
        ref.push({"email": email, "role": role})

def push_to_firebase(data):
    ref = db.reference("name_to_id")
    existing_data = ref.get() or {}
    for file in data.get('files', []):
        file_id = file["id"]
        if file_id not in existing_data:
            ref.child(file_id).set({"name": file["name"]})

def get_file_id_by_name(file_name):
    ref = db.reference("name_to_id")
    all_files = ref.get() or {}  

    for file_id, file_data in all_files.items():
        if file_data.get("name") == file_name:
            return file_id 
    return None

@app.get("/files/")
async def list_files():
    try:
        service = get_drive_service()
        results = service.files().list(pageSize=10, fields="files(id, name)").execute()
        push_to_firebase(results)
        logging.debug("Files response: %s", results)
        return results.get('files', [])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/permissions/roles/")
async def get_roles_and_actions():
    return {
        "roles": ["reader", "writer", "commenter", "organizer", "owner"],
        "actions": ["granted", "adjusted", "revoked"]
    }

@app.post("/files/{file_id}/permissions/")
async def grant_permission(file_name: str, email: str, role: str):
    try:
        file_id = get_file_id_by_name(file_name)
        print(file_id)
        if not file_id:
            raise HTTPException(status_code=404, detail="File not found")
        service = get_drive_service()
        permission = {
            'type': 'user',
            'role': role,
            'emailAddress': email
        }
        service.permissions().create(fileId=file_id, body=permission).execute()
        log_permission_change(file_id, email, role, "granted")
        update_current_status(file_id, email, role)  # Update current status
        return {"message": "Permission granted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/files/{file_id}/permissions/update/")
async def update_permission(file_name: str, email: str, new_role: str = None):
    try:
        file_id = get_file_id_by_name(file_name)
        if not file_id:
            raise HTTPException(status_code=404, detail="File not found")
        service = get_drive_service()
        permissions = service.permissions().list(fileId=file_id, fields="permissions(id, emailAddress, role)").execute()
        permission_id = None

        for perm in permissions.get('permissions', []):
            if perm.get('emailAddress') == email:
                permission_id = perm.get('id')
                break

        if not permission_id:
            return {"error": "Permission not found"}

        if new_role:
            permission = {'role': new_role}
            service.permissions().update(fileId=file_id, permissionId=permission_id, body=permission).execute()
            log_permission_change(file_id, email, new_role, "adjusted")
            update_current_status(file_id, email, new_role)  # Update current status
            return {"message": f"Role updated to {new_role}"}
        else:
            service.permissions().delete(fileId=file_id, permissionId=permission_id).execute()
            log_permission_change(file_id, email, None, "revoked")
            update_current_status(file_id, email)  # Remove from current status
            return {"message": "Permission revoked"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/files/{file_id}/permissions/retrieve/")
async def list_file_permissions(file_name: str):
    try:
        file_id = get_file_id_by_name(file_name)
        if not file_id:
            raise HTTPException(status_code=404, detail="File not found")
        service = get_drive_service()
        permissions = service.permissions().list(fileId=file_id, fields="permissions(id, emailAddress, role)").execute()
        return permissions.get('permissions', [])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/{email}/files/")
async def list_user_access(email: str):
    try:
        ref = db.reference("current_status")
        current_status = ref.get() or {}
        user_access = []

        for file_id, permissions in current_status.items():
            if email in permissions:
                user_access.append({
                    "file_id": file_id,
                    "role": permissions[email]
                })

        return user_access
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/files/{file_id}/users/")
async def list_file_users(file_name: str):
    try:
        file_id = get_file_id_by_name(file_name)
        if not file_id:
            raise HTTPException(status_code=404, detail="File not found")
        ref = db.reference(f"current_status/{file_id}")
        current_status = ref.get() or {}
        users = []

        for email, role in current_status.items():
            users.append({
                "email": email,
                "role": role
            })

        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/files/{file_id}/permissions/delete/")
async def revoke_permission(file_name: str, email: str):
    try:
        file_id = get_file_id_by_name(file_name)
        if not file_id:
            raise HTTPException(status_code=404, detail="File not found")
        service = get_drive_service()
        permissions = service.permissions().list(fileId=file_id, fields="permissions(id, emailAddress, role)").execute()
        permission_id = None

        for perm in permissions.get('permissions', []):
            if perm.get('emailAddress') == email:
                permission_id = perm.get('id')
                break

        if not permission_id:
            return {"error": "Permission not found"}

        service.permissions().delete(fileId=file_id, permissionId=permission_id).execute()
        log_permission_change(file_id, email, None, "revoked")
        update_current_status(file_id, email)  # Remove from current status
        return {"message": "Permission revoked"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/users/{email}/revoke_all/")
async def revoke_all_access(email: str):
    try:
        service = get_drive_service()
        ref = db.reference("current_status")
        current_status = ref.get() or {}

        for file_id, permissions in current_status.items():
            if email in permissions:
                try:
                    permissions_list = service.permissions().list(fileId=file_id, fields="permissions(id, emailAddress, role)").execute()
                    permission_id = None
                    for perm in permissions_list.get('permissions', []):
                        if perm.get('emailAddress') == email:
                            permission_id = perm.get('id')
                            break

                    if permission_id:
                        service.permissions().delete(fileId=file_id, permissionId=permission_id).execute()
                        log_permission_change(file_id, email, None, "revoked")
                        update_current_status(file_id, email)  # Remove from current status
                except Exception as e:
                    logging.error(f"Failed to revoke access for file {file_id}: {e}")
                    continue
            update_current_status(file_id, email, "delete")

        return {"message": "Access revoked for all files"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/{email}/file_permissions/")
async def get_user_file_permissions(email: str):
    try:
        service = get_drive_service()
        ref = db.reference("current_status")
        current_status = ref.get() or {}
        user_files = []

        for file_id, permission_entries in current_status.items():
            if isinstance(permission_entries, dict):  # Ensure it's a valid dictionary
                for key, details in permission_entries.items():
                    if isinstance(details, dict) and details.get("email") == email:
                        file_info = service.files().get(fileId=file_id, fields="name").execute()
                        user_files.append({
                            "file_name": file_info.get("name"),
                            "role": details.get("role")
                        })

        return user_files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
