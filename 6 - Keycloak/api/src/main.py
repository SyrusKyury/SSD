from fastapi import FastAPI, APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi_keycloak import FastAPIKeycloak, OIDCUser

app = FastAPI()
prefix_router = APIRouter(prefix="/api")

idp = FastAPIKeycloak(
    server_url="http://keycloakAddress:8080/keycloak",
    client_id="SSDClient",
    client_secret="SdMcfJgScqynGcM8dScBDL4nN9kFRev4",
    admin_client_secret="admin",
    realm="SSDRealm",
    callback_uri="https://localhost/api/home"
)
idp.add_swagger_config(prefix_router)

origins = ['*']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@prefix_router.get("/test")
async def test():
    return {"message": "Hello from FastAPI"}

@prefix_router.get("/user/roles")
def user_roles(user: OIDCUser = Depends(idp.get_current_user)):
    return f'{user.roles}'

app.include_router(prefix_router)