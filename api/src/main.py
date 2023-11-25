from fastapi import FastAPI, APIRouter, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = ["http://127.0.0.1"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex='http://127.0.0.1.*',
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
    max_age=3600
)

prefix_router = APIRouter(prefix="/api")


@prefix_router.post("/")
async def test(request: Request):
    return "TEST"

app.include_router(prefix_router)