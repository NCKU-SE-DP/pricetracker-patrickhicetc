from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
import requests

router = APIRouter(
    prefix = "/price",
    tags = ["price"],
    responses = {404: {"description": "Not found"}},
)

@router.get("/necessities-price")
def get_necessities_prices(
        category=Query(None), commodity=Query(None)
):
    return requests.get(
        "https://opendata.ey.gov.tw/api/ConsumerProtection/NecessitiesPrice",
        params={"CategoryName": category, "Name": commodity},
    ).json()