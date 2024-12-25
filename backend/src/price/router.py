from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
import requests

from ..logger.logger import logger

router = APIRouter(
    prefix = "/price",
    tags = ["price"],
    responses = {404: {"description": "Not found"}},
)

@router.get("/necessities-price")
def get_necessities_prices(
        category=Query(None), commodity=Query(None)
):
    try:
        response = requests.get(
            "https://opendata.ey.gov.tw/api/ConsumerProtection/NecessitiesPrice",
            params={"CategoryName": category, "Name": commodity},
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to get price: {str(e)}")
        raise HTTPException(status_code=502, detail=f"Failed to fetch data from external API: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to get price: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    if not data:
        logger.info("No data found")
        raise HTTPException(status_code=404, detail="No data found for the given parameters.")
    return data
    