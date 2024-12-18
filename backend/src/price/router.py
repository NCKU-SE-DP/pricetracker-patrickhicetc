from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
import requests

from ..logger.price_logger import price_logger

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
        if not category and not commodity:
            price_logger.no_parameters_provided()
            raise HTTPException(status_code=400, detail="At least one parameter (category or commodity) must be provided.")
        response = requests.get(
            "https://opendata.ey.gov.tw/api/ConsumerProtection/NecessitiesPrice",
            params={"CategoryName": category, "Name": commodity},
        )
        response.raise_for_status()
        data = response.json()
        if not data:
            price_logger.no_data()
            raise HTTPException(status_code=404, detail="No data found for the given parameters.")
        return data
    except requests.exceptions.RequestException as e:
        price_logger.get_price_failed(str(e))
        raise HTTPException(status_code=502, detail=f"Failed to fetch data from external API: {str(e)}")
    except ValueError as ve:
        price_logger.get_price_failed(str(ve))
        raise HTTPException(status_code=500, detail="Invalid JSON response from the external API.")
    except Exception as e:
        price_logger.get_price_failed(str(e))
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")