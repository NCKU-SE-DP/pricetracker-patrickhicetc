from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
from openai import OpenAI
import requests
from bs4 import BeautifulSoup
import json
from sqlalchemy.exc import SQLAlchemyError
from requests.exceptions import RequestException

from ..auth.dependencies import session_opener
from ..auth.service import authenticate_user_token
from ..model import NewsArticle
from .service import get_article_upvote_details, get_new_info, _id_counter, toggle_upvote, openai_client, anthropic_client
from .schemas import PromptRequest, NewsSumaryRequestSchema, NewsSumaryCustomModelSchema
from ..logger.news_logger import news_logger

router = APIRouter(
    prefix = "/news",
    tags = ["news"],
    responses = {404: {"description": "Not found"}},
)

@router.get("/news")
def read_news(db=Depends(session_opener)):
    """
    read new

    :param db:
    :return:
    """
    try:
        news = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
        if not news:
            news_logger.no_news()
        result = []
        for news in news:
            upvotes, upvoted = get_article_upvote_details(news.id, None, db)
            result.append(
                {**news.__dict__, "upvotes": upvotes, "is_upvoted": upvoted}
            )
        return result
    except SQLAlchemyError as db_error:
        news_logger.read_news_failed(str(db_error))
        raise HTTPException(status_code=500, detail="Database query failed.")
    except Exception as e:
        news_logger.read_news_failed(str(e))
        raise HTTPException(status_code=500, detail=f"Error reading news: {str(e)}")

@router.get("/user_news")
def read_user_news(
        db=Depends(session_opener),
        user=Depends(authenticate_user_token)
):
    try:
        news_articles = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
        if not news_articles:
            news_logger.no_news_for_user()
        articles_with_upvotes = []
        for article in news_articles:
            upvotes, upvoted = get_article_upvote_details(article.id, user.id, db)
            articles_with_upvotes.append(
                {
                    **article.__dict__,
                    "upvotes": upvotes,
                    "is_upvoted": upvoted,
                }
            )
        return articles_with_upvotes
    except SQLAlchemyError as db_error:
        news_logger.fetch_user_news_failed(str(db_error))
        raise HTTPException(status_code=500, detail="Failed to fetch user news from database.")
    except Exception as e:
        news_logger.fetch_user_news_failed(str(e))
        raise HTTPException(status_code=500, detail=f"Error reading user news: {str(e)}")

@router.post("/search_news")
async def search_news(request: PromptRequest):
    prompt = request.prompt
    news_list = []
    keywords = openai_client.extract_keywords(prompt)
    if not keywords:
        news_logger.extract_keywords_failed()
        raise HTTPException(status_code=400, detail="Failed to extract keywords.")
    news_items = get_new_info(keywords, is_initial=False)
    for news in news_items:
        try:
            response = requests.get(news["titleLink"])
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("h1", class_="article-content__title").text
            time = soup.find("time", class_="article-content__time").text
            content_section = soup.find("section", class_="article-content__editor")
            if not title or not time or not content_section:
                news_logger.miss_fields()
            paragraphs = [
                p.text
                for p in content_section.find_all("p")
                if p.text.strip() != "" and "▪" not in p.text
            ]
            detailed_news = {
                "url": news["titleLink"],
                "title": title,
                "time": time,
                "content": paragraphs,
            }
            detailed_news["content"] = " ".join(detailed_news["content"])
            detailed_news["id"] = next(_id_counter)
            news_list.append(detailed_news)
        except RequestException as req_error:
            news_logger.search_news_failed(str(req_error))
        except Exception as e:
            news_logger.search_news_failed(str(e))
    return sorted(news_list, key=lambda x: x["time"], reverse=True)

@router.post("/news_summary")
async def news_summary(
        payload: NewsSumaryRequestSchema, u=Depends(authenticate_user_token)
):
    try:
        response = {}
        completion_result = openai_client.get_summary(payload.content)
        response["summary"] = completion_result["影響"]
        response["reason"] = completion_result["原因"]
        return response
    except Exception as e:
        news_logger.generate_summary_failed(str(e))
        raise HTTPException(status_code=500, detail=f"Error generating summary: {str(e)}")

@router.post("/{article_id}/upvote")
def upvote_article(
        article_id,
        db=Depends(session_opener),
        user=Depends(authenticate_user_token),
):
    try:
        message = toggle_upvote(article_id, user.id, db)
        return {"message": message}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except SQLAlchemyError as db_error:
        news_logger.upvote_article_failed(str(db_error))
        raise HTTPException(status_code=500, detail="Failed to process upvote in database.")
    except Exception as e:
        news_logger.upvote_article_failed(str(e))
        raise HTTPException(status_code=500, detail="Failed to toggle upvote.")

@router.post("/news_summary_custom_model")
async def news_summary_custom_model(
        payload: NewsSumaryCustomModelSchema, u=Depends(authenticate_user_token)
):
    try:
        response = {}
        if payload.ai_model == "anthropic":
            completion_result = anthropic_client.get_summary(payload.content)
        else:
            completion_result = openai_client.get_summary(payload.content)
        response["summary"] = completion_result["影響"]
        response["reason"] = completion_result["原因"]
        return response
    except Exception as e:
        news_logger.generate_custom_model_summary_failed(str(e))
        raise HTTPException(status_code=500, detail=f"Error in custom model summary: {str(e)}")
