from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
from openai import OpenAI
import requests
from bs4 import BeautifulSoup
import json

from ..auth.dependencies import session_opener
from ..auth.service import authenticate_user_token
from ..model import NewsArticle
from .service import get_article_upvote_details, get_new_info, _id_counter, toggle_upvote, openai_client
from ..user.schemas import PromptRequest, NewsSumaryRequestSchema

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
    news = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
    result = []
    for news in news:
        upvotes, upvoted = get_article_upvote_details(news.id, None, db)
        result.append(
            {**news.__dict__, "upvotes": upvotes, "is_upvoted": upvoted}
        )
    return result

@router.get("/user_news")
def read_user_news(
        db=Depends(session_opener),
        user=Depends(authenticate_user_token)
):
    news_articles = db.query(NewsArticle).order_by(NewsArticle.time.desc()).all()
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

@router.post("/search_news")
async def search_news(request: PromptRequest):
    prompt = request.prompt
    news_list = []
    keywords = openai_client.extract_keywords(prompt)
    news_items = get_new_info(keywords, is_initial=False)
    for news in news_items:
        try:
            response = requests.get(news["titleLink"])
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("h1", class_="article-content__title").text
            time = soup.find("time", class_="article-content__time").text
            content_section = soup.find("section", class_="article-content__editor")
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
        except Exception as error:
            print(error)
    return sorted(news_list, key=lambda x: x["time"], reverse=True)

@router.post("/news_summary")
async def news_summary(
        payload: NewsSumaryRequestSchema, u=Depends(authenticate_user_token)
):
    response = {}
    completion_result = openai_client.get_summary(payload.content)
    response["summary"] = completion_result["影響"]
    response["reason"] = completion_result["原因"]
    return response

@router.post("/{article_id}/upvote")
def upvote_article(
        article_id,
        db=Depends(session_opener),
        user=Depends(authenticate_user_token),
):
    message = toggle_upvote(article_id, user.id, db)
    return {"message": message}