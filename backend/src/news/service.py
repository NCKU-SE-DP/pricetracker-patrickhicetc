from sqlalchemy.orm import Session
import requests
from urllib.parse import quote
from openai import OpenAI
from bs4 import BeautifulSoup
import json
import itertools
from sqlalchemy import delete, insert, select

from ..model import NewsArticle, user_news_association_table
from ..crawler.udn_crawler import UDNCrawler
from ..crawler.crawler_base import NewsWithSummary

udn_crawler = UDNCrawler()
_id_counter = itertools.count(start=1000000)

def add_new(news_data):
    """
    add new to db
    :param news_data: news info
    :return:
    """
    session = Session()
    session.add(NewsArticle(
        url=news_data.url,
        title=news_data.title,
        time=news_data.time,
        content=news_data.content,  # 將內容list轉換為字串
        summary=news_data.summary,
        reason=news_data.reason,
    ))
    session.commit()
    session.close()

def get_new_info(search_term, is_initial=False):
    if is_initial:
        return udn_crawler.startup(search_term)
    else:
        return udn_crawler.get_headline(search_term, page = 1)

def get_new(is_initial=False):
    news_data = get_new_info("價格", is_initial=is_initial)
    for news in news_data:
        title = news.title
        messagesToAi = [
            {
                "role": "system",
                "content": "你是一個關聯度評估機器人，請評估新聞標題是否與「民生用品的價格變化」相關，並給予'high'、'medium'、'low'評價。(僅需回答'high'、'medium'、'low'三個詞之一)",
            },
            {"role": "user", "content": f"{title}"},
        ]
        ai_response = OpenAI(api_key="xxx").chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messagesToAi,
        )
        relevance = ai_response.choices[0].message.content
        if relevance == "high":
            news_details = udn_crawler.parse(news.url)
            news_details = NewsWithSummary(
                title=news_details.title,
                url=news_details.url,
                time=news_details.time,
                content=news_details.content,
                summary=completion_result["影響"],
                reason=completion_result["原因"],
            )
            messagesToAi = [
                {
                    "role": "system",
                    "content": "你是一個新聞摘要生成機器人，請統整新聞中提及的影響及主要原因 (影響、原因各50個字，請以json格式回答 {'影響': '...', '原因': '...'})",
                },
                {"role": "user", "content": " ".join(news_details.content)},
            ]

            completion = OpenAI(api_key="xxx").chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messagesToAi,
            )
            completion_result = completion.choices[0].message.content
            completion_result = json.loads(completion_result)
            news_details.summary = completion_result["影響"]
            news_details.reason = completion_result["原因"]
            add_new(news_details)

def get_article_upvote_details(article_id, user_id, db):
    upvote_count = (
        db.query(user_news_association_table)
        .filter_by(news_articles_id=article_id)
        .count()
    )
    voted = False
    if user_id:
        voted = (
                db.query(user_news_association_table)
                .filter_by(news_articles_id=article_id, user_id=user_id)
                .first()
                is not None
        )
    return upvote_count, voted

def toggle_upvote(news_id, user_id, db):
    existing_upvote = db.execute(
        select(user_news_association_table).where(
            user_news_association_table.c.news_articles_id == news_id,
            user_news_association_table.c.user_id == user_id,
        )
    ).scalar()

    if existing_upvote:
        delete_stmt = delete(user_news_association_table).where(
            user_news_association_table.c.news_articles_id == news_id,
            user_news_association_table.c.user_id == user_id,
        )
        db.execute(delete_stmt)
        db.commit()
        return "Upvote removed"
    else:
        insert_stmt = insert(user_news_association_table).values(
            news_articles_id=news_id, user_id=user_id
        )
        db.execute(insert_stmt)
        db.commit()
        return "Article upvoted"
    
def news_exists(article_id, db: Session):
    return db.query(NewsArticle).filter_by(id=article_id).first() is not None