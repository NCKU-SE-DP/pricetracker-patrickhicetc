import json
import abc

from pydantic import BaseModel, Field
from pydantic import BaseModel, Field
from abc import ABC, abstractmethod
from typing import Optional

from .prompt import Prompt

class MessagePassingInterface(BaseModel):
    system_content: str = Field(...)
    user_content: str = Field(...)
    
    @property
    def to_dict(self):
        dic = [
            {"role" : "system", "content" : f"{self.system_content}"},
            {"role" : "user", "content" : f"{self.user_content}"},
        ]
        return dic

class LLMClientBase(metaclass=abc.ABCMeta):
    
    @abc.abstractmethod
    def _get_response(self, prompt: MessagePassingInterface) -> str:
        """
        get response based on prompt
        :param prompt: a list of MessagePassingInterface as messages to AI
        """
        return NotImplemented
    
class LLMClientTemplate(LLMClientBase, ABC):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._initialize_client()

    #initialize client function should be abstract
    @abstractmethod
    def _initialize_client(self):        
        return NotImplemented

    def _get_response(self, prompt: MessagePassingInterface) -> str:
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=prompt.to_dict,
            )
            return completion.choices[0].message.content
        except Exception as error:
            raise ValueError(f"fail to get response: {error}")
    
    def extract_keywords(self, prompt: str) -> str:
        return self._get_response(MessagePassingInterface(
            system_content = Prompt.extract_keywords_text(),
            user_content = prompt
        ))
    
    def get_summary(self, prompt: str) -> Optional[dict[str, str]]:
        
        response = self._get_response(MessagePassingInterface(
            system_content = Prompt.get_summary_text(),
            user_content = prompt
        ))
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            raise ValueError("fail to get summary")
        
    def get_relevance_assessment(self, prompt: str) -> Optional[str]:
        response = self._get_response(MessagePassingInterface(
            system_content = Prompt.get_relevance_assessment_text(),
            user_content = prompt
        ))
        if(response not in ["high", "medium", "low"]):
            raise ValueError("fail to get relevance assessment")
        else:
            return response