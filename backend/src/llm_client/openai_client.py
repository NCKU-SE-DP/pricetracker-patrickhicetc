import aisuite as ai

from .base import LLMClientTemplate

class OpenAIClient(LLMClientTemplate):

    def _initialize_client(self):
        self.client = ai.Client({"openai": {"api_key": self.api_key}})
        # self.model = "openai:gpt-4o"
        self.model = "openai:gpt-3.5-turbo"

    
=======
import json
import openai as OpenAI
from typing import Optional

from .base import LLMClientBase, MessagePassingInterface
from .prompt import Prompt

class OpenAIClient(LLMClientBase):
    def __init__(self, _api_key: str):
        try:
            OpenAI.api_key = _api_key
            self.openai_client = OpenAI
        except Exception as error:
            raise ValueError(f"fail to initialize OpenAI client: {error}")

    def _get_response(self, prompt: MessagePassingInterface) -> str:
        try:
            completion = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=prompt.to_dict,
            )
            return completion.choices[0].message.content
        except Exception as error:
            print(f"fail to get response: {error}")
            return ""
    def extract_keywords(self, prompt: str) -> str:
        return self._get_response(MessagePassingInterface(
            system_content = Prompt.extract_keywords_text(),
            user_content = prompt
        ))
    
    def get_summary(self, prompt: str) -> Optional[dict[str, str]]:
        print(prompt)
        response = self._get_response(MessagePassingInterface(
            system_content = Prompt.get_summary_text(),
            user_content = prompt
        ))
        print(response)
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
