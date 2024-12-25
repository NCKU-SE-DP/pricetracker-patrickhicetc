import aisuite as ai

from .base import LLMClientTemplate

class OpenAIClient(LLMClientTemplate):

    def _initialize_client(self):
        self.client = ai.Client({"openai": {"api_key": self.api_key}})
        # self.model = "openai:gpt-4o"
        self.model = "openai:gpt-3.5-turbo" 