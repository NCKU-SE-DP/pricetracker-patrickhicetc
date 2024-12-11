import aisuite as ai

from .base import LLMClientTemplate

class AnthropicClient(LLMClientTemplate):

    def _initialize_client(self):
        self.client = ai.Client({"anthropic": {"api_key": self.api_key}})
        self.model = "anthropic:claude-3-5-sonnet-20240620"

    