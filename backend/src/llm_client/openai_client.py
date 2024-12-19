import aisuite as ai

from .base import LLMClientTemplate

class OpenAIClient(LLMClientTemplate):

    def _initialize_client(self):
        self.client = ai.Client({"openai": {"api_key": self.api_key}})
        # self.model = "openai:gpt-4o"
        self.model = "openai:gpt-3.5-turbo"

    

from .base import LLMClientTemplate

class OpenAIClient(LLMClientTemplate):

    def _initialize_client(self):
        self.client = ai.Client({"openai": {"api_key": self.api_key}})
        # self.model = "openai:gpt-4o"
        self.model = "openai:gpt-3.5-turbo"

    
    def get_relevance_assessment(self, prompt: str) -> Optional[str]:
        response = self._get_response(MessagePassingInterface(
            system_content = Prompt.get_relevance_assessment_text(),
            user_content = prompt
        ))
        if(response not in ["high", "medium", "low"]):
            raise ValueError("fail to get relevance assessment")
        else:
            return response
