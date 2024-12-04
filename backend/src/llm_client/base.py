import abc

from openai import OpenAI
from pydantic import BaseModel, Field


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