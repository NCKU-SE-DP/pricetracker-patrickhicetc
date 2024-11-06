from pydantic import BaseModel, Field, AnyHttpUrl

class PromptRequest(BaseModel):
    prompt: str

class NewsSumaryRequestSchema(BaseModel):
    content: str