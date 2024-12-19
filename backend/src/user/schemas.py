from pydantic import BaseModel, Field, AnyHttpUrl

class UserAuthSchema(BaseModel):
    username: str
    password: str