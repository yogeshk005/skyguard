from pydantic import BaseModel, Field
from typing import Optional, List

class RegisterIn(BaseModel):
    email: str = Field(min_length=5,max_length=254)
    password: str = Field(min_length=10, max_length=200)
class LoginIn(BaseModel):
    email: str = Field(min_length=5,max_length=254)
    password: str
class ProjectIn(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    root_label: Optional[str] = None
    description: str = Field(default='',max_length=1000)
    project_type: str = Field(default='application',max_length=60)
    primary_language: str = Field(default='',max_length=60)
class FindingIn(BaseModel):
    fingerprint: str = Field(min_length=1,max_length=128)
    title: str = Field(min_length=1,max_length=300)
    severity: str = 'MEDIUM'
    category: str = 'STATIC_ANALYSIS'
    message: str = Field(max_length=6000)
    file_path: Optional[str] = Field(default=None,max_length=1000)
    line: Optional[int] = Field(default=None,ge=1)
    column: Optional[int] = Field(default=None,ge=1)
    analyzer: Optional[str] = Field(default=None,max_length=120)
    code_snippet: Optional[str] = Field(default=None,max_length=6000)
class BulkFindings(BaseModel):
    project_id: str
    findings: List[FindingIn] = Field(max_length=20000)
    files_scanned: int = Field(default=0,ge=0)
class ContextFileIn(BaseModel):
    path: str = Field(min_length=1,max_length=1000)
    content: str = Field(max_length=1_000_000)
    sha256: str = Field(min_length=64,max_length=64)
class ContextSync(BaseModel):
    files: List[ContextFileIn] = Field(max_length=5000)
    paths: List[str] = Field(max_length=5000)
    complete: bool = False
class StatusIn(BaseModel):
    status: str
class RuntimeLogIn(BaseModel):
    level: str = 'ERROR'
    message: str = Field(min_length=1,max_length=6000)
    stack_trace: Optional[str] = Field(default=None,max_length=12000)
    file_path: Optional[str] = Field(default=None,max_length=1000)
    line: Optional[int] = Field(default=None,ge=1)
