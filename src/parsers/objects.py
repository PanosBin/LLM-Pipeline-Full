# src/objects.py

from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# This helper function can be moved to a utils.py file if you have one
def get_method_signature_to_str(name: str, return_type: str, parameters: List[JavaParameter]) -> str:
    """Helper to create a standardized string representation of a method signature."""
    param_str = ", ".join([f"{p.type} {p.name}" for p in parameters])
    return f"{return_type} {name}({param_str})"

class Position(BaseModel):
    """Represents a code span with line and column numbers."""
    start_line: int
    end_line: int
    start_column: int
    end_column: int

    def to_dict(self) -> Dict[str, int]:
        return self.model_dump()

class JavaParameter(BaseModel):
    """Represents a Java method parameter with a name and type."""
    name: str
    type: str = "unknown"

    def to_dict(self) -> Dict[str, str]:
        return self.model_dump()

class JavaMethod(BaseModel):
    """Represents a parsed Java method with its attributes and metadata."""
    parent: Any  # To avoid circular dependency issues, can be refined later
    name: str
    return_type: str
    # Use 'alias' to gracefully handle the 'paremeters' typo from the original file
    parameters: List[JavaParameter] = Field(default_factory=list, alias="paremeters")
    position: Position
    code: str
    summary: str = ""
    cluster_summary: str = ""
    parent_cluster: Optional[Any] = None
    is_false_positive: Optional[bool] = None
    is_vulnerable: bool = False
    vulnerability_meta: Optional[Dict[str, Any]] = None
    vulnerability: Optional[str] = None
    matched_string: str = ""

    class Config:
        validate_by_name = True # Use the new name for Pydantic V2

    @property
    def signature(self) -> str:
        """Dynamically generates the full method signature string."""
        return get_method_signature_to_str(self.name, self.return_type, self.parameters)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the object to a dictionary, excluding circular references."""
        return self.model_dump(exclude={'parent', 'parent_cluster'})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JavaMethod):
            return NotImplemented
        return self.parent.name == other.parent.name and self.signature == other.signature

    def __hash__(self) -> int:
        return hash((self.parent.name, self.signature))

class JavaClass(BaseModel):
    """Represents a parsed Java class and contains a list of its methods."""
    parent_file: Any
    name: str
    position: Position
    code: str
    summary: str = ""
    methods: List[JavaMethod] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(exclude={'parent_file'})

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JavaClass):
            return NotImplemented
        return self.name == other.name and self.methods == other.methods

    def __hash__(self) -> int:
        return hash((self.name, tuple(self.methods)))

class JavaFile(BaseModel):
    """Represents a single parsed Java file and contains a list of its classes."""
    path: str
    code: str
    classes: List[JavaClass] = Field(default_factory=list)

    def get_all_methods(self) -> List[JavaMethod]:
        """Returns a flat list of all methods contained within this file."""
        return [method for cls in self.classes for method in cls.methods]

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

