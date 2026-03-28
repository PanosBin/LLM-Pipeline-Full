# src/parsers/parsing.py

import logging
from typing import List
import os

from tree_sitter import Language, Parser, Node
from .objects import JavaClass, JavaMethod, JavaParameter, Position, JavaFile

logger = logging.getLogger(__name__)

# --- LANGUAGE LOADING AND COMPILATION ---
LIB_PATH = "build/languages.so"

if not os.path.exists(LIB_PATH):
    print("Language library not found. Compiling Java grammar...")
    # This requires 'tree-sitter-java' to be cloned in your project root
    Language.build_library(LIB_PATH, ["tree-sitter-java"])
    print(f"Language library compiled and saved to: {LIB_PATH}")

JAVA_LANGUAGE = Language(LIB_PATH, "java")

class TreeSitterParser:
    """A robust Java parser using Tree-sitter for detailed and accurate CST extraction."""

    def __init__(self):
        """Initializes the parser and sets the language to Java."""
        self.parser = Parser()
        self.parser.set_language(JAVA_LANGUAGE)

    def _get_node_text(self, node: Node) -> str:
        """Helper to safely decode a Tree-sitter node's text."""
        return node.text.decode('utf8')

    def _create_position(self, node: Node) -> Position:
        """Helper to create a Position object from a node."""
        return Position(
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            start_column=node.start_point[1],
            end_column=node.end_point[1]
        )

    def _extract_parameters(self, params_node: Node) -> List[JavaParameter]:
        """Extracts all formal parameters from a method's 'formal_parameters' node."""
        parameters = []
        param_query = JAVA_LANGUAGE.query("(formal_parameter type: (_) @type name: (identifier) @name)")
        captures = param_query.captures(params_node)
        
        param_map = {}
        for node, name in captures:
            param_id = node.parent.id
            if param_id not in param_map:
                param_map[param_id] = {}
            param_map[param_id][name] = self._get_node_text(node)

        for _, details in param_map.items():
            parameters.append(JavaParameter(name=details.get('name', 'unknown'), type=details.get('type', 'unknown')))
            
        return parameters

    def parse_java_file(self, source_code: str, file_path: str) -> JavaFile:
        """Parses an entire Java file and returns a structured JavaFile object."""
        tree = self.parser.parse(bytes(source_code, "utf8"))
        root_node = tree.root_node
        
        if root_node.has_error:
            logger.warning(f"Syntax errors detected in {file_path}. Parsing will continue but may be incomplete.")

        java_file = JavaFile(path=file_path, code=source_code)
        
        class_query = JAVA_LANGUAGE.query("(class_declaration) @class")
        
        for class_node, _ in class_query.captures(root_node):
            class_name_node = class_node.child_by_field_name('name')
            if not class_name_node: continue
            
            java_class = JavaClass(
                parent_file=java_file,
                name=self._get_node_text(class_name_node),
                position=self._create_position(class_node),
                code=self._get_node_text(class_node)
            )
            
            class_body_node = class_node.child_by_field_name('body')
            if not class_body_node: continue

            # --- CORRECTED METHOD QUERY ---
            # This query is simpler and more reliable. It just finds all method_declaration nodes.
            method_query = JAVA_LANGUAGE.query("(method_declaration) @method")
            
            methods_in_class = []
            for method_node, _ in method_query.captures(class_body_node):
                # Use child_by_field_name for reliable access to parts of the method
                method_name_node = method_node.child_by_field_name('name')
                return_type_node = method_node.child_by_field_name('type')
                parameters_node = method_node.child_by_field_name('parameters')
                
                if not method_name_node: continue

                methods_in_class.append(JavaMethod(
                    parent=java_class,
                    name=self._get_node_text(method_name_node),
                    # Handle void methods where return_type_node is None
                    return_type=self._get_node_text(return_type_node) if return_type_node else "void",
                    parameters=self._extract_parameters(parameters_node) if parameters_node else [],
                    position=self._create_position(method_node),
                    code=self._get_node_text(method_node)
                ))

            java_class.methods = methods_in_class
            java_file.classes.append(java_class)
            
        return java_file
