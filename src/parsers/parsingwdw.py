# src/parsers/parsing.py

import logging
from typing import List
import os

from tree_sitter import Language, Parser, Node
from .objects import JavaClass, JavaMethod, JavaParameter, Position, JavaFile

logger = logging.getLogger(__name__)

LIB_PATH = "build/languages.so"
if not os.path.exists(LIB_PATH):
    Language.build_library(LIB_PATH, ["tree-sitter-java"])
JAVA_LANGUAGE = Language(LIB_PATH, "java")

class TreeSitterParser:
    def __init__(self):
        self.parser = Parser()
        self.parser.set_language(JAVA_LANGUAGE)

    def _get_node_text(self, node: Node) -> str:
        return node.text.decode('utf8')

    def _create_position(self, node: Node) -> Position:
        return Position(
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            start_column=node.start_point[1],
            end_column=node.end_point[1]
        )

    def _extract_parameters(self, params_node: Node) -> List[JavaParameter]:
        parameters = []
        query = JAVA_LANGUAGE.query("""
            (formal_parameter
                type: (_) @type
                name: (identifier) @name
            )
        """)
        captures = query.captures(params_node)
        param_map = {}
        for node, name in captures:
            pid = node.parent.id
            param_map.setdefault(pid, {})[name] = self._get_node_text(node)
        for details in param_map.values():
            parameters.append(JavaParameter(
                name=details.get("name", "unknown"),
                type=details.get("type", "unknown")
            ))
        return parameters

    def parse_java_file(self, source_code: str, file_path: str) -> JavaFile:
        tree = self.parser.parse(source_code.encode("utf8"))
        root = tree.root_node
        java_file = JavaFile(path=file_path, code=source_code)

        # Match classes, interfaces, enums, annotations
        class_query = JAVA_LANGUAGE.query("""
            (class_declaration) @class
            (interface_declaration) @class
            (enum_declaration) @class
            (annotation_type_declaration) @class
        """)
        class_captures = class_query.captures(root)

        for class_node, _ in class_captures:
            name_node = class_node.child_by_field_name("name")
            if not name_node:
                continue

            java_class = JavaClass(
                parent_file=java_file,
                name=self._get_node_text(name_node),
                position=self._create_position(class_node),
                code=self._get_node_text(class_node)
            )

            body_node = class_node.child_by_field_name("body")
            if body_node is None:
                java_file.classes.append(java_class)
                continue

            # Method declarations
            method_query = JAVA_LANGUAGE.query("(method_declaration) @method")
            for method_node, _ in method_query.captures(body_node):
                m_name = method_node.child_by_field_name("name")
                m_type = method_node.child_by_field_name("type")
                params = method_node.child_by_field_name("parameters")
                if m_name:
                    java_class.methods.append(JavaMethod(
                        parent=java_class,
                        name=self._get_node_text(m_name),
                        return_type=self._get_node_text(m_type) if m_type else "void",
                        parameters=self._extract_parameters(params) if params else [],
                        position=self._create_position(method_node),
                        code=self._get_node_text(method_node)
                    ))

            # Constructor declarations
            ctor_query = JAVA_LANGUAGE.query("(constructor_declaration) @ctor")
            for ctor_node, _ in ctor_query.captures(body_node):
                params = ctor_node.child_by_field_name("parameters")
                java_class.methods.append(JavaMethod(
                    parent=java_class,
                    name=java_class.name,
                    return_type=java_class.name,
                    parameters=self._extract_parameters(params) if params else [],
                    position=self._create_position(ctor_node),
                    code=self._get_node_text(ctor_node)
                ))

            java_file.classes.append(java_class)

        return java_file
