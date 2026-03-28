"""
File-context-aware summarizer.
Generates specific summaries showing how methods are used within their file context.
"""

import re
import logging
from typing import List, Set, Dict
from src.parsers.objects import JavaClass, JavaMethod, JavaFile

logger = logging.getLogger(__name__)


class FileContextSummarizer:
    """
    Summarizer that analyzes method usage within file context.
    Provides more specific summaries than global analysis.
    """

    def __init__(self):
        pass

    def extract_method_calls_in_file(self, java_file: JavaFile) -> Dict[str, Set[str]]:
        """
        For each method in the file, extract what OTHER methods it calls within the same file.

        Returns:
            Dict mapping "ClassName.methodName" -> Set of method names called
        """
        # Get all method names in this file
        all_method_names = set()
        for cls in java_file.classes:
            for method in cls.methods:
                all_method_names.add(method.name)

        # For each method, find which other methods it calls
        method_calls = {}

        for cls in java_file.classes:
            for method in cls.methods:
                method_key = f"{cls.name}.{method.name}"
                calls = self._extract_method_calls_from_code(method.code, all_method_names)
                # Remove self-call
                calls.discard(method.name)
                method_calls[method_key] = calls

        return method_calls

    def _extract_method_calls_from_code(self, code: str, valid_method_names: Set[str]) -> Set[str]:
        """Extract method calls that match valid method names in the file."""
        # Pattern to match method calls
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.findall(pattern, code)

        # Filter to only valid method names in this file
        calls = set()
        for match in matches:
            if match in valid_method_names:
                # Skip common Java keywords
                if match not in ['if', 'for', 'while', 'switch', 'catch', 'new', 'return', 'throw']:
                    calls.add(match)

        return calls

    def get_method_callers(self, java_file: JavaFile, target_method_name: str) -> Set[str]:
        """
        Find which methods in the file CALL the target method.
        """
        callers = set()

        for cls in java_file.classes:
            for method in cls.methods:
                if target_method_name in method.code:
                    # Simple check - ideally would use AST
                    pattern = rf'\b{re.escape(target_method_name)}\s*\('
                    if re.search(pattern, method.code):
                        callers.add(f"{cls.name}.{method.name}")

        return callers

    def summarize_method_in_file_context(self, method: JavaMethod, java_class: JavaClass, java_file: JavaFile) -> str:
        """
        Generate a specific summary for a method showing its usage within the file.
        """
        method_key = f"{java_class.name}.{method.name}"

        # Get method call graph within file
        method_calls = self.extract_method_calls_in_file(java_file)
        calls_made = method_calls.get(method_key, set())
        calls_received = self.get_method_callers(java_file, method.name)

        # Build context-aware summary
        summary_parts = []

        # Basic description
        summary_parts.append(f"Method '{method.name}' in class '{java_class.name}'")

        # What it does (simplified from code)
        if method.return_type and method.return_type != "void":
            summary_parts.append(f"returns {method.return_type}")

        # Parameters
        if method.parameters:
            param_str = ", ".join([f"{p.type} {p.name}" for p in method.parameters])
            summary_parts.append(f"with parameters: {param_str}")

        # File context - what it calls
        if calls_made:
            calls_str = ", ".join(sorted(calls_made)[:5])  # Limit to 5 for readability
            if len(calls_made) > 5:
                calls_str += f" and {len(calls_made)-5} more"
            summary_parts.append(f"Calls methods: {calls_str}")

        # File context - who calls it
        if calls_received:
            callers_str = ", ".join(sorted(calls_received)[:3])
            if len(calls_received) > 3:
                callers_str += f" and {len(calls_received)-3} more"
            summary_parts.append(f"Called by: {callers_str}")

        return ". ".join(summary_parts) + "."

    def summarize_class_in_file_context(self, java_class: JavaClass, java_file: JavaFile, cluster_classes: List[JavaClass]) -> str:
        """
        Generate a specific summary for a class showing its role in the file.
        """
        # Count methods
        num_methods = len(java_class.methods)

        # Get method names
        method_names = [m.name for m in java_class.methods]

        # Check if this class is central (called by many methods)
        all_calls = self.extract_method_calls_in_file(java_file)
        times_called = sum(1 for calls in all_calls.values()
                           for call in calls
                           if any(call == m.name for m in java_class.methods))

        # Build summary
        summary_parts = []
        summary_parts.append(f"Class '{java_class.name}' with {num_methods} methods")

        if method_names:
            method_list = ", ".join(method_names[:5])
            if len(method_names) > 5:
                method_list += f" and {len(method_names)-5} more"
            summary_parts.append(f"Methods: {method_list}")

        # Clustering info
        if cluster_classes and len(cluster_classes) > 1:
            cluster_class_names = [c.name for c in cluster_classes if c.name != java_class.name]
            if cluster_class_names:
                cluster_str = ", ".join(cluster_class_names[:3])
                summary_parts.append(f"Semantically similar to: {cluster_str}")

        # Usage frequency
        if times_called > 5:
            summary_parts.append(f"Frequently used ({times_called} calls from other methods)")
        elif times_called > 0:
            summary_parts.append(f"Used {times_called} times by other methods")

        return ". ".join(summary_parts) + "."

    def summarize_file_cluster(self, cluster: List[JavaClass], file_path: str) -> str:
        """
        Summarize a cluster of classes within a specific file.
        """
        if not cluster:
            return "Empty cluster"

        class_names = [cls.name for cls in cluster]
        total_methods = sum(len(cls.methods) for cls in cluster)

        summary = f"Cluster in file '{file_path.split('/')[-1]}' with {len(cluster)} classes: {', '.join(class_names)}. "
        summary += f"Total of {total_methods} methods. "

        # Find common patterns
        all_method_names = []
        for cls in cluster:
            all_method_names.extend([m.name for m in cls.methods])

        # Find most common method names (might indicate similar functionality)
        from collections import Counter
        common_methods = Counter(all_method_names).most_common(3)
        if common_methods and common_methods[0][1] > 1:
            common_names = [name for name, count in common_methods if count > 1]
            if common_names:
                summary += f"Common method patterns: {', '.join(common_names)}."

        return summary
