# /Users/panagiotisbinikos/Desktop/CB_Thesis/code/LLM-main/CB_N/src/scipts/test_parser.py

import sys
import pathlib

# --- START: PATH CORRECTION ---
# This code block adds the project's root directory to the Python path.
# It ensures that imports starting with 'src.' will always work,
# no matter where you run the script from.

# Get the directory of the current script (e.g., .../src/scipts/)
current_script_path = pathlib.Path(__file__).parent.resolve()

# Traverse up to find the project root directory ('.../CB_N/')
project_root = current_script_path.parent.parent
sys.path.insert(0, str(project_root))

print(f"--- Path Correction ---")
print(f"Project root added to Python path: {project_root}")
print(f"-----------------------\n")
# --- END: PATH CORRECTION ---


# --- The rest of your script ---
import unittest
import logging

# Now this import will work correctly because Python can find the 'src' directory
from CB_N.src.parsers.parsingwdw import TreeSitterParser
from src.parsers.objects import JavaFile, JavaClass, JavaMethod

# ... (rest of your test code)

# Configure logging to see any warnings from the parser
logging.basicConfig(level=logging.INFO)

class TestTreeSitterParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize the parser once for all tests."""
        cls.parser = TreeSitterParser()

    def test_01_parse_clean_code(self):
        """Tests parsing a simple, error-free Java file."""
        print("\n--- Running Test 1: Clean Code ---")
        java_code = """
        package com.example;
        
        public class Calculator {
            public int add(int a, int b) {
                return a + b;
            }
        }
        """
        parsed_file = self.parser.parse_java_file(java_code, "Calculator.java")
        
        self.assertIsInstance(parsed_file, JavaFile)
        self.assertEqual(len(parsed_file.classes), 1)
        
        calculator_class = parsed_file.classes[0]
        self.assertEqual(calculator_class.name, "Calculator")
        self.assertEqual(len(calculator_class.methods), 1)
        
        add_method = calculator_class.methods[0]
        self.assertEqual(add_method.name, "add")
        self.assertEqual(add_method.return_type, "int")
        self.assertEqual(len(add_method.parameters), 2)
        
        print("Test 1 PASSED: Clean code parsed correctly.")

    def test_02_parse_with_syntax_error(self):
        """Tests the parser's resilience to syntax errors."""
        print("\n--- Running Test 2: Code with Syntax Error ---")
        java_code_with_error = """
        public class UserManager {
            public User findUser(int id) {
                return db.find(id);
            }
            
            public void deleteUser(int id) {
                db.delete(id) // ERROR: Missing semicolon
            }
        }
        """
        # The parser should log a warning but not crash.
        parsed_file = self.parser.parse_java_file(java_code_with_error, "UserManager.java")
        
        self.assertIsNotNone(parsed_file)
        self.assertEqual(len(parsed_file.classes), 1)
        # The key test: it should still find both methods.
        self.assertEqual(len(parsed_file.classes[0].methods), 2)
        
        print("Test 2 PASSED: Parser correctly handled a syntax error.")

# This allows the script to be run directly.
if __name__ == '__main__':
    unittest.main()
