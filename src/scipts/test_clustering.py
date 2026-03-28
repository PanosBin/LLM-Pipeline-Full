import sys
import pathlib

# Add the project root directory to sys.path dynamically
project_root = pathlib.Path(__file__).parent.parent.parent.resolve()
sys.path.insert(0, str(project_root))

# Now imports from 'src' will work
from src.clustering.codebert_clustering import CodeBERTClustering
from src.parsers.objects import JavaMethod,Position,JavaParameter

# ... rest of your test script ...
import logging
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def make_dummy_method(code: str, name: str="dummy", return_type: str="void") -> JavaMethod:
    pos = Position(start_line=1, end_line=10, start_column=0, end_column=0)
    params = [JavaParameter(name="param1", type="int")]
    # Provide None or a dummy for the parent field
    return JavaMethod(file=None, name=name, return_type=return_type, parameters=params, position=pos, code=code, parent=None)

def test_codebert_clustering():
    methods = [
        make_dummy_method("public void foo() { int x = 5; }", name="foo"),
        make_dummy_method("public void bar() { int y = 10; }", name="bar"),
        make_dummy_method("public int add(int a, int b) { return a + b; }", name="add", return_type="int"),
        make_dummy_method("public int sum(int a, int b) { return a + b; }", name="sum", return_type="int"),
    ]

    clusterer = CodeBERTClustering(n_clusters=2)
    clusterer.cluster(methods)
    clusters = clusterer.get_clusters()

    print("Clusters formed:")
    for i, cluster in enumerate(clusters):
        print(f"Cluster {i+1}:")
        for m in cluster:
            print(f"  Method name: {m.name}")
    print("Test completed.")

if __name__ == "__main__":
    test_codebert_clustering()
