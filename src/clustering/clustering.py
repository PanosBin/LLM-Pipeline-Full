from typing import List, Tuple
import logging
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from src.clustering.codebert_clustering import CodeBERTClustering, CodeBERTClassClustering
from src.parsers.objects import JavaMethod, JavaClass

logger = logging.getLogger(__name__)

def find_optimal_k(embeddings_np, min_k=4, max_k=15) -> int:
    # Double check that min_k is actually used here
    best_k = min_k
    best_score = -1
    
    # If the log shows k=2, this range is being called with min_k=2 elsewhere
    for k in range(min_k, max_k + 1):
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = kmeans.fit_predict(embeddings_np)
        score = silhouette_score(embeddings_np, labels)
        logger.info(f"k={k} | Silhouette Score={score:.3f}")
        
        if score > best_score:
            best_score = score
            best_k = k
            
    logger.info(f"Best number of clusters determined (min {min_k}): {best_k}")
    return best_k

def cluster_methods_semantically(parsed_files: List) -> Tuple[List[List[JavaMethod]], CodeBERTClustering]:
    """Legacy method clustering (kept for backward compatibility)"""
    all_methods = [
        method for file in parsed_files
        for cls in file.classes
        for method in cls.methods
    ]

    if not all_methods:
        logger.warning("No methods found to cluster.")
        return [], None

    # Embed methods
    embedder = CodeBERTClustering()
    code_texts = [method.code for method in all_methods]
    embeddings = embedder.embedder.embed(code_texts).cpu().numpy()

    # Find best k with silhouette
    optimal_k = find_optimal_k(embeddings)
    logger.info(f"Clustering with optimal number of clusters: {optimal_k}")

    # Cluster with optimal k
    codebert_clusterer = CodeBERTClustering(n_clusters=optimal_k)
    codebert_clusterer.cluster(all_methods)
    clusters = codebert_clusterer.get_clusters()

    return clusters, codebert_clusterer

def cluster_classes_semantically(parsed_files: List) -> Tuple[List[List[JavaClass]], CodeBERTClassClustering]:
    """
    Cluster classes semantically using CodeBERT embeddings.
    This is the NEW approach recommended by supervisor.
    """
    all_classes = [
        cls for file in parsed_files
        for cls in file.classes
    ]

    if not all_classes:
        logger.warning("No classes found to cluster.")
        return [], None

    logger.info(f"Found {len(all_classes)} classes to cluster")

    # Embed classes
    embedder = CodeBERTClassClustering()
    code_texts = [cls.code for cls in all_classes]
    embeddings = embedder.embedder.embed(code_texts).cpu().numpy()

    # Find best k with silhouette
    optimal_k = find_optimal_k(embeddings, min_k=2, max_k=min(15, len(all_classes)-1))
    logger.info(f"Clustering classes with optimal number of clusters: {optimal_k}")

    # Cluster with optimal k
    codebert_clusterer = CodeBERTClassClustering(n_clusters=optimal_k)
    codebert_clusterer.cluster(all_classes)
    clusters = codebert_clusterer.get_clusters()

    logger.info(f"Created {len(clusters)} class clusters")
    for idx, cluster in enumerate(clusters):
        logger.info(f"  Cluster {idx+1}: {len(cluster)} classes")

    return clusters, codebert_clusterer

