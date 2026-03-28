"""
Per-file clustering approach.
Instead of clustering ALL classes globally, we cluster classes WITHIN EACH FILE.
This provides more specific, context-aware summaries.
"""

from typing import List, Dict, Tuple
import logging
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from src.clustering.codebert_clustering import CodeBERTEmbedder
from src.parsers.objects import JavaClass, JavaFile
import numpy as np

logger = logging.getLogger(__name__)


def find_optimal_k_for_file(embeddings_np, min_k=2, max_k=5) -> int:
    """
    Find optimal k for a single file.
    Uses smaller max_k since files have fewer classes.
    """
    n_samples = len(embeddings_np)
    if n_samples < 2:
        return 1

    if n_samples <= min_k:
        return n_samples

    max_k = min(max_k, n_samples - 1)

    best_k = min_k
    best_score = -1

    for k in range(min_k, max_k + 1):
        kmeans = KMeans(n_clusters=k, random_state=42)
        labels = kmeans.fit_predict(embeddings_np)
        score = silhouette_score(embeddings_np, labels)
        logger.debug(f"  k={k} | Silhouette Score={score:.3f}")
        if score > best_score:
            best_score = score
            best_k = k

    return best_k


def cluster_classes_in_file(java_file: JavaFile, embedder: CodeBERTEmbedder) -> Tuple[List[List[JavaClass]], int]:
    """
    Cluster classes within a single file.

    Returns:
        - List of clusters (each cluster is a list of JavaClass objects)
        - Optimal k used
    """
    classes = java_file.classes

    if len(classes) == 0:
        logger.debug(f"File {java_file.path} has no classes")
        return [], 0

    if len(classes) == 1:
        logger.debug(f"File {java_file.path} has only 1 class - no clustering needed")
        return [classes], 1

    # Generate embeddings
    code_texts = [cls.code for cls in classes]
    embeddings = embedder.embed(code_texts)
    embeddings_np = embeddings.cpu().numpy()

    # Find optimal k for this file
    optimal_k = find_optimal_k_for_file(embeddings_np, min_k=2, max_k=min(5, len(classes)))

    # Cluster
    kmeans = KMeans(n_clusters=optimal_k, random_state=42)
    labels = kmeans.fit_predict(embeddings_np)

    # Organize into clusters
    clusters_dict = {}
    for cls, label in zip(classes, labels):
        clusters_dict.setdefault(label, []).append(cls)

    clusters = list(clusters_dict.values())

    return clusters, optimal_k


def cluster_all_files(parsed_files: List[JavaFile]) -> Dict[str, List[List[JavaClass]]]:
    """
    Cluster classes within EACH file separately.

    Returns:
        Dictionary mapping file path to list of clusters in that file.
    """
    logger.info(f"Starting PER-FILE clustering for {len(parsed_files)} files...")

    embedder = CodeBERTEmbedder()
    file_clusters = {}

    total_files_with_classes = 0
    total_clusters = 0
    total_classes = 0

    for java_file in parsed_files:
        if not java_file.classes:
            continue

        total_files_with_classes += 1
        total_classes += len(java_file.classes)

        file_path = java_file.path
        logger.info(f"Clustering file: {file_path} ({len(java_file.classes)} classes)")

        clusters, optimal_k = cluster_classes_in_file(java_file, embedder)
        file_clusters[file_path] = clusters
        total_clusters += len(clusters)

        logger.info(f"  ✓ Created {len(clusters)} clusters (k={optimal_k})")

    logger.info("="*60)
    logger.info("Per-file clustering complete!")
    logger.info(f"  Files processed: {total_files_with_classes}")
    logger.info(f"  Total classes: {total_classes}")
    logger.info(f"  Total clusters: {total_clusters}")
    logger.info(f"  Avg clusters per file: {total_clusters/total_files_with_classes:.1f}")
    logger.info("="*60)

    return file_clusters
