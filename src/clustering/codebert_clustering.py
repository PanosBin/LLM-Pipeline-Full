import logging
from typing import List
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModel
from sklearn.cluster import KMeans
from src.parsers.objects import JavaMethod, JavaClass

logger = logging.getLogger(__name__)

class CodeBERTEmbedder:
    def __init__(self, model_name="microsoft/codebert-base"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.eval()

    def embed(self, code_texts: List[str]) -> torch.Tensor:
        inputs = self.tokenizer(code_texts, padding=True, truncation=True, return_tensors="pt")
        with torch.no_grad():
            outputs = self.model(**inputs)
        embeddings = outputs.last_hidden_state[:, 0, :]
        return embeddings

class CodeBERTClustering:
    def __init__(self, n_clusters=10, model_name="microsoft/codebert-base"):
        self.embedder = CodeBERTEmbedder(model_name)
        self.n_clusters = n_clusters
        self.kmeans = KMeans(n_clusters=n_clusters)
        self.embeddings_ = None
        self.cluster_labels_ = None
        self.centroids_ = None
        self.clusters_ = None

    def cluster(self, methods: List[JavaMethod]) -> None:
        logger.info(f"Starting clustering on {len(methods)} methods...")
        code_texts = [method.code for method in methods]
        embeddings = self.embedder.embed(code_texts)
        embeddings_np = embeddings.cpu().numpy()

        cluster_labels = self.kmeans.fit_predict(embeddings_np)

        clusters = {}
        for method, label in zip(methods, cluster_labels):
            clusters.setdefault(label, []).append(method)

        self.clusters_ = list(clusters.values())
        self.embeddings_ = embeddings_np
        self.cluster_labels_ = cluster_labels
        self.centroids_ = self.kmeans.cluster_centers_
        logger.info(f"Clustering complete. Created {len(self.clusters_)} clusters.")

    def get_clusters(self) -> List[List[JavaMethod]]:
        return self.clusters_

    def get_cluster_embeddings(self) -> List[np.ndarray]:
        cluster_embeddings = []
        for idx, cluster in enumerate(self.clusters_):
            indices = [i for i, label in enumerate(self.cluster_labels_) if label == idx]
            cluster_embeddings.append(self.embeddings_[indices, :])
        return cluster_embeddings

    def get_centroids(self) -> np.ndarray:
        return self.centroids_

    def get_labels(self) -> List[int]:
        return self.cluster_labels_


class CodeBERTClassClustering:
    """
    Cluster Java classes using CodeBERT embeddings.
    This is the NEW approach - clusters classes instead of methods.
    """
    def __init__(self, n_clusters=10, model_name="microsoft/codebert-base"):
        self.embedder = CodeBERTEmbedder(model_name)
        self.n_clusters = n_clusters
        self.kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        self.embeddings_ = None
        self.cluster_labels_ = None
        self.centroids_ = None
        self.clusters_ = None

    def cluster(self, classes: List[JavaClass]) -> None:
        logger.info(f"Starting class clustering on {len(classes)} classes...")
        logger.info("Extracting code texts from classes...")
        code_texts = [cls.code for cls in classes]
        logger.info(f"Generating embeddings for {len(code_texts)} classes...")
        embeddings = self.embedder.embed(code_texts)
        logger.info("Converting embeddings to numpy array...")
        embeddings_np = embeddings.cpu().numpy()

        logger.info(f"Running KMeans clustering with k={self.n_clusters}...")
        cluster_labels = self.kmeans.fit_predict(embeddings_np)

        logger.info("Organizing classes into clusters...")
        clusters = {}
        for cls, label in zip(classes, cluster_labels):
            clusters.setdefault(label, []).append(cls)

        self.clusters_ = list(clusters.values())
        self.embeddings_ = embeddings_np
        self.cluster_labels_ = cluster_labels
        self.centroids_ = self.kmeans.cluster_centers_
        logger.info(f"Class clustering complete. Created {len(self.clusters_)} clusters.")

    def get_clusters(self) -> List[List[JavaClass]]:
        return self.clusters_

    def get_cluster_embeddings(self) -> List[np.ndarray]:
        cluster_embeddings = []
        for idx, cluster in enumerate(self.clusters_):
            indices = [i for i, label in enumerate(self.cluster_labels_) if label == idx]
            cluster_embeddings.append(self.embeddings_[indices, :])
        return cluster_embeddings

    def get_centroids(self) -> np.ndarray:
        return self.centroids_

    def get_labels(self) -> List[int]:
        return self.cluster_labels_
