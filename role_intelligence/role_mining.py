from typing import Dict, List, Optional, Set, Tuple
from uuid import UUID

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from role_intelligence.models import (
    AccessLog,
    Permission,
    Role,
    RoleRecommendation,
    User,
)


class RoleMiner:
    """Mines and optimizes roles using machine learning techniques."""

    def __init__(self, min_cluster_size: int = 3, similarity_threshold: float = 0.7):
        self.min_cluster_size = min_cluster_size
        self.similarity_threshold = similarity_threshold
        self.vectorizer = TfidfVectorizer(
            analyzer="word",
            tokenizer=lambda x: x.split(),
            preprocessor=lambda x: x.lower(),
            token_pattern=None,
        )

    def _create_permission_matrix(
        self, users: List[User], permissions: List[Permission], roles: List[Role]
    ) -> Tuple[np.ndarray, Dict[UUID, int]]:
        """Create a binary matrix of user-permission assignments."""
        # Create mapping of permission IDs to matrix indices
        perm_to_idx = {perm.id: idx for idx, perm in enumerate(permissions)}
        
        # Initialize matrix
        matrix = np.zeros((len(users), len(permissions)))
        
        # Fill matrix based on user roles and permissions
        for user_idx, user in enumerate(users):
            for role_id in user.roles:
                # Find role and its permissions
                role_permissions = next(
                    (r.permissions for r in roles if r.id == role_id), set()
                )
                for perm_id in role_permissions:
                    if perm_id in perm_to_idx:
                        matrix[user_idx, perm_to_idx[perm_id]] = 1
        
        return matrix, perm_to_idx

    def _extract_role_features(
        self, roles: List[Role], permissions: List[Permission]
    ) -> List[str]:
        """Extract text features from roles for similarity analysis."""
        features = []
        for role in roles:
            # Combine role name, description, and permission descriptions
            role_perms = [
                p for p in permissions if p.id in role.permissions
            ]
            perm_descs = " ".join(
                f"{p.level} {p.resource_id}" for p in role_perms
            )
            feature = f"{role.name} {role.description or ''} {perm_descs}"
            features.append(feature)
        return features

    def _find_similar_roles(
        self, roles: List[Role], permissions: List[Permission]
    ) -> List[Tuple[Role, Role, float]]:
        """Find pairs of similar roles using cosine similarity."""
        features = self._extract_role_features(roles, permissions)
        
        # Create TF-IDF matrix
        tfidf_matrix = self.vectorizer.fit_transform(features)
        
        # Calculate cosine similarity
        similarity_matrix = cosine_similarity(tfidf_matrix)
        
        # Find similar role pairs
        similar_pairs = []
        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                similarity = similarity_matrix[i, j]
                if similarity >= self.similarity_threshold:
                    similar_pairs.append((roles[i], roles[j], similarity))
        
        return sorted(similar_pairs, key=lambda x: x[2], reverse=True)

    def _cluster_users_by_permissions(
        self, users: List[User], permissions: List[Permission], roles: List[Role]
    ) -> List[Set[UUID]]:
        """Cluster users based on their permission patterns."""
        matrix, _ = self._create_permission_matrix(users, permissions, roles)
        
        # Use DBSCAN for clustering
        clustering = DBSCAN(
            eps=0.3,
            min_samples=self.min_cluster_size,
            metric="cosine",
        ).fit(matrix)
        
        # Group users by cluster
        clusters: Dict[int, Set[UUID]] = {}
        for user_idx, cluster_id in enumerate(clustering.labels_):
            if cluster_id != -1:  # Skip noise points
                if cluster_id not in clusters:
                    clusters[cluster_id] = set()
                clusters[cluster_id].add(users[user_idx].id)
        
        return list(clusters.values())

    def analyze_roles(
        self,
        roles: List[Role],
        users: List[User],
        permissions: List[Permission],
        access_logs: List[AccessLog],
    ) -> List[RoleRecommendation]:
        """Analyze roles and generate optimization recommendations."""
        recommendations = []

        # Find similar roles that could be merged
        similar_roles = self._find_similar_roles(roles, permissions)
        for role1, role2, similarity in similar_roles:
            if similarity > 0.9:  # Very similar roles
                recommendations.append(
                    RoleRecommendation(
                        role_id=role1.id,
                        action="merge",
                        reason=f"High similarity ({similarity:.2f}) with role '{role2.name}'",
                        suggested_changes={
                            "merge_with": str(role2.id),
                            "new_name": f"{role1.name}_{role2.name}_merged",
                            "combined_permissions": [str(p) for p in role1.permissions.union(role2.permissions)],
                        },
                        confidence_score=similarity,
                    )
                )

        # Analyze role usage patterns
        for role in roles:
            # Get users with this role
            role_users = [u for u in users if role.id in u.roles]
            
            # Get access logs for these users
            role_access_logs = [
                log for log in access_logs
                if log.user_id in {u.id for u in role_users}
            ]
            
            # Calculate permission usage
            used_permissions = {
                log.permission_id
                for log in role_access_logs
                if log.success and log.permission_id in role.permissions
            }
            
            unused_permissions = role.permissions - used_permissions
            
            if unused_permissions:
                recommendations.append(
                    RoleRecommendation(
                        role_id=role.id,
                        action="modify",
                        reason="Unused permissions detected",
                        suggested_changes={
                            "remove_permissions": [str(p) for p in unused_permissions],
                            "reason": "These permissions have not been used in recent access logs",
                        },
                        confidence_score=0.8,
                    )
                )

        # Cluster users to identify potential new roles
        user_clusters = self._cluster_users_by_permissions(users, permissions, roles)
        for cluster in user_clusters:
            if len(cluster) >= self.min_cluster_size:
                # Find common permissions among users in cluster
                cluster_users = [u for u in users if u.id in cluster]
                common_permissions = set.intersection(
                    *[set().union(*(r.permissions for r in roles if r.id in u.roles)) for u in cluster_users]
                )
                
                if common_permissions:
                    recommendations.append(
                        RoleRecommendation(
                            role_id=roles[0].id,  # Use first role as reference
                            action="create",
                            reason=f"New role pattern detected among {len(cluster)} users",
                            suggested_changes={
                                "new_role_name": f"auto_generated_role_{len(recommendations)}",
                                "permissions": [str(p) for p in common_permissions],
                                "assigned_users": [str(u) for u in cluster],
                            },
                            confidence_score=0.7,
                        )
                    )

        return recommendations

    def optimize_role_hierarchy(
        self, roles: List[Role], permissions: List[Permission]
    ) -> List[RoleRecommendation]:
        """Optimize role hierarchy based on permission patterns."""
        recommendations = []

        # Analyze permission inheritance patterns
        for role in roles:
            # Find roles that could be parents based on permission subsets
            potential_parents = []
            for other_role in roles:
                if other_role.id != role.id and other_role.permissions.issuperset(
                    role.permissions
                ):
                    potential_parents.append(
                        (other_role, len(other_role.permissions - role.permissions))
                    )

            # Sort by number of additional permissions
            potential_parents.sort(key=lambda x: x[1])

            if potential_parents:
                best_parent, additional_perms = potential_parents[0]
                if additional_perms <= 5:  # Only recommend if inheritance makes sense
                    recommendations.append(
                        RoleRecommendation(
                            role_id=role.id,
                            action="modify",
                            reason=f"Role '{role.name}' could inherit from '{best_parent.name}'",
                            suggested_changes={
                                "add_parent": str(best_parent.id),
                                "inherited_permissions": [str(p) for p in role.permissions],
                                "additional_permissions": [str(p) for p in best_parent.permissions - role.permissions],
                            },
                            confidence_score=0.8,
                        )
                    )

        return recommendations 