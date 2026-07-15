"""
Neo4j database client for attack path modeling.
Graph database is essential for cybersecurity platforms as attack chains are graph problems.
Matches blueprint specification for Neo4j integration.
"""

from neo4j import GraphDatabase
from typing import Optional, List, Dict, Any
import os
import logging

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Neo4j client for managing attack path graph data."""

    def __init__(self, uri: str = None, username: str = None, password: str = None):
        """
        Initialize Neo4j client.

        Args:
            uri: Neo4j URI (default: from NEO4J_URI env)
            username: Neo4j username (default: from NEO4J_USER env)
            password: Neo4j password (default: from NEO4J_PASSWORD env)
        """
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://neo4j:7687")
        self.username = username or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        if not self.password:
            raise ValueError("NEO4J_PASSWORD environment variable is required")
        self.driver = None

    def connect(self):
        """Establish connection to Neo4j."""
        try:
            self.driver = GraphDatabase.driver(
                self.uri, auth=(self.username, self.password)
            )
            # Verify connectivity
            self.driver.verify_connectivity()
            logger.info("Neo4j connection established successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            return False

    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")

    def create_asset_node(
        self,
        asset_id: int,
        hostname: str = None,
        ip_address: str = None,
        asset_type: str = None,
        exposure_level: str = "internal",
    ) -> bool:
        """
        Create an asset node in the graph.

        Args:
            asset_id: Unique asset identifier
            hostname: Asset hostname
            ip_address: Asset IP address
            asset_type: Type of asset (web_server, api, database, etc.)
            exposure_level: Exposure level (internal, external, public)

        Returns:
            True if successful, False otherwise
        """
        query = """
        MERGE (a:Asset {asset_id: $asset_id})
        SET a.hostname = $hostname,
            a.ip_address = $ip_address,
            a.asset_type = $asset_type,
            a.exposure_level = $exposure_level,
            a.updated_at = timestamp()
        RETURN a
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    asset_id=asset_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    asset_type=asset_type,
                    exposure_level=exposure_level,
                )
            return True
        except Exception as e:
            logger.error(f"Failed to create asset node: {e}")
            return False

    def create_exploit_relationship(
        self,
        source_id: int,
        target_id: int,
        exploit_type: str,
        cvss_score: float = 0.0,
        description: str = None,
    ) -> bool:
        """
        Create an exploit relationship between two assets.
        Represents a potential attack path.

        Args:
            source_id: Source asset ID
            target_id: Target asset ID
            exploit_type: Type of exploit (sql_injection, xss, etc.)
            cvss_score: CVSS score of the vulnerability
            description: Description of the exploit

        Returns:
            True if successful, False otherwise
        """
        query = """
        MATCH (src:Asset {asset_id: $source_id})
        MATCH (tgt:Asset {asset_id: $target_id})
        MERGE (src)-[r:EXPLOIT {type: $exploit_type}]->(tgt)
        SET r.cvss_score = $cvss_score,
            r.description = $description,
            r.updated_at = timestamp()
        RETURN r
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    source_id=source_id,
                    target_id=target_id,
                    exploit_type=exploit_type,
                    cvss_score=cvss_score,
                    description=description,
                )
            return True
        except Exception as e:
            logger.error(f"Failed to create exploit relationship: {e}")
            return False

    def find_attack_paths(
        self, entry_asset_id: int, critical_asset_id: int, max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find all attack paths from entry point to critical asset.
        Uses graph traversal to identify potential attack chains.

        Args:
            entry_asset_id: Starting asset ID
            critical_asset_id: Target/critical asset ID
            max_depth: Maximum path depth to search

        Returns:
            List of attack paths with nodes and edges
        """
        query = (
            """
        MATCH path = (entry:Asset {asset_id: $entry_id})-[r:EXPLOIT*1..%d]->(critical:Asset {asset_id: $critical_id})
        RETURN path,
               length(path) as path_length,
               reduce(score = 0, rel IN relationships(path) | score + coalesce(rel.cvss_score, 0)) as total_risk
        ORDER BY total_risk DESC
        LIMIT 10
        """
            % max_depth
        )

        try:
            with self.driver.session() as session:
                result = session.run(
                    query, entry_id=entry_asset_id, critical_id=critical_asset_id
                )

                paths = []
                for record in result:
                    path = record["path"]
                    path_data = {
                        "nodes": [],
                        "edges": [],
                        "length": record["path_length"],
                        "total_risk": record["total_risk"],
                    }

                    # Extract nodes
                    for node in path.nodes:
                        path_data["nodes"].append(
                            {
                                "asset_id": node.get("asset_id"),
                                "hostname": node.get("hostname"),
                                "ip_address": node.get("ip_address"),
                                "asset_type": node.get("asset_type"),
                            }
                        )

                    # Extract relationships
                    for rel in path.relationships:
                        path_data["edges"].append(
                            {
                                "type": rel.get("type"),
                                "cvss_score": rel.get("cvss_score"),
                                "description": rel.get("description"),
                            }
                        )

                    paths.append(path_data)

                return paths
        except Exception as e:
            logger.error(f"Failed to find attack paths: {e}")
            return []

    def get_critical_paths(self, org_id: int = None) -> List[Dict[str, Any]]:
        """
        Get the most critical attack paths (highest risk).

        Args:
            org_id: Optional organization filter

        Returns:
            List of critical attack paths
        """
        query = """
        MATCH path = (entry:Asset)-[r:EXPLOIT*]->(critical:Asset)
        WITH path, relationships(path) as rels,
             reduce(score = 0, rel IN rels | score + coalesce(rel.cvss_score, 0)) as total_risk
        WHERE total_risk > 7.0
        RETURN path, total_risk
        ORDER BY total_risk DESC
        LIMIT 20
        """

        try:
            with self.driver.session() as session:
                result = session.run(query)

                paths = []
                for record in result:
                    path = record["path"]
                    path_data = {
                        "nodes": [dict(node) for node in path.nodes],
                        "total_risk": record["total_risk"],
                    }
                    paths.append(path_data)

                return paths
        except Exception as e:
            logger.error(f"Failed to get critical paths: {e}")
            return []

    def get_asset_relationships(self, asset_id: int) -> Dict[str, List]:
        """
        Get all relationships for a specific asset.

        Args:
            asset_id: Asset ID to query

        Returns:
            Dictionary with incoming and outgoing relationships
        """
        query = """
        MATCH (a:Asset {asset_id: $asset_id})
        OPTIONAL MATCH (a)-[r:EXPLOIT]->(target:Asset)
        WITH a, collect(DISTINCT {target: target, relation: r}) as outgoing
        OPTIONAL MATCH (source:Asset)-[r:EXPLOIT]->(a)
        WITH outgoing, collect(DISTINCT {source: source, relation: r}) as incoming
        RETURN outgoing, incoming
        """

        try:
            with self.driver.session() as session:
                result = session.run(query, asset_id=asset_id)
                record = result.single()

                if record:
                    return {
                        "outgoing": record["outgoing"],
                        "incoming": record["incoming"],
                    }
                return {"outgoing": [], "incoming": []}
        except Exception as e:
            logger.error(f"Failed to get asset relationships: {e}")
            return {"outgoing": [], "incoming": []}

    def delete_asset_node(self, asset_id: int) -> bool:
        """
        Delete an asset and all its relationships from the graph.

        Args:
            asset_id: Asset ID to delete

        Returns:
            True if successful, False otherwise
        """
        query = """
        MATCH (a:Asset {asset_id: $asset_id})
        DETACH DELETE a
        """
        try:
            with self.driver.session() as session:
                session.run(query, asset_id=asset_id)
            return True
        except Exception as e:
            logger.error(f"Failed to delete asset node: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get graph statistics.

        Returns:
            Dictionary with node and relationship counts
        """
        query = """
        MATCH (a:Asset)
        OPTIONAL MATCH (a)-[r:EXPLOIT]->()
        RETURN count(DISTINCT a) as total_assets,
               count(r) as total_exploits
        """
        try:
            with self.driver.session() as session:
                result = session.run(query)
                record = result.single()
                if record:
                    return {
                        "total_assets": record["total_assets"],
                        "total_exploits": record["total_exploits"],
                    }
                return {"total_assets": 0, "total_exploits": 0}
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {"total_assets": 0, "total_exploits": 0}


# Singleton instance
_neo4j_client: Optional[Neo4jClient] = None


def get_neo4j_client() -> Neo4jClient:
    """Get or create Neo4j client singleton."""
    global _neo4j_client
    if _neo4j_client is None:
        _neo4j_client = Neo4jClient()
    return _neo4j_client


def init_neo4j() -> bool:
    """Initialize Neo4j connection."""
    client = get_neo4j_client()
    return client.connect()


def close_neo4j():
    """Close Neo4j connection."""
    global _neo4j_client
    if _neo4j_client:
        _neo4j_client.close()
        _neo4j_client = None
