"""
Graph Intelligence Service
Owner: Nidhi
Description: Constructs, queries, and analyzes NetworkX entity-relationship graphs.
Maps IPs, Users, Targets, URLs, Honeytokens, and Alerts with evidence-backed edges.
Calculates centrality hubs and supports IP-rotation linkage.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
import networkx as nx
from app.schemas.alert import StandardAlert
from app.schemas.incident import IncidentGraphResponse, GraphNode, GraphEdge


class IncidentGraphBuilder:
    def __init__(self):
        pass

    def build_graph_for_alerts(self, incident_id: str, alerts: List[StandardAlert]) -> IncidentGraphResponse:
        """
        Build NetworkX graph for a set of alerts and extract serializable visualization data.
        """
        G = nx.MultiGraph()

        node_registry: Dict[str, GraphNode] = {}
        edge_list: List[GraphEdge] = []

        def add_node_if_absent(node_id: str, label: str, node_type: str, role: str, metadata: Dict[str, Any] = None):
            if node_id not in node_registry:
                meta = metadata or {}
                node_obj = GraphNode(id=node_id, label=label, type=node_type, role=role, metadata=meta)
                node_registry[node_id] = node_obj
                G.add_node(node_id, type=node_type, role=role, label=label)

        for alert in alerts:
            alert_node_id = f"alert_{alert.alert_id}"
            add_node_if_absent(
                alert_node_id,
                alert.title,
                node_type="alert",
                role="detector_finding",
                metadata={
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "detector": alert.detector,
                    "timestamp": alert.timestamp.isoformat()
                }
            )

            # IP Entity Node
            if alert.source_ip:
                ip_node_id = f"ip_{alert.source_ip}"
                add_node_if_absent(ip_node_id, alert.source_ip, node_type="ip", role="attacker_origin")
                edge = GraphEdge(
                    source=ip_node_id,
                    target=alert_node_id,
                    relationship="TRIGGERED",
                    evidence=f"Alert generated from source IP {alert.source_ip}",
                    timestamp=alert.timestamp.isoformat()
                )
                edge_list.append(edge)
                G.add_edge(ip_node_id, alert_node_id, relationship="TRIGGERED")

            # User Entity Node
            if alert.user_id:
                user_node_id = f"user_{alert.user_id}"
                add_node_if_absent(user_node_id, alert.user_id, node_type="user", role="targeted_account")
                edge = GraphEdge(
                    source=alert_node_id,
                    target=user_node_id,
                    relationship="IMPLICATES",
                    evidence=f"Alert involved user account {alert.user_id}",
                    timestamp=alert.timestamp.isoformat()
                )
                edge_list.append(edge)
                G.add_edge(alert_node_id, user_node_id, relationship="IMPLICATES")

                # Direct link between IP and User if both exist
                if alert.source_ip:
                    ip_node_id = f"ip_{alert.source_ip}"
                    edge_ip_user = GraphEdge(
                        source=ip_node_id,
                        target=user_node_id,
                        relationship="AUTHENTICATED_AS",
                        evidence=f"Activity observed from {alert.source_ip} targeting user {alert.user_id}",
                        timestamp=alert.timestamp.isoformat()
                    )
                    edge_list.append(edge_ip_user)
                    G.add_edge(ip_node_id, user_node_id, relationship="AUTHENTICATED_AS")

            # Target Node
            if alert.target:
                target_node_id = f"target_{alert.target}"
                add_node_if_absent(target_node_id, alert.target, node_type="target", role="victim_resource")
                edge = GraphEdge(
                    source=alert_node_id,
                    target=target_node_id,
                    relationship="TARGETED",
                    evidence=f"Attack directed at resource {alert.target}",
                    timestamp=alert.timestamp.isoformat()
                )
                edge_list.append(edge)
                G.add_edge(alert_node_id, target_node_id, relationship="TARGETED")

                if alert.source_ip:
                    ip_node_id = f"ip_{alert.source_ip}"
                    edge_ip_target = GraphEdge(
                        source=ip_node_id,
                        target=target_node_id,
                        relationship="COMMUNICATED_WITH",
                        evidence=f"{alert.source_ip} sent traffic to {alert.target}",
                        timestamp=alert.timestamp.isoformat()
                    )
                    edge_list.append(edge_ip_target)
                    G.add_edge(ip_node_id, target_node_id, relationship="COMMUNICATED_WITH")

            # Honeytoken Entity
            if alert.detector in ("honeytoken", "HONEYTOKEN") or "masked_honeytoken" in alert.evidence:
                token_val = alert.evidence.get("masked_honeytoken") or alert.target or "Honeytoken_Trap"
                token_node_id = f"honeytoken_{token_val}"
                add_node_if_absent(token_node_id, token_val, node_type="honeytoken", role="decoy_trap")
                edge = GraphEdge(
                    source=alert_node_id,
                    target=token_node_id,
                    relationship="DECEPTION_ACTIVATED",
                    evidence=f"Decoy canary triggered: {token_val}",
                    timestamp=alert.timestamp.isoformat()
                )
                edge_list.append(edge)
                G.add_edge(alert_node_id, token_node_id, relationship="DECEPTION_ACTIVATED")

                if alert.source_ip:
                    ip_node_id = f"ip_{alert.source_ip}"
                    edge_ip_token = GraphEdge(
                        source=ip_node_id,
                        target=token_node_id,
                        relationship="ACCESSED_CANARY",
                        evidence=f"{alert.source_ip} triggered trap {token_val}",
                        timestamp=alert.timestamp.isoformat()
                    )
                    edge_list.append(edge_ip_token)
                    G.add_edge(ip_node_id, token_node_id, relationship="ACCESSED_CANARY")

            # Phishing URL Entity
            if alert.detector in ("phishing", "PHISHING") and alert.target:
                url_node_id = f"url_{alert.target}"
                add_node_if_absent(url_node_id, alert.target, node_type="url", role="malicious_url")
                edge = GraphEdge(
                    source=alert_node_id,
                    target=url_node_id,
                    relationship="DELIVERED_PAYLOAD",
                    evidence=f"Phishing lure URL: {alert.target}",
                    timestamp=alert.timestamp.isoformat()
                )
                edge_list.append(edge)
                G.add_edge(alert_node_id, url_node_id, relationship="DELIVERED_PAYLOAD")

        # NetworkX Centrality Analysis
        key_hubs = []
        if len(G.nodes) > 0:
            degree_centrality = nx.degree_centrality(G)
            sorted_hubs = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)
            for node_id, cent in sorted_hubs[:5]:
                if cent > 0.1:
                    label = node_registry.get(node_id, GraphNode(id=node_id, label=node_id, type="entity")).label
                    key_hubs.append(f"{label} (degree={cent:.2f})")

        return IncidentGraphResponse(
            incident_id=incident_id,
            nodes=list(node_registry.values()),
            edges=edge_list,
            node_count=len(node_registry),
            edge_count=len(edge_list),
            key_hubs=key_hubs
        )


graph_builder = IncidentGraphBuilder()
