from typing import Any


class GraphService:
    @staticmethod
    def generate_stix_graph(indicators: list[dict[str, Any]], infrastructure: dict[str, Any], campaign_flag: bool) -> dict[str, Any]:
        nodes = [{"id": "email-1", "type": "observable-email", "data": {"label": "Suspicious Email"}}]
        edges = []
        
        if infrastructure and infrastructure.get("ip"):
            ip_node_id = f"ip-{infrastructure['ip']}"
            nodes.append({
                "id": ip_node_id,
                "type": "observable-ip",
                "data": {"label": infrastructure["ip"], "asn": infrastructure.get("asn")}
            })
            edges.append({"id": f"e-email-{ip_node_id}", "source": "email-1", "target": ip_node_id})

        for idx, ind in enumerate(indicators):
            ind_type = ind.get("type", "").lower()
            ind_val = ind.get("value", "")
            node_id = f"ind-{idx}"
            
            node_type = "indicator"
            if "ip" in ind_type: node_type = "observable-ip"
            elif "url" in ind_type: node_type = "indicator-url"
            elif "domain" in ind_type: node_type = "observable-domain"
                
            nodes.append({"id": node_id, "type": node_type, "data": {"label": ind_val}})
            edges.append({"id": f"e-email-{node_id}", "source": "email-1", "target": node_id})
            
        if campaign_flag:
            campaign_id = "campaign-1"
            nodes.append({"id": campaign_id, "type": "campaign-cluster", "data": {"label": "Coordinated Campaign"}})
            edges.append({"id": f"e-{campaign_id}-email", "source": campaign_id, "target": "email-1"})
            
        return {"nodes": nodes, "edges": edges}
