"""Graph intelligence layer using NetworkX for network analysis."""
import networkx as nx
import numpy as np
from collections import Counter
from app.db import get_connection, release_connection

try:
    import community as community_louvain
    HAS_LOUVAIN = True
except ImportError:
    HAS_LOUVAIN = False


class GraphEngine:
    """Graph-based intelligence for detecting network-level patterns."""

    def __init__(self):
        self.G = None
        self.node_risks = {}
        self.communities = {}

    def build_graph(self, limit=500000):
        """Build a directed graph from transactions.
        
        Nodes = accounts (bank_account), Edges = transactions (weighted by amount)
        """
        conn = get_connection()
        
        sql = """
            SELECT from_bank || '_' || from_account as sender,
                   to_bank || '_' || to_account as receiver,
                   SUM(amount_paid) as total_amount,
                   COUNT(*) as txn_count,
                   MAX(is_laundering) as has_laundering
            FROM transactions
            GROUP BY sender, receiver
        """
        if limit:
            sql += f" LIMIT {limit}"

        with conn.cursor(cursor_factory=None) as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        release_connection(conn)

        print(f"[GraphEngine] Building graph from {len(rows):,} edges...")

        self.G = nx.DiGraph()

        for row in rows:
            self.G.add_edge(
                row['sender'], row['receiver'],
                weight=row['total_amount'],
                txn_count=row['txn_count'],
                has_laundering=row['has_laundering'],
            )

        print(f"[GraphEngine] Graph: {self.G.number_of_nodes():,} nodes, "
              f"{self.G.number_of_edges():,} edges")

        return self.G

    def analyze(self):
        """Run all graph analyses and compute node risk scores."""
        if self.G is None:
            self.build_graph()

        print("[GraphEngine] Running graph analysis...")

        # 1. Degree analysis (fan-out / fan-in)
        out_degrees = dict(self.G.out_degree())
        in_degrees = dict(self.G.in_degree())

        # 2. PageRank
        print("[GraphEngine] Computing PageRank...")
        pagerank = nx.pagerank(self.G, weight='weight', max_iter=50)

        # 3. Betweenness centrality (on sampled subgraph for performance)
        print("[GraphEngine] Computing centrality...")
        if self.G.number_of_nodes() > 10000:
            # Sample for large graphs
            sample_nodes = list(self.G.nodes())[:5000]
            subG = self.G.subgraph(sample_nodes)
            betweenness = nx.betweenness_centrality(subG, weight='weight', k=min(100, len(subG)))
        else:
            betweenness = nx.betweenness_centrality(self.G, weight='weight')

        # 4. Community detection (on undirected version)
        print("[GraphEngine] Detecting communities...")
        if HAS_LOUVAIN:
            undirected = self.G.to_undirected()
            self.communities = community_louvain.best_partition(undirected)
            community_sizes = Counter(self.communities.values())
            print(f"[GraphEngine] Found {len(community_sizes)} communities")
        else:
            self.communities = {n: 0 for n in self.G.nodes()}

        # 5. Cycle detection (limited)
        print("[GraphEngine] Detecting cycles...")
        cycles = self._detect_cycles(max_length=5, max_cycles=1000)

        # 6. Compile node risk scores
        cycle_nodes = set()
        for cycle in cycles:
            cycle_nodes.update(cycle)

        max_pr = max(pagerank.values()) if pagerank else 1
        max_out = max(out_degrees.values()) if out_degrees else 1
        max_in = max(in_degrees.values()) if in_degrees else 1
        max_bt = max(betweenness.values()) if betweenness else 1

        for node in self.G.nodes():
            # Normalize each signal to 0-1
            pr_norm = pagerank.get(node, 0) / max(max_pr, 1e-8)
            out_norm = out_degrees.get(node, 0) / max(max_out, 1)
            in_norm = in_degrees.get(node, 0) / max(max_in, 1)
            bt_norm = betweenness.get(node, 0) / max(max_bt, 1e-8)
            in_cycle = 1.0 if node in cycle_nodes else 0.0

            # Weighted risk score
            risk = (
                0.25 * pr_norm +
                0.15 * out_norm +
                0.15 * in_norm +
                0.20 * bt_norm +
                0.25 * in_cycle
            )

            self.node_risks[node] = {
                'risk_score': round(min(risk, 1.0), 4),
                'pagerank': round(pr_norm, 4),
                'out_degree': out_degrees.get(node, 0),
                'in_degree': in_degrees.get(node, 0),
                'betweenness': round(bt_norm, 4),
                'in_cycle': in_cycle > 0,
                'community': self.communities.get(node, -1),
            }

        high_risk = sum(1 for v in self.node_risks.values() if v['risk_score'] > 0.7)
        print(f"[GraphEngine] Analysis complete. {high_risk:,} high-risk nodes (>0.7)")

        return self.node_risks

    def _detect_cycles(self, max_length=5, max_cycles=1000):
        """Detect short cycles (potential laundering rings)."""
        cycles = []
        try:
            for cycle in nx.simple_cycles(self.G):
                if len(cycle) <= max_length:
                    cycles.append(cycle)
                if len(cycles) >= max_cycles:
                    break
        except Exception:
            # Fall back to finding strongly connected components
            for component in nx.strongly_connected_components(self.G):
                if 2 <= len(component) <= max_length:
                    cycles.append(list(component))
                if len(cycles) >= max_cycles:
                    break

        print(f"[GraphEngine] Found {len(cycles)} short cycles")
        return cycles

    def get_account_risk(self, account_id):
        """Get risk score for a specific account."""
        return self.node_risks.get(account_id, {
            'risk_score': 0,
            'pagerank': 0,
            'out_degree': 0,
            'in_degree': 0,
            'betweenness': 0,
            'in_cycle': False,
            'community': -1,
        })

    def get_neighbors(self, account_id, depth=2):
        """Get the subgraph around an account for visualization."""
        if self.G is None or account_id not in self.G:
            return {'nodes': [], 'edges': []}

        # BFS to depth
        nodes = {account_id}
        frontier = {account_id}
        for _ in range(depth):
            new_frontier = set()
            for node in frontier:
                new_frontier.update(self.G.successors(node))
                new_frontier.update(self.G.predecessors(node))
            nodes.update(new_frontier)
            frontier = new_frontier

        # Limit to prevent massive subgraphs
        if len(nodes) > 100:
            nodes = set(list(nodes)[:100])

        subG = self.G.subgraph(nodes)

        node_list = []
        for n in subG.nodes():
            risk = self.node_risks.get(n, {})
            node_list.append({
                'id': n,
                'risk': risk.get('risk_score', 0),
                'is_center': n == account_id,
            })

        edge_list = []
        for u, v, data in subG.edges(data=True):
            edge_list.append({
                'source': u,
                'target': v,
                'weight': data.get('weight', 0),
                'txn_count': data.get('txn_count', 0),
            })

        return {'nodes': node_list, 'edges': edge_list}

    def get_high_risk_nodes(self, threshold=0.7):
        """Get nodes above risk threshold."""
        return {k: v for k, v in self.node_risks.items() if v['risk_score'] > threshold}

    def has_graph(self) -> bool:
        """Returns True if graph has been built and analysed already."""
        return bool(self.node_risks)
