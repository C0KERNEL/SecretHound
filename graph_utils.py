#!/usr/bin/env python3
"""
BloodHound Graph Utilities

This script provides utilities for modifying existing BloodHound OpenGraph files.
It can import existing graphs, add edges, update nodes, and export modified graphs.
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from bhopengraph.OpenGraph import OpenGraph
    from bhopengraph.Node import Node
    from bhopengraph.Edge import Edge
    from bhopengraph.Properties import Properties
except ImportError:
    print("Error: bhopengraph library not found. Install with: pip install bhopengraph")
    exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class GraphModifier:
    """Utility class for modifying BloodHound OpenGraph files"""

    def __init__(self, graph_file: Path, source_kind: str = "StargateNetwork"):
        """
        Initialize GraphModifier by importing an existing graph

        Args:
            graph_file: Path to existing BloodHound OpenGraph JSON file
            source_kind: Source kind for the OpenGraph (default: StargateNetwork)
        """
        logger.info(f"Importing graph from {graph_file}")
        self.graph = OpenGraph(source_kind=source_kind)
        self.graph.import_from_file(str(graph_file))
        logger.info(f"Successfully imported graph")

    def add_edge(self, start_node_id: str, end_node_id: str, edge_kind: str) -> bool:
        """
        Add a new edge between two existing nodes

        Args:
            start_node_id: ID of the starting node
            end_node_id: ID of the ending node
            edge_kind: Type of edge (e.g., "CanAuthenticate", "HasCredential")

        Returns:
            True if edge was added successfully
        """
        try:
            edge = Edge(
                start_node=start_node_id,
                end_node=end_node_id,
                kind=edge_kind
            )
            self.graph.add_edge(edge)
            logger.info(f"Added edge: {start_node_id} -[{edge_kind}]-> {end_node_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add edge: {e}")
            return False

    def add_node(self, node_id: str, kinds: List[str], properties: Dict[str, Any]) -> bool:
        """
        Add a new node to the graph

        Args:
            node_id: Unique identifier for the node
            kinds: List of node kinds (e.g., ["Secret", "AWSBase"])
            properties: Dictionary of node properties

        Returns:
            True if node was added successfully
        """
        try:
            node = Node(
                id=node_id,
                kinds=kinds,
                properties=Properties(**properties)
            )
            self.graph.add_node(node)
            logger.info(f"Added node: {node_id} with kinds {kinds}")
            return True
        except Exception as e:
            logger.error(f"Failed to add node: {e}")
            return False

    def update_node_properties(self, node_id: str, properties: Dict[str, Any]) -> bool:
        """
        Update properties of an existing node

        Args:
            node_id: ID of the node to update
            properties: Dictionary of properties to add/update

        Returns:
            True if node was updated successfully
        """
        try:
            # Find the node in the graph
            node = self.graph.nodes.get(node_id)
            if node:
                # Update properties
                for key, value in properties.items():
                    setattr(node.properties, key, value)
                logger.info(f"Updated node {node_id} with properties: {list(properties.keys())}")
                return True
            else:
                logger.warning(f"Node {node_id} not found in graph")
                return False
        except Exception as e:
            logger.error(f"Failed to update node: {e}")
            return False

    def add_node_kind(self, node_id: str, kind: str) -> bool:
        """
        Add a kind to an existing node

        Args:
            node_id: ID of the node to update
            kind: Kind to add (e.g., "AWSBase")

        Returns:
            True if kind was added successfully
        """
        try:
            node = self.graph.nodes.get(node_id)
            if node:
                if kind not in node.kinds:
                    node.kinds.append(kind)
                    logger.info(f"Added kind '{kind}' to node {node_id}")
                    return True
                else:
                    logger.info(f"Kind '{kind}' already exists on node {node_id}")
                    return True
            else:
                logger.warning(f"Node {node_id} not found in graph")
                return False
        except Exception as e:
            logger.error(f"Failed to add kind: {e}")
            return False

    def find_nodes_by_kind(self, kind: str) -> List[Node]:
        """
        Find all nodes with a specific kind

        Args:
            kind: Node kind to search for

        Returns:
            List of matching nodes
        """
        matching_nodes = [node for node in self.graph.nodes.values() if kind in node.kinds]
        logger.info(f"Found {len(matching_nodes)} nodes with kind '{kind}'")
        return matching_nodes

    def find_node_by_id(self, node_id: str) -> Optional[Node]:
        """
        Find a node by its ID

        Args:
            node_id: ID of the node to find

        Returns:
            Node if found, None otherwise
        """
        return self.graph.nodes.get(node_id)

    def get_node_info(self, node_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a node

        Args:
            node_id: ID of the node

        Returns:
            Dictionary with node information or None if not found
        """
        node = self.find_node_by_id(node_id)
        if node:
            return {
                "id": node.id,
                "kinds": node.kinds,
                "properties": node.properties._properties
            }
        return None

    def list_edges_for_node(self, node_id: str) -> Dict[str, List[Edge]]:
        """
        List all edges connected to a node

        Args:
            node_id: ID of the node

        Returns:
            Dictionary with "outgoing" and "incoming" edge lists
        """
        outgoing = []
        incoming = []

        for edge in self.graph.edges:
            if edge.start_node == node_id:
                outgoing.append(edge)
            if edge.end_node == node_id:
                incoming.append(edge)

        logger.info(f"Node {node_id}: {len(outgoing)} outgoing, {len(incoming)} incoming edges")
        return {
            "outgoing": outgoing,
            "incoming": incoming
        }

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the graph

        Returns:
            Dictionary with graph statistics
        """
        stats = {
            "total_nodes": len(self.graph.nodes),
            "total_edges": len(self.graph.edges),
            "node_kinds": {},
            "edge_kinds": {}
        }

        # Count nodes by kind
        for node in self.graph.nodes.values():
            for kind in node.kinds:
                stats["node_kinds"][kind] = stats["node_kinds"].get(kind, 0) + 1

        # Count edges by kind
        for edge in self.graph.edges:
            stats["edge_kinds"][edge.kind] = stats["edge_kinds"].get(edge.kind, 0) + 1

        return stats

    def save(self, output_file: Path):
        """
        Save the modified graph to a file

        Args:
            output_file: Path to output file
        """
        logger.info(f"Saving modified graph to {output_file}")
        self.graph.export_to_file(str(output_file))
        logger.info("Graph saved successfully")


def main():
    """Interactive CLI for graph manipulation"""
    parser = argparse.ArgumentParser(
        description='Modify BloodHound OpenGraph files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # View graph statistics
  python graph_utils.py -i secrets.json --stats

  # Add an edge between two nodes
  python graph_utils.py -i secrets.json -o modified.json \\
    --add-edge START_ID END_ID CanAuthenticate

  # Update node properties
  python graph_utils.py -i secrets.json -o modified.json \\
    --update-node NODE_ID --properties '{"verified": true, "notes": "confirmed"}'

  # Add a kind to a node
  python graph_utils.py -i secrets.json -o modified.json \\
    --add-kind NODE_ID AWSBase

  # Find all nodes of a specific kind
  python graph_utils.py -i secrets.json --find-kind Secret
        """
    )

    parser.add_argument(
        '-i', '--input',
        type=Path,
        required=True,
        help='Input BloodHound OpenGraph JSON file'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file for modified graph'
    )

    parser.add_argument(
        '--source-kind',
        default='StargateNetwork',
        help='Source kind for OpenGraph (default: StargateNetwork)'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Display graph statistics'
    )

    parser.add_argument(
        '--add-edge',
        nargs=3,
        metavar=('START_ID', 'END_ID', 'KIND'),
        help='Add an edge: START_ID END_ID EDGE_KIND'
    )

    parser.add_argument(
        '--update-node',
        metavar='NODE_ID',
        help='Update a node (use with --properties)'
    )

    parser.add_argument(
        '--properties',
        metavar='JSON',
        help='Properties as JSON string (use with --update-node)'
    )

    parser.add_argument(
        '--add-kind',
        nargs=2,
        metavar=('NODE_ID', 'KIND'),
        help='Add a kind to a node: NODE_ID KIND'
    )

    parser.add_argument(
        '--find-kind',
        metavar='KIND',
        help='Find all nodes with a specific kind'
    )

    parser.add_argument(
        '--node-info',
        metavar='NODE_ID',
        help='Get information about a specific node'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize graph modifier
    modifier = GraphModifier(args.input, source_kind=args.source_kind)

    # Execute requested operations
    modified = False

    if args.stats:
        stats = modifier.get_statistics()
        print("\nGraph Statistics:")
        print(f"Total Nodes: {stats['total_nodes']}")
        print(f"Total Edges: {stats['total_edges']}")
        print("\nNode Kinds:")
        for kind, count in sorted(stats['node_kinds'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {kind}: {count}")
        print("\nEdge Kinds:")
        for kind, count in sorted(stats['edge_kinds'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {kind}: {count}")

    if args.add_edge:
        start_id, end_id, kind = args.add_edge
        if modifier.add_edge(start_id, end_id, kind):
            modified = True

    if args.update_node and args.properties:
        import json
        try:
            properties = json.loads(args.properties)
            if modifier.update_node_properties(args.update_node, properties):
                modified = True
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON for properties: {e}")

    if args.add_kind:
        node_id, kind = args.add_kind
        if modifier.add_node_kind(node_id, kind):
            modified = True

    if args.find_kind:
        nodes = modifier.find_nodes_by_kind(args.find_kind)
        print(f"\nFound {len(nodes)} nodes with kind '{args.find_kind}':")
        for node in nodes[:10]:  # Show first 10
            props = node.properties._properties
            name = props.get('name', props.get('displayname', 'Unknown'))
            print(f"  {node.id[:16]}... - {name}")
        if len(nodes) > 10:
            print(f"  ... and {len(nodes) - 10} more")

    if args.node_info:
        info = modifier.get_node_info(args.node_info)
        if info:
            print(f"\nNode Information:")
            print(f"ID: {info['id']}")
            print(f"Kinds: {', '.join(info['kinds'])}")
            print(f"Properties:")
            for key, value in info['properties'].items():
                print(f"  {key}: {value}")

            edges = modifier.list_edges_for_node(args.node_info)
            print(f"\nOutgoing Edges: {len(edges['outgoing'])}")
            for edge in edges['outgoing'][:5]:
                print(f"  -[{edge.kind}]-> {edge.end_node[:16]}...")
            print(f"\nIncoming Edges: {len(edges['incoming'])}")
            for edge in edges['incoming'][:5]:
                print(f"  <-[{edge.kind}]- {edge.start_node[:16]}...")
        else:
            print(f"Node {args.node_info} not found")

    # Save if modifications were made and output file specified
    if modified:
        if args.output:
            modifier.save(args.output)
        else:
            logger.warning("Graph was modified but no output file specified. Use -o to save changes.")
    elif args.output and not args.stats and not args.find_kind and not args.node_info:
        logger.info("No modifications made, but output file specified. Saving copy...")
        modifier.save(args.output)


if __name__ == '__main__':
    main()
