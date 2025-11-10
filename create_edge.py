#!/usr/bin/env python3
"""
create_edge.py - Helper script to create a single edge in BloodHound OpenGraph format

This script creates a simple graph with a single edge between two nodes identified by their IDs.
The output is in BloodHound OpenGraph JSON format.

Usage:
  python create_edge.py START_ID END_ID EDGE_KIND [PROPERTIES]

Examples:
  # Basic edge with no properties
  python create_edge.py user-123 server-456 AdminTo

  # Edge with JSON properties
  python create_edge.py user-123 server-456 HasSession '{"timestamp": "2025-04-16T12:00:00Z", "duration": 45}'

  # Edge with key=value properties
  python create_edge.py user-123 server-456 HasSession timestamp=2025-04-16T12:00:00Z duration=45

  # Save to file instead of stdout
  python create_edge.py user-123 server-456 AdminTo -o output.json
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from bhopengraph.OpenGraph import OpenGraph
    from bhopengraph.Edge import Edge
    from bhopengraph.Properties import Properties
except ImportError:
    print("Error: bhopengraph library not found. Install with: pip install bhopengraph", file=sys.stderr)
    sys.exit(1)


def parse_properties(properties_arg):
    """
    Parse properties from either JSON string or key=value format

    Args:
        properties_arg: Either a JSON string or key=value pairs

    Returns:
        Dictionary of properties or None
    """
    if not properties_arg:
        return None

    # Try to parse as JSON first
    try:
        props = json.loads(properties_arg)
        if isinstance(props, dict):
            return props
    except json.JSONDecodeError:
        pass

    # Try to parse as key=value pairs
    props = {}
    for pair in properties_arg.split():
        if '=' in pair:
            key, value = pair.split('=', 1)
            # Try to convert to appropriate type
            try:
                # Try int
                props[key] = int(value)
            except ValueError:
                try:
                    # Try float
                    props[key] = float(value)
                except ValueError:
                    # Try boolean
                    if value.lower() in ('true', 'false'):
                        props[key] = value.lower() == 'true'
                    else:
                        # Keep as string
                        props[key] = value

    return props if props else None


def create_edge_graph(start_id, end_id, edge_kind, properties=None, source_kind="StargateNetwork"):
    """
    Create a BloodHound OpenGraph with a single edge

    Args:
        start_id: Starting node ID
        end_id: Ending node ID
        edge_kind: Edge relationship kind
        properties: Optional dictionary of edge properties
        source_kind: Source kind for the OpenGraph

    Returns:
        OpenGraph instance
    """
    # Create the graph
    graph = OpenGraph(source_kind=source_kind)

    # Create the edge
    if properties:
        # Edge with properties - pass as Properties object if supported
        try:
            edge = Edge(
                start_node=start_id,
                end_node=end_id,
                kind=edge_kind,
                properties=Properties(**properties)
            )
        except TypeError:
            # If Properties not supported in Edge, try without it
            print(f"Warning: Edge properties may not be supported by this version of bhopengraph", file=sys.stderr)
            edge = Edge(
                start_node=start_id,
                end_node=end_id,
                kind=edge_kind
            )
    else:
        # Edge without properties
        edge = Edge(
            start_node=start_id,
            end_node=end_id,
            kind=edge_kind
        )

    # Add edge to graph
    graph.add_edge(edge)

    return graph


def main():
    parser = argparse.ArgumentParser(
        description='Create a BloodHound OpenGraph edge between two nodes by ID',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic edge
  python create_edge.py user-123 server-456 AdminTo

  # Edge with JSON properties
  python create_edge.py repo-abc secret-xyz ContainsCredentialsFor '{"confidence": "high", "verified": true}'

  # Edge with key=value properties
  python create_edge.py user-123 server-456 HasSession timestamp=2025-04-16 duration=45

  # Output to file
  python create_edge.py user-123 server-456 AdminTo -o edge.json

The output is a BloodHound OpenGraph JSON file with a single edge.
        """
    )

    parser.add_argument(
        'start_id',
        help='Starting node ID (objectid)'
    )

    parser.add_argument(
        'end_id',
        help='Ending node ID (objectid)'
    )

    parser.add_argument(
        'edge_kind',
        help='Edge kind/relationship type (e.g., AdminTo, HasSession, ContainsCredentialsFor)'
    )

    parser.add_argument(
        'properties',
        nargs='?',
        help='Optional edge properties as JSON string or space-separated key=value pairs'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file path (default: stdout)'
    )

    parser.add_argument(
        '--source-kind',
        default='StargateNetwork',
        help='Source kind for BloodHound OpenGraph (default: StargateNetwork)'
    )

    args = parser.parse_args()

    # Parse properties if provided
    props = parse_properties(args.properties) if args.properties else None

    # Create the graph with the edge
    graph = create_edge_graph(
        start_id=args.start_id,
        end_id=args.end_id,
        edge_kind=args.edge_kind,
        properties=props,
        source_kind=args.source_kind
    )

    # Output the graph
    if args.output:
        # Save to file
        graph.export_to_file(str(args.output))
        print(f"Edge created and saved to {args.output}", file=sys.stderr)
    else:
        # Print to stdout
        # Get the JSON representation
        graph_dict = graph.to_dict()
        print(json.dumps(graph_dict, indent=2))

    return 0


if __name__ == '__main__':
    sys.exit(main())
