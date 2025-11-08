#!/usr/bin/env python3
"""
Technology Taxonomy Module for SecretHound

This module provides centralized taxonomy for mapping scanner-specific rule IDs
to technology platforms and their corresponding BloodHound node kinds.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """Represents a technology platform with its BloodHound node configuration"""
    base_kind: str
    secret_kind: str
    color: str
    display_name: str


class Taxonomy:
    """
    Centralized technology taxonomy for mapping scanner outputs to BloodHound nodes

    This class loads a taxonomy configuration file that maps scanner-specific
    rule IDs (e.g., NoseyParker rule IDs) to technology platforms, which then
    map to BloodHound node kinds.
    """

    def __init__(self, taxonomy_file: Path):
        """
        Initialize taxonomy from a JSON configuration file

        Args:
            taxonomy_file: Path to taxonomy JSON file
        """
        self.taxonomy_file = taxonomy_file
        self.technologies: Dict[str, Technology] = {}
        self.scanner_mappings: Dict[str, Dict[str, str]] = {}
        self._load_taxonomy()

    def _load_taxonomy(self):
        """Load taxonomy configuration from JSON file"""
        try:
            with open(self.taxonomy_file, 'r') as f:
                config = json.load(f)

            # Load technologies
            tech_config = config.get('technologies', {})
            for tech_key, tech_data in tech_config.items():
                self.technologies[tech_key] = Technology(
                    base_kind=tech_data['base_kind'],
                    secret_kind=tech_data['secret_kind'],
                    color=tech_data['color'],
                    display_name=tech_data['display_name']
                )

            # Load scanner mappings
            self.scanner_mappings = config.get('scanner_mappings', {})

            logger.info(f"Loaded taxonomy from {self.taxonomy_file}")
            logger.info(f"  Technologies: {len(self.technologies)}")
            logger.info(f"  Scanners: {', '.join(self.scanner_mappings.keys())}")

        except FileNotFoundError:
            logger.error(f"Taxonomy file not found: {self.taxonomy_file}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in taxonomy file: {e}")
            raise
        except KeyError as e:
            logger.error(f"Missing required field in taxonomy file: {e}")
            raise

    def lookup_by_rule_id(self, scanner: str, rule_id: str) -> Optional[Tuple[str, str]]:
        """
        Look up technology node kinds by scanner-specific rule ID

        Args:
            scanner: Scanner name (e.g., 'noseyparker', 'trufflehog')
            rule_id: Scanner-specific rule ID (e.g., 'np.aws.2')

        Returns:
            Tuple of (secret_kind, base_kind) if found, None otherwise
            Example: ('AWSSecret', 'AWSBase')
        """
        # Get scanner mappings
        scanner_map = self.scanner_mappings.get(scanner, {})

        # Look up technology key from rule ID
        tech_key = scanner_map.get(rule_id)

        if not tech_key:
            logger.debug(f"No taxonomy mapping for {scanner}:{rule_id}")
            return None

        # Get technology definition
        tech = self.technologies.get(tech_key)

        if not tech:
            logger.warning(f"Technology key '{tech_key}' found in mappings but not in technologies")
            return None

        return (tech.secret_kind, tech.base_kind)

    def get_technology_color(self, scanner: str, rule_id: str) -> Optional[str]:
        """
        Get the color for a technology based on scanner rule ID

        Args:
            scanner: Scanner name
            rule_id: Scanner-specific rule ID

        Returns:
            Hex color code if found, None otherwise
        """
        scanner_map = self.scanner_mappings.get(scanner, {})
        tech_key = scanner_map.get(rule_id)

        if not tech_key:
            return None

        tech = self.technologies.get(tech_key)
        return tech.color if tech else None

    def get_all_technologies(self) -> Dict[str, Technology]:
        """Get all defined technologies"""
        return self.technologies

    def get_all_colors(self) -> Dict[str, str]:
        """
        Get mapping of node kinds to colors for icon registration

        Returns:
            Dict mapping node kind (e.g., 'AWSSecret') to color hex code
        """
        colors = {}
        for tech in self.technologies.values():
            colors[tech.secret_kind] = tech.color
            colors[tech.base_kind] = tech.color
        return colors
