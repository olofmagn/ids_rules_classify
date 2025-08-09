import re
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import argparse
import sys
import logging

from typing import List, Optional, TextIO, Tuple, Dict, Any

"""
Author: Olof Magnusson
Date: 2025-06-03
A program that simplifies the understanding of the different rules from open-source data-sets using suricata/snort ids.
"""

BANNER = r"""
   _____ _               _  __
  / ____| |             (_)/ _|
 | |    | | __ _ ___ ___ _| |_ _   _
 | |    | |/ _` / __/ __| |  _| | | |
 | |____| | (_| \__ \__ \ | | | |_| |
  \_____|_|\__,_|___/___/_|_|  \__, |
                                __/ |
                               |___/
"""


class LoggerManager:
    """
    Logger manager
    """

    def __init__(self, name: str = __name__, level: int = logging.INFO) -> None:
        """
        Initialize logger manager with specified name and logging level

        Args:
        - name (str): name of the logger
        - level (int): logging level
        """

        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Avoid duplicate handlers if logger already has one
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def get_logger(self) -> logging.Logger:
        """
        Return configured logger instance
        """

        return self.logger


class SuricataRuleVisualizer:
    """
    Visualizes and analyzes Suricata rule patterns and classifications
    """

    def __init__(self, input_file: str, output_file: Optional[str] = None) -> None:
        """
        Initalize input_file and output_file for rule loading and writing

        Args:
        - input_file (str): Path to the input Suricata rule file
        - output_file (Optional[str]) : Path to the output file
        """

        self.logger = LoggerManager(self.__class__.__name__).get_logger()
        self.input_file = input_file
        self.output_file = output_file
        self.hash_pattern = re.compile(r"[a-fA-F0-9]{32,128}", re.IGNORECASE)
        self.hex_pattern = re.compile(r"\|(?:[0-9a-fA-F]{2}\s*)+\|", re.IGNORECASE)
        self.pcre_values = re.compile(r'pcre\s*:\s*"([^"]+)"', re.IGNORECASE)
        self.content_pattern = re.compile(
            r"^(?!\|)(?![a-fA-F0-9]{32,128}$).{4,}$", re.IGNORECASE
        )
        self.match_pattern = re.compile(
            r"^\s*(alert)\s+(tcp|udp|icmp|dns|tls)", re.IGNORECASE
        )  # only IDS alerts
        self.content_values = re.compile(r'content:\s*"([^"]+)"', re.IGNORECASE)

    def _load_ruleset(self) -> List[str]:
        """
        Loads a file and read all possible lines

        Returns:
        - (List[str]): A list of lines to process
        """

        try:
            with open(self.input_file, "r", encoding="utf-8") as file:
                lines = file.readlines()
            return lines
        except FileNotFoundError:
            self.logger.error(
                f"File not found: {self.input_file}. Check if you provided correct filepath"
            )
            sys.exit(1)
        except IOError:
            self.logger.error(
                f"I/O Error occured when reading {self.input_file}. Exiting"
            )
            sys.exit(1)

    def _parse_rule(self, rule: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse protocol and alert type from a rule

        Args:
        - rule (str): Rule logic type

        Returns:
        - Optional[Tuple[str, str, str]]: Tuple of (protocol, alert_type, rule)
        """

        match = re.match(self.match_pattern, rule)
        if match:
            alert_type, protocol = match.groups()
            return protocol, alert_type, rule
        return None

    def _classify_rule_logic(self, rule: str) -> Dict[str, Any]:
        """
        Classify rule logic type

        Args:
        - rule (str): Rule logic type

        Returns:
        - (Dict[str, Any]): The primary alert definition based on the weighted score
        """

        # Priority levels for scoring
        PRIORITY = {"PCRE": 100, "Hash": 90, "Hex": 80, "String": 70, "Unknown": 0}

        content_values = re.findall(self.content_values, rule)
        pcre_values = re.findall(self.pcre_values, rule)
        matches = []

        # Classify content fields
        for content in content_values:
            content = content.strip()

            # Hex content pattern (e.g., |00 01 02|)
            if self.hex_pattern.fullmatch(content):
                matches.append("Hex")
            # File hash detection (e.g., 32 to 128 hex chars)
            if self.hash_pattern.fullmatch(content):
                matches.append("Hash")
            # Generic strings (e.g., cmd.exe)
            if self.content_pattern.fullmatch(content) and not content.startswith("|"):
                matches.append("String")

        # Classify pcre patterns
        for _ in pcre_values:
            matches.append("PCRE")

        # invalid strings
        if not matches:
            return {"primary": "Unknown", "total_score": 0, "matched": []}

        match_counts = defaultdict(int)
        for m in matches:
            match_counts[m] += 1

        # Score system
        category_scores = {
            cat: PRIORITY[cat] * count for cat, count in match_counts.items()
        }

        primary = max(category_scores, key=category_scores.get)
        total_score = category_scores[primary]

        return {
            "primary": primary,
            "score": total_score,
            "matched": matches,
            "counts": dict(match_counts),
        }

    def group_and_classify_rules(self, rules: List[str]) -> Dict[str, Any]:
        """
        Group and classify rules based on the pattern

        Args:
        - rules (List[str]): A list of rule strings to process

        Returns:
        - Dict[str, Any]: Grouped rule data by protocol, alert type, and logic type
        """

        grouped_data = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        for idx, rule in enumerate(rules):
            rule = rule.strip()
            parsed = self._parse_rule(rule)
            if parsed:
                protocol, alert_type, full_rule = parsed
                logic = self._classify_rule_logic(full_rule)
                logic_type = logic["primary"]
                grouped_data[protocol][alert_type][logic_type] += 1

        return grouped_data

    def save_or_print_grouped_data(
        self, grouped_data: Dict[str, Any], output_file: Optional[str] = None
    ) -> None:
        """
        Save grouped data to a text file in a structured format
        If no file provided, the result will be printed to the console

        Args:
        - grouped_data (Dict[str, Any]): Protocol, alert and rule type data
        - output_file (Optional[str]): Path to the output file
        """

        f = open(output_file, "w") if output_file else None
        try:
            for protocol, alert_dict in grouped_data.items():
                line = f"Protocol: {protocol.upper()}"
                if f:
                    f.write(f"{line}\n")
                else:
                    print(line)

                for alert_type, logic_dict in alert_dict.items():
                    line = f"Alert type: {alert_type}"
                    if f:
                        f.write(f"{line}\n")
                    else:
                        print(line)

                    for logic_type, count in logic_dict.items():
                        line = f"{logic_type}: {count}"
                        if f:
                            f.write(f"{line}\n")
                        else:
                            print(line)

                if f:
                    f.write("\n")
                else:
                    print()
        finally:
            if f:
                f.close()
                self.logger.info(f"Grouped data saved to {output_file}")

    def visualize_data(self, grouped_data: Dict[str, Any]) -> None:
        """
        Visualize data using stacked bar chart and heatmap

        Args:
        - grouped_data (Dict[str, Any]): protocol, alert and rule type
        """

        protocols = []
        alert_types = []
        logic_types = []
        counts = []

        for protocol, alert_dict in grouped_data.items():
            for alert_type, logic_dict in alert_dict.items():
                for logic_type, count in logic_dict.items():
                    protocols.append(protocol)
                    alert_types.append(alert_type)
                    logic_types.append(logic_type)
                    counts.append(count)

        # Create DataFrame for visualization
        data = pd.DataFrame(
            {
                "Protocol": protocols,
                "Alert Type": alert_types,
                "Logic Type": logic_types,
                "Count": counts,
            }
        )

        # Stacked Bar Chart for each protocol
        for protocol in data["Protocol"].unique():
            protocol_data = data[data["Protocol"] == protocol]
            protocol_pivot = protocol_data.pivot_table(
                index="Alert Type",
                columns="Logic Type",
                values="Count",
                aggfunc="sum",
                fill_value=0,
            )
            protocol_pivot.plot(
                kind="bar",
                stacked=True,
                figsize=(10, 6),
                title=f"Logic Type Distribution in {protocol.upper()} Protocol",
            )
            plt.ylabel("Rule Count")
            plt.tight_layout()
            plt.show()
            # Heatmap
        heatmap_pivot = data.pivot_table(
            index=["Protocol", "Alert Type"],
            columns="Logic Type",
            values="Count",
            aggfunc="sum",
            fill_value=0,
        )
        plt.figure(figsize=(12, 8))
        sns.heatmap(heatmap_pivot, annot=True, fmt="d", cmap="YlGnBu")
        plt.title("Rule Logic Type Distribution by Protocol and Alert Type")
        plt.ylabel("Protocol & Alert Type")
        plt.xlabel("Logic Type")
        plt.tight_layout()
        plt.show()


class ArgumentParser:
    """
    Handles argument parsing
    """

    def __init__(self) -> None:
        """
        Initialize argument parser
        """

        self.parser = self.create_parser()

    def create_parser(self) -> argparse.ArgumentParser:
        """
        Configures the argument parser with expected arguments.

        Returns: An instance of argparse.ArgumentParser
        """

        parser = argparse.ArgumentParser(
            description="Suricata Rule Classifier",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=BANNER,
        )

        parser.add_argument(
            "-i",
            "--input_file",
            required=True,
            help="Path to the input Suricata rule file.",
        )
        parser.add_argument(
            "-o",
            "--output_file",
            help="Path to the output file for saving matched rules",
        )
        return parser

    def parse_args(self) -> argparse.Namespace:
        """
        Parse and return command-line arguments

        Returns: a namespace object
        """

        return self.parser.parse_args()


class SuricataRuleClassifier:
    """
    Classifies rules in IDS rule files depending on a given pattern
    """

    def __init__(self) -> None:
        """
        Initialize the application, including argument parsing and searcher
        """

        parser = ArgumentParser()

        self.args = parser.parse_args()
        self.visualizer = SuricataRuleVisualizer(
            input_file=self.args.input_file, output_file=self.args.output_file
        )

    def run(self) -> None:
        """
        Loads rulesets and save/visualize the result
        """

        rules = self.visualizer._load_ruleset()
        results = self.visualizer.group_and_classify_rules(rules)
        self.visualizer.save_or_print_grouped_data(results, self.args.output_file)
        self.visualizer.visualize_data(results)


def main() -> None:
    try:
        app = SuricataRuleClassifier()
        app.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
