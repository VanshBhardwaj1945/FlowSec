from typing import Any

import yaml
from yaml.resolver import BaseResolver

from .errors import ScanError


class LineLoader(yaml.SafeLoader):
    """SafeLoader that records the line number of every string value.

    For each key with a string value, an extra "__line_<key>__" entry is added
    to the mapping so rules can report where a finding lives in the file.
    """


def construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        value = loader.construct_object(value_node)
        mapping[key] = value
        if isinstance(value, str):
            mapping[f"__line_{key}__"] = key_node.start_mark.line + 1
    return mapping


LineLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping,
)


def parse_pipeline_with_lines(content: str) -> dict[str, Any]:
    try:
        config = yaml.load(content, Loader=LineLoader)  # nosec B506 — LineLoader extends yaml.SafeLoader
    except yaml.YAMLError as error:
        raise ScanError(f"Invalid YAML: {error}") from error

    if config is None:
        return {}
    if not isinstance(config, dict):
        raise ScanError("Pipeline file must be a YAML mapping at the top level")
    return config
