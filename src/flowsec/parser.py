from typing import Any

import yaml
from yaml.resolver import BaseResolver

from .errors import ScanError


class LineStr(str):
    """A YAML string that remembers where it came from.

    ``line`` is the 1-based line of the value's first character. For a literal
    block (``run: |``) it is the first content line and ``block`` is True, so
    line N inside the text sits at ``line + N``.
    """

    line: int = 0
    block: bool = False


class LineDict(dict[Any, Any]):
    """A YAML mapping that remembers its own line and the line of every key."""

    line: int = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.key_lines: dict[Any, int] = {}


class LineList(list[Any]):
    """A YAML sequence that remembers the line it starts on."""

    line: int = 0


class LineLoader(yaml.SafeLoader):
    """SafeLoader that records where every string, mapping, key and list lives.

    Strings come back as LineStr, mappings as LineDict (with ``key_lines``),
    sequences as LineList. For backward compatibility each key with a string
    value also gets an extra "__line_<key>__" entry in its mapping.
    """


def construct_str(loader: LineLoader, node: yaml.ScalarNode) -> LineStr:
    value = LineStr(loader.construct_scalar(node))
    value.line = node.start_mark.line + 1
    if node.style == "|":
        # The mark sits on the '|' indicator; the text starts on the next line.
        value.line += 1
        value.block = True
    return value


def construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict()
    mapping.line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        value = loader.construct_object(value_node)
        mapping[key] = value
        mapping.key_lines[key] = key_node.start_mark.line + 1
        if isinstance(value, str):
            mapping[f"__line_{key}__"] = key_node.start_mark.line + 1
    return mapping


def construct_sequence(loader: LineLoader, node: yaml.SequenceNode) -> LineList:
    items = LineList(loader.construct_object(child) for child in node.value)
    items.line = node.start_mark.line + 1
    return items


LineLoader.add_constructor(BaseResolver.DEFAULT_SCALAR_TAG, construct_str)
LineLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
LineLoader.add_constructor(BaseResolver.DEFAULT_SEQUENCE_TAG, construct_sequence)


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
