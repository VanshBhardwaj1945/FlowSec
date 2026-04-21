import yaml
from yaml.resolver import BaseResolver


class LineLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node):
    loader.flatten_mapping(node)
    mapping = {}
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


def parse_pipeline(file_path: str) -> dict:
    with open(file_path, "r") as f:
        return yaml.load(f, Loader=LineLoader)


def parse_pipeline_with_lines(content: str) -> dict:
    return yaml.load(content, Loader=LineLoader)