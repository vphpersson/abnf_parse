from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterator
from functools import cached_property
from collections import deque


@dataclass(frozen=True)
class MatchNode:
    name: str
    start_offset: int
    end_offset: int
    source: memoryview
    children: list[MatchNode] = field(default_factory=list)

    @cached_property
    def _get_field_map(self):
        """
        Create a name-to-child-node(s) map.

        :return: The resulting name-to-child-node(s) map.
        """

        field_map: dict[str, MatchNode | list[MatchNode]] = {}

        for child in self.children:
            existing_field_value = field_map.get(child.name)

            if existing_field_value is None:
                field_map[child.name] = child
            else:
                if isinstance(existing_field_value, list):
                    existing_field_value.append(child)
                else:
                    field_map[child.name] = [existing_field_value, child]

        return field_map

    def search(self, name: str) -> Iterator[MatchNode]:
        """
        Search a node recursively for nodes having the provided name.

        The search is performed breadth first.

        :param name: The name of nodes to be yielded.
        :return: None
        """

        queue: deque[MatchNode] = deque([self])
        while queue:
            current_node: MatchNode = queue.popleft()

            if current_node.name == name:
                yield current_node
            else:
                queue.extend(current_node.children)

    def get_field(self, name: str, as_list: bool = False) -> MatchNode | list[MatchNode] | None:
        """
        Return the child match nodes having the specified name.

        Single child match nodes are returned as-is unless `as_list` is set to `True`.

        :param name: The name of the child match nodes to be returned.
        :param as_list: Whether to return a resulting single child match node in a list.
        :return: Child match nodes having the specified name. `None` if none was found.
        """

        field_result = self._get_field_map.get(name)
        if as_list and not isinstance(field_result, list):
            return [field_result] if field_result is not None else []
        else:
            return field_result

    def get_value(self) -> bytes:
        """
        Return the byte value at between the start and end offsets in the memoryview.

        :return: The byte value corresponding to the match.
        """

        return self.source[self.start_offset:self.end_offset].tobytes()

    def __len__(self) -> int:
        return self.end_offset - self.start_offset

    def __str__(self) -> str:
        return self.get_value().decode()

    def __bytes__(self) -> bytes:
        return self.get_value()
