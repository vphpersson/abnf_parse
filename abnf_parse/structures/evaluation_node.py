from __future__ import annotations
from abc import ABC, abstractmethod
from typing import ByteString, Iterator
from itertools import pairwise
from collections import defaultdict
from re import compile as re_compile, Pattern as RePattern, escape as re_escape, MULTILINE as RE_MULTILINE,\
    IGNORECASE as RE_IGNORECASE

from abnf_parse.structures.match_node import MatchNode


class EvaluationNode(ABC):

    def __init__(self, name: str):
        self.name = name

    def evaluate(self, source: ByteString | memoryview, offset: int = 0) -> MatchNode | None:

        source_memoryview = memoryview(source)

        for match_node in self._evaluate(source=source_memoryview, offset=offset):
            if match_node.end_offset == len(source_memoryview):
                return match_node

        return None

    @abstractmethod
    def _evaluate(self, source: memoryview, offset: int = 0) -> Iterator[MatchNode]:
        raise NotImplementedError


class AlternationNode(EvaluationNode):

    def __init__(self, *nodes: EvaluationNode, name: str | None = None):
        super().__init__(name=name or self.__class__.__name__)
        self.nodes = nodes

    def _evaluate(self, source: memoryview, offset: int = 0) -> Iterator[MatchNode]:
        for node in self.nodes:
            for match_node in node._evaluate(source=source, offset=offset):
                if self.name == self.__class__.__name__:
                    yield match_node
                else:
                    if match_node.name in {ConcatenationNode.__name__, RepetitionNode.__name__, OptionNode.__name__}:
                        children = match_node.children
                    else:
                        children = [match_node]

                    yield MatchNode(
                        name=self.name,
                        start_offset=match_node.start_offset,
                        end_offset=match_node.end_offset,
                        source=source,
                        children=children
                    )


class ConcatenationNode(EvaluationNode):

    def __init__(self, node_a: EvaluationNode | None, node_b: EvaluationNode | None, name: str | None = None):
        super().__init__(name=name or self.__class__.__name__)
        self.node_a = node_a
        self.node_b = node_b

    @classmethod
    def from_nodes(cls, *nodes: EvaluationNode) -> ConcatenationNode | None:
        last_concatenation_node: ConcatenationNode | None = None

        for node_a, node_b in pairwise(nodes):
            node_a = last_concatenation_node or node_a
            concatenation_node = ConcatenationNode(node_a=node_a, node_b=node_b)
            last_concatenation_node = concatenation_node

        return last_concatenation_node

    def _evaluate(self, source: memoryview, offset: int = 0) -> Iterator[MatchNode]:

        # TODO: Reconsider this `None` business...

        if self.node_a is None:
            raise ValueError('The left node is `None`.')

        if self.node_b is None:
            raise ValueError('The right node is `None`.')

        for match_node_a in self.node_a._evaluate(source=source, offset=offset):
            for match_node_b in self.node_b._evaluate(source=source, offset=match_node_a.end_offset):

                # Flatten unnamed, recursive concatenation nodes.

                node_a_is_concatenation_node = match_node_a.name == self.__class__.__name__
                node_b_is_concatenation_node = match_node_b.name == self.__class__.__name__

                if node_a_is_concatenation_node and node_b_is_concatenation_node:
                    children = match_node_a.children + match_node_b.children
                elif node_a_is_concatenation_node:
                    children = match_node_a.children + [match_node_b]
                elif node_b_is_concatenation_node:
                    children = [match_node_a] + match_node_b.children
                else:
                    children = [match_node_a, match_node_b]

                node_a_is_repetition_node = match_node_a.name in {RepetitionNode.__name__, OptionNode.__name__}
                node_b_is_repetition_node = match_node_b.name in {RepetitionNode.__name__, OptionNode.__name__}

                if node_a_is_repetition_node and node_b_is_repetition_node:
                    children = [*match_node_a.children, *match_node_b.children]
                elif node_a_is_repetition_node:
                    children = [*match_node_a.children, match_node_b]
                elif node_b_is_repetition_node:
                    children = [match_node_a, *match_node_b.children]

                # Yield the match. Discard children whose match length is zero.

                yield MatchNode(
                    name=self.name,
                    start_offset=match_node_a.start_offset,
                    end_offset=match_node_b.end_offset,
                    source=source,
                    children=[child for child in children if len(child) != 0]
                )


class LiteralNode(EvaluationNode):

    def __init__(self, value: bytes, case_sensitive: bool = False, name: str | None = None):
        super().__init__(name=name or self.__class__.__name__)
        self.case_sensitive: bool = case_sensitive
        self.value: bytes = value
        self._pattern: RePattern = re_compile(
            pattern=re_escape(pattern=value),
            flags=RE_MULTILINE | (RE_IGNORECASE if not case_sensitive else 0)
        )

    def _evaluate(self, source: memoryview, offset: int = 0) -> Iterator[MatchNode]:

        end_offset: int = offset + len(self.value)

        # NOTE: The type hint asserts that the string type must be `AnyStr`, but `memoryview` luckily seems to work too.
        if self._pattern.fullmatch(string=source[offset:end_offset]):
            yield MatchNode(
                name=self.name,
                start_offset=offset,
                end_offset=end_offset,
                source=source
            )


class RangedLiteralNode(EvaluationNode):

    def __init__(self, min_value: int, max_value: int, name: str | None = None):
        super().__init__(name=name or self.__class__.__name__)
        self.min_value = min_value
        self.max_value = max_value

    def _evaluate(self, source: memoryview, offset: int = 0) -> Iterator[MatchNode]:
        literal = next(iter(source[offset:]), None)
        if literal is not None and self.min_value <= literal <= self.max_value:
            yield MatchNode(
                name=self.name,
                start_offset=offset,
                end_offset=offset + 1,
                source=source
            )


class RepetitionNode(EvaluationNode):

    def __init__(self, node: EvaluationNode, min_value: int = 0, max_value: int | None = None, name: str | None = None):
        super().__init__(name=name or self.__class__.__name__)
        self.node = node
        self.min_value = min_value
        self.max_value = max_value

    def _evaluate(self, source: memoryview, offset: int = 0) -> Iterator[MatchNode]:
        match_len_to_match_list: dict[int, list[MatchNode]] = defaultdict(list)

        match_stack = []

        def horse(iteration_offset: int):
            for iteration_match_node in self.node._evaluate(source=source, offset=iteration_offset):
                match_stack.append(iteration_match_node)

                match_node = MatchNode(
                    name=self.name,
                    start_offset=offset,
                    end_offset=iteration_match_node.end_offset,
                    source=source,
                    children=list(match_stack)
                )

                if len(match_stack) == self.max_value:
                    yield match_node
                    match_stack.pop()
                    continue
                else:
                    if len(match_stack) >= self.min_value:
                        match_len_to_match_list[len(match_stack)].append(match_node)
                    yield from horse(iteration_offset=match_node.end_offset)
                    match_stack.pop()

        yield from horse(iteration_offset=offset)

        for match_len in sorted(match_len_to_match_list.keys(), reverse=True):
            for match_node in match_len_to_match_list[match_len]:
                yield match_node

        if self.min_value == 0:
            yield MatchNode(
                name=self.name,
                start_offset=offset,
                end_offset=offset,
                source=source
            )


class OptionNode(RepetitionNode):
    def __init__(self, node: EvaluationNode):
        super().__init__(node=node, min_value=0, max_value=1)
