from __future__ import annotations
from typing import Iterator, ByteString
from functools import cached_property, partial
from collections import ChainMap, UserDict

from abnf_parse.structures.evaluation_node import EvaluationNode, AlternationNode, RangedLiteralNode, LiteralNode, \
    ConcatenationNode, RepetitionNode, OptionNode
from abnf_parse.structures.match_node import MatchNode


class Ruleset(UserDict):
    CORE_RULESET: Ruleset | None = None

    @cached_property
    def _retrieve_map(self):
        return ChainMap(self.data, self.CORE_RULESET or {})

    def __setitem__(self, key: str, value: EvaluationNode):
        value.name = key
        super().__setitem__(key, value)

    def __getitem__(self, item: str) -> EvaluationNode:
        # If the rule cannot be found in the current ruleset, a lookup will be performed in the core ruleset.
        return self._retrieve_map.__getitem__(item)

    def update_from_source(self, source: ByteString | memoryview) -> Ruleset | None:
        """
        Read ABNF rules from source data and update an existing ruleset.

        :param source: Source data from which to read ABNF rules.
        :return: The provided ruleset if the source could be parsed, otherwise `None`.
        """

        from abnf_parse.rulesets import ABNF_RULESET

        match_node: MatchNode | None = ABNF_RULESET['rulelist'].evaluate(source=source)
        if not MatchNode:
            return None

        for rule_node in match_node.get_field(name='rule', as_list=True):
            name: bytes = rule_node.get_field(name='rulename').get_value()
            rule: EvaluationNode = _node_from_alternation(
                alternation=rule_node.get_field(name='elements').get_field(name='alternation'),
                ruleset=self
            )

            self[name.decode()] = rule

        return self

    @classmethod
    def from_source(cls, source: ByteString | memoryview) -> Ruleset | None:
        return cls().update_from_source(source=source)


def _nodes_from_concatenation(concatenation, ruleset: Ruleset) -> Iterator[EvaluationNode]:
    """
    Turn an ABNF concatenation node into corresponding evaluation nodes.

    :param concatenation: The ABNF concatenation node to be converted.
    :param ruleset: A ruleset from which to retrieve referenced rules.
    :return: An iterator yielding evaluation nodes corresponding to the ABNF concatenation node.
    """

    first_repetition = concatenation.get_field(name='repetition')
    later_repetitions = [
        concatenation_child.get_field(name='repetition')
        for concatenation_child in concatenation.children[1:]
    ]

    for repetition in (first_repetition, *later_repetitions):
        element_child = repetition.get_field(name='element').children[0]

        match name := element_child.name:
            case 'rulename':
                node = ruleset[element_child.get_value().decode()]
            case 'group':
                node = _node_from_alternation(
                    alternation=next(element_child.search(name='alternation')),
                    ruleset=ruleset
                )
            case 'option':
                node = OptionNode(
                    node=_node_from_alternation(
                        alternation=next(element_child.search(name='alternation')),
                        ruleset=ruleset
                    )
                )
            case 'char-val':
                value = b''.join(
                    quoted_string_child.get_value()
                    for quoted_string_child in next(element_child.search(name='quoted-string')).children
                    if quoted_string_child.name != 'DQUOTE'
                )

                match char_val_type := element_child.children[0].name:
                    case 'case-insensitive-string':
                        case_sensitive = False
                    case 'case-sensitive-string':
                        case_sensitive = True
                    case _:
                        raise ValueError(f'Unexpected char-val type: {char_val_type}')

                node = LiteralNode(value=value, case_sensitive=case_sensitive)
            case 'num-val':
                num_val_child = element_child.children[1]

                match num_val_child_type := num_val_child.name:
                    case 'bin-val':
                        converter = partial(int, base=2)
                    case 'dec-val':
                        converter = int
                    case 'hex-val':
                        converter = partial(int, base=16)
                    case _:
                        raise ValueError(f'Unexpected num-val name: {num_val_child_type}')

                numeric_value = num_val_child.get_value()[1:]

                if b'-' in numeric_value:
                    min_value, _, max_value = numeric_value.partition(b'-')
                    node = RangedLiteralNode(min_value=converter(min_value), max_value=converter(max_value))
                elif b'.' in numeric_value:
                    node = ConcatenationNode.from_nodes(
                        *(
                            LiteralNode(
                                value=bytes([converter(value)]),
                                case_sensitive=True
                            )
                            for value in numeric_value.split(b'.')
                        )
                    )
                else:
                    node = LiteralNode(value=bytes([converter(numeric_value)]))
            case 'prose-val':
                raise NotImplementedError('prose-val')
            case _:
                raise ValueError(f'Unexpected element child name: {name}')

        if repeat := repetition.get_field(name='repeat'):
            min_value, asterisk_separator, max_value = repeat.get_value().partition(b'*')

            if not asterisk_separator:
                max_value = min_value

            yield RepetitionNode(
                node=node,
                min_value=(int(min_value) if min_value != b'' else 0),
                max_value=(int(max_value) if max_value != b'' else None)
            )
        else:
            yield node


def _node_from_alternation(alternation, ruleset: Ruleset) -> EvaluationNode:
    """
    Turn an ABNF alternation node into a corresponding evaluation nodes.

    :param alternation: The ABNF alternation node to be converted.
    :param ruleset: A ruleset from which to retrieve referenced rules.
    :return: An iterator yielding evaluation nodes corresponding to the ABNF concatenation node.
    """

    first_concatenation = alternation.get_field(name='concatenation')
    later_concatenations = [
        elements_alternation_child.get_field(name='concatenation')
        for elements_alternation_child in alternation.children[1:]
    ]

    nodes_to_be_alternated = []

    for concatenation in (first_concatenation, *later_concatenations):
        nodes_to_be_concatenated = []
        for node in _nodes_from_concatenation(concatenation=concatenation, ruleset=ruleset):
            nodes_to_be_concatenated.append(node)
        nodes_to_be_alternated.append(
            nodes_to_be_concatenated[0] if len(nodes_to_be_concatenated) == 1
            else ConcatenationNode.from_nodes(*nodes_to_be_concatenated)
        )

    if len(nodes_to_be_alternated) == 1:
        return nodes_to_be_alternated[0]
    else:
        return AlternationNode(*nodes_to_be_alternated)


