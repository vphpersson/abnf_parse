from typing import Final
from abnf_parse.structures.ruleset import Ruleset
from abnf_parse.structures.evaluation_node import AlternationNode, RangedLiteralNode, LiteralNode, ConcatenationNode, \
    RepetitionNode, OptionNode


def _initialize_core_ruleset():
    core_ruleset = Ruleset({
        'ALPHA': AlternationNode(
            RangedLiteralNode(min_value=0x61, max_value=0x7A),
            RangedLiteralNode(min_value=0x41, max_value=0x5A)
        ),
        'BIT': AlternationNode(LiteralNode(value=b'0'), LiteralNode(value=b'1')),
        'CHAR': RangedLiteralNode(min_value=0x01, max_value=0x7F),
        'CTL': AlternationNode(RangedLiteralNode(min_value=0x00, max_value=0x1F), LiteralNode(value=b'\x7F')),
        'CR': LiteralNode(value=b'\x0D'),
        'LF': LiteralNode(value=b'\x0A'),
        'DIGIT': RangedLiteralNode(min_value=0x30, max_value=0x39),
        'DQUOTE': LiteralNode(value=b'\x22'),
        'SP': LiteralNode(value=b'\x20'),
        'HTAB': LiteralNode(value=b'\x09'),
        'OCTET': RangedLiteralNode(min_value=0x00, max_value=0xFF),
        'VCHAR': RangedLiteralNode(min_value=0x21, max_value=0x7E)
    })

    core_ruleset['CRLF'] = ConcatenationNode(core_ruleset['CR'], core_ruleset['LF'])

    core_ruleset['HEXDIG'] = AlternationNode(
        core_ruleset['DIGIT'],
        LiteralNode(value=b'A'),
        LiteralNode(value=b'B'),
        LiteralNode(value=b'C'),
        LiteralNode(value=b'D'),
        LiteralNode(value=b'E'),
        LiteralNode(value=b'F')
    )

    core_ruleset['WSP'] = AlternationNode(core_ruleset['SP'], core_ruleset['HTAB'])

    core_ruleset['LWSP'] = RepetitionNode(
        node=AlternationNode(core_ruleset['WSP'], ConcatenationNode(core_ruleset['CRLF'], core_ruleset['WSP']))
    )
    
    return core_ruleset


CORE_RULESET: Final[Ruleset] = _initialize_core_ruleset()

Ruleset.CORE_RULESET = CORE_RULESET


def _initialize_abnf_ruleset():
    abnf_ruleset = Ruleset({
        'quoted-string': ConcatenationNode.from_nodes(
            CORE_RULESET['DQUOTE'],
            RepetitionNode(
                AlternationNode(
                    RangedLiteralNode(0x20, 0x21),
                    RangedLiteralNode(0x23, 0x7E)
                )
            ),
            CORE_RULESET['DQUOTE']
        ),
        'prose-val': ConcatenationNode.from_nodes(
            LiteralNode(value=b'<'),
            RepetitionNode(
                node=AlternationNode(
                    RangedLiteralNode(0x20, 0x3D),
                    RangedLiteralNode(0x3F, 0x7E)
                )
            ),
            LiteralNode(value=b'>')
        ),
        'hex-val': ConcatenationNode(
            LiteralNode(value=b'x'),
            ConcatenationNode(
                RepetitionNode(CORE_RULESET['HEXDIG'], min_value=1),
                OptionNode(
                    AlternationNode(
                        RepetitionNode(
                            node=ConcatenationNode(
                                LiteralNode(value=b'.'),
                                RepetitionNode(
                                    node=CORE_RULESET['HEXDIG'],
                                    min_value=1
                                )
                            ),
                            min_value=1
                        ),
                        ConcatenationNode(
                            LiteralNode(b'-'),
                            RepetitionNode(node=CORE_RULESET['HEXDIG'], min_value=1)
                        )
                    )
                )
            )
        ),
        'dec-val': ConcatenationNode(
            LiteralNode(value=b'd'),
            ConcatenationNode(
                RepetitionNode(CORE_RULESET['DIGIT'], min_value=1),
                OptionNode(
                    AlternationNode(
                        RepetitionNode(
                            node=ConcatenationNode(
                                LiteralNode(value=b'.'),
                                RepetitionNode(
                                    node=CORE_RULESET['DIGIT'],
                                    min_value=1
                                )
                            ),
                            min_value=1
                        ),
                        ConcatenationNode(
                            LiteralNode(b'-'),
                            RepetitionNode(node=CORE_RULESET['DIGIT'], min_value=1)
                        )
                    )
                )
            )
        ),
        'bin-val': ConcatenationNode(
            LiteralNode(value=b'b'),
            ConcatenationNode(
                RepetitionNode(node=CORE_RULESET['BIT'], min_value=1),
                OptionNode(
                    node=AlternationNode(
                        RepetitionNode(
                            node=ConcatenationNode(
                                LiteralNode(value=b'.'),
                                RepetitionNode(
                                    node=CORE_RULESET['BIT'],
                                    min_value=1
                                )
                            ),
                            min_value=1
                        ),
                        ConcatenationNode(
                            LiteralNode(b'-'),
                            RepetitionNode(node=CORE_RULESET['BIT'], min_value=1)
                        )
                    )
                )
            )
        ),
        'comment': ConcatenationNode.from_nodes(
            LiteralNode(value=b';'),
            RepetitionNode(node=AlternationNode(CORE_RULESET['WSP'], CORE_RULESET['VCHAR'])),
            CORE_RULESET['CRLF']
        ),
        'rulename': ConcatenationNode(
            CORE_RULESET['ALPHA'],
            RepetitionNode(
                node=AlternationNode(
                    CORE_RULESET['ALPHA'],
                    CORE_RULESET['DIGIT'],
                    LiteralNode(value=b'-')
                )
            )
        ),
        'repeat': AlternationNode(
            ConcatenationNode.from_nodes(
                RepetitionNode(node=CORE_RULESET['DIGIT']),
                LiteralNode(value=b'*'),
                RepetitionNode(node=CORE_RULESET['DIGIT'])
            ),
            RepetitionNode(node=CORE_RULESET['DIGIT'], min_value=1)
        )
    })

    # TODO: Add support for `#` operator in `repeat`? (Not sure if it is official)

    abnf_ruleset['case-sensitive-string'] = ConcatenationNode(
        LiteralNode(value=b'%s'),
        abnf_ruleset['quoted-string']
    )

    abnf_ruleset['case-insensitive-string'] = ConcatenationNode(
        OptionNode(node=LiteralNode(value=b'%i')),
        abnf_ruleset['quoted-string']
    )

    abnf_ruleset['char-val'] = AlternationNode(
        abnf_ruleset['case-insensitive-string'],
        abnf_ruleset['case-sensitive-string']
    )

    abnf_ruleset['num-val'] = ConcatenationNode.from_nodes(
        LiteralNode(value=b'%'),
        AlternationNode(
            abnf_ruleset['bin-val'],
            abnf_ruleset['dec-val'],
            abnf_ruleset['hex-val']
        )
    )

    abnf_ruleset['c-nl'] = AlternationNode(abnf_ruleset['comment'], CORE_RULESET['CRLF'])

    abnf_ruleset['c-wsp'] = AlternationNode(
        CORE_RULESET['WSP'],
        ConcatenationNode(abnf_ruleset['c-nl'], CORE_RULESET['WSP'])
    )

    # The `alternation` rule is defined in terms of itself (alternation -> concatenation -> element -> group/option).
    # Therefore, little trickery is needed to make it work (temporarily assign `Node` in place of the `alternation`
    # evaluation node, then swap the `None` value with the node once it has been defined).
    # (?TODO: Incorporate some kind of lazy lookup? Seems advanced.)

    _option_alternation_concatenation_node = ConcatenationNode(
        node_a=ConcatenationNode(
            LiteralNode(value=b'['),
            RepetitionNode(node=abnf_ruleset['c-wsp'])
        ),
        node_b=None
    )

    CORE_RULESET['option'] = ConcatenationNode(
        ConcatenationNode(
            _option_alternation_concatenation_node,
            RepetitionNode(node=abnf_ruleset['c-wsp'])
        ),
        LiteralNode(value=b']')
    )

    _group_alternation_concatenation_node = ConcatenationNode(
        node_a=ConcatenationNode(
            LiteralNode(value=b'('),
            RepetitionNode(node=abnf_ruleset['c-wsp'])
        ),
        node_b=None
    )

    abnf_ruleset['group'] = ConcatenationNode(
        ConcatenationNode(
            _group_alternation_concatenation_node,
            RepetitionNode(node=abnf_ruleset['c-wsp'])
        ),
        LiteralNode(value=b')')
    )

    abnf_ruleset['element'] = AlternationNode(
        abnf_ruleset['rulename'],
        abnf_ruleset['group'],
        abnf_ruleset['option'],
        abnf_ruleset['char-val'],
        abnf_ruleset['num-val'],
        abnf_ruleset['prose-val']
    )

    abnf_ruleset['repetition'] = ConcatenationNode(
        OptionNode(node=abnf_ruleset['repeat']),
        abnf_ruleset['element']
    )

    abnf_ruleset['concatenation'] = ConcatenationNode(
        abnf_ruleset['repetition'],
        RepetitionNode(
            node=ConcatenationNode(
                RepetitionNode(node=abnf_ruleset['c-wsp'], min_value=1),
                abnf_ruleset['repetition']
            )
        )
    )

    _alternation = ConcatenationNode(
        abnf_ruleset['concatenation'],
        RepetitionNode(
            node=ConcatenationNode.from_nodes(
                RepetitionNode(node=abnf_ruleset['c-wsp']),
                LiteralNode(value=b'/'),
                RepetitionNode(node=abnf_ruleset['c-wsp']),
                abnf_ruleset['concatenation']
            )
        )
    )

    abnf_ruleset['alternation'] = _alternation

    _option_alternation_concatenation_node.node_b = _alternation
    _group_alternation_concatenation_node.node_b = _alternation

    abnf_ruleset['elements'] = ConcatenationNode(
        abnf_ruleset['alternation'],
        RepetitionNode(node=abnf_ruleset['c-wsp'])
    )

    abnf_ruleset['defined-as'] = ConcatenationNode.from_nodes(
        RepetitionNode(node=abnf_ruleset['c-wsp']),
        AlternationNode(LiteralNode(value=b'=/'), LiteralNode(value=b'=')),
        RepetitionNode(node=abnf_ruleset['c-wsp'])
    )

    abnf_ruleset['rule'] = ConcatenationNode.from_nodes(
        abnf_ruleset['rulename'],
        abnf_ruleset['defined-as'],
        abnf_ruleset['elements'],
        abnf_ruleset['c-nl']
    )

    abnf_ruleset['rulelist'] = RepetitionNode(
        node=AlternationNode(
            abnf_ruleset['rule'],
            ConcatenationNode(
                RepetitionNode(node=abnf_ruleset['c-wsp']),
                abnf_ruleset['c-nl']
            )
        ),
        min_value=1
    )

    return abnf_ruleset


ABNF_RULESET: Final[Ruleset] = _initialize_abnf_ruleset()
