from abc import ABC


class ABNFParseError(Exception, ABC):
    pass


class NoMatchError(ABNFParseError):
    def __init__(self, rule_name: str, source: memoryview, offset: int):
        super().__init__(f'The source data did not match the rule "{rule_name}".')
        self.rule_name = rule_name
        self.source = source
        self.offset = offset


class BacktrackingLimitReachedError(ABNFParseError):
    def __init__(self, rule_name: str, source: memoryview, offset: int, count: int, limit: int):
        super().__init__(
            f'The backtracking count {count} reached the limit when evaluating the rule "{rule_name}" at the offset'
            f' {offset}.'
        )

        self.rule_name = rule_name
        self.source = source
        self.offset = offset
        self.count = count
        self.limit = limit
