"""Cyber domain canonical section schema (PR-REL1)."""

CANONICAL_TABLES = {
    'vision_objectives': {
        'header_ar': (
            '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
            ' المبرر | الإطار الزمني |'),
        'header_en': (
            '| # | Strategic Objective | Measurable Target |'
            ' Rationale | Timeframe |'),
        'columns': 5,
    },
    'roadmap': {
        'header_ar': '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |',
        'columns': 6,
    },
}
