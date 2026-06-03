from domains._base import pack as _pack
from domains import _fixtures_shared as _fx


class _Fixtures:
    @staticmethod
    def technical_sections():
        return dict(_fx.AI_SECTIONS)

    board_sections = technical_sections


class _FixturesAr:
    @staticmethod
    def technical_sections():
        return _fx.ar_mirror(_fx.AI_SECTIONS)

    board_sections = technical_sections


pack = _pack('ai', 'Artificial Intelligence', 'الذكاء الاصطناعي',
              fixtures_ar=_FixturesAr, fixtures_en=_Fixtures,
              frameworks=['nist_ai_rmf'])
