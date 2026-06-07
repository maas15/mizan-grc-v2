from domains._base import pack as _pack
from domains import _fixtures_shared as _fx


class _Fixtures:
    @staticmethod
    def technical_sections():
        return dict(_fx.GLOBAL_SECTIONS)

    board_sections = technical_sections


class _FixturesAr:
    @staticmethod
    def technical_sections():
        return _fx.ar_mirror(_fx.GLOBAL_SECTIONS)

    board_sections = technical_sections


pack = _pack('global', 'Global Standards', 'المعايير العالمية',
              fixtures_ar=_FixturesAr, fixtures_en=_Fixtures,
              frameworks=['iso_27001', 'nist_csf'])
