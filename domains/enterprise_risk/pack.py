from domains._base import pack as _pack
from domains import _fixtures_shared as _fx


class _Fixtures:
    @staticmethod
    def technical_sections():
        return dict(_fx.ERM_SECTIONS)

    board_sections = technical_sections


class _FixturesAr:
    @staticmethod
    def technical_sections():
        return _fx.ar_mirror(_fx.ERM_SECTIONS)

    board_sections = technical_sections


pack = _pack('erm', 'Enterprise Risk Management', 'إدارة المخاطر المؤسسية',
              fixtures_ar=_FixturesAr, fixtures_en=_Fixtures,
              frameworks=['iso_31000'])
