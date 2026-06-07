from domains._base import pack as _pack
from domains import _fixtures_shared as _fx


class _Fixtures:
    @staticmethod
    def technical_sections():
        return dict(_fx.DATA_SECTIONS)

    @staticmethod
    def board_sections():
        return dict(_fx.DATA_SECTIONS)


class _FixturesAr:
    @staticmethod
    def technical_sections():
        return _fx.ar_mirror(_fx.DATA_SECTIONS)

    @staticmethod
    def board_sections():
        return _fx.ar_mirror(_fx.DATA_SECTIONS)


pack = _pack('data', 'Data Management', 'إدارة البيانات',
              fixtures_ar=_FixturesAr, fixtures_en=_Fixtures,
              frameworks=['ndmo'])
