from domains._base import pack as _pack
from domains.cyber import fixtures_ar, fixtures_en

pack = _pack(
    'cyber',
    'Cyber Security',
    'الأمن السيبراني',
    fixtures_ar=fixtures_ar,
    fixtures_en=fixtures_en,
    frameworks=['nca_ecc', 'nca_dcc'],
)
