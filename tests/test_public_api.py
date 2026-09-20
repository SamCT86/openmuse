import openmuse


def test_public_api_is_explicit_and_importable():
    assert openmuse.__all__
    for name in openmuse.__all__: assert getattr(openmuse,name) is not None
