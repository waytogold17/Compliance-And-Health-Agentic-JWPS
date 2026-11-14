from cryptagent.detectors import cn_id_is_valid, detect, score

from .conftest import nir_key


def test_valid_nir_detected_invalid_ignored():
    body = "1850775123456"
    good = f"NIR 1 85 07 75 123 456 {nir_key(body)}"
    bad = f"NIR 1 85 07 75 123 456 {(int(nir_key(body)) + 1) % 97:02d}"
    assert detect(good)["nir_fr"] == 1
    assert detect(bad)["nir_fr"] == 0


def test_corsica_nir():
    # 2A est remplacé par 19 pour le calcul de la clé
    body_num = "1850719123456"
    key = 97 - int(body_num) % 97
    assert detect(f"1 85 07 2A 123 456 {key:02d}")["nir_fr"] == 1


def test_chinese_id_checksum():
    assert cn_id_is_valid("11010519491231002X")
    assert not cn_id_is_valid("110105194912310021")
    assert detect("身份证 11010519491231002X")["id_cn"] == 1


def test_us_ssn():
    assert detect("SSN 123-45-6789")["ssn_us"] == 1
    assert detect("SSN 000-45-6789")["ssn_us"] == 0


def test_scoring_levels():
    assert score(detect("Menu de la cantine")) == "none"
    assert score(detect("contact : a.b@aphb.fr")) == "low"
    assert score(detect("Diagnostic posé, patient joignable au 06 12 34 56 78")) == "high"
    assert score(detect("IPP : 12345678")) == "high"
