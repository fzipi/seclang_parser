# -*- coding: utf-8 -*-
import glob

import pytest

@pytest.fixture(scope="session")
def crs_files() -> list:
    files = glob.glob("../testdata/crs/*.conf")
    yield files

@pytest.fixture(scope="session")
def plugins_files() -> list:
    files = glob.glob("../testdata/plugins/*.conf")
    yield files

@pytest.fixture(scope="session")
def generic_test_files() -> list:
    files = glob.glob("../testdata/*.conf")
    yield files
