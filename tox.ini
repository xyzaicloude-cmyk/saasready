[tox]
envlist = py{38,39,310,311,312}, lint, type, coverage
isolated_build = True
skip_missing_interpreters = True

[testenv]
# Install package and test dependencies
deps =
    pytest>=7.0.0
    pytest-cov>=4.0.0
    pytest-mock>=3.10.0
    responses>=0.23.0
    faker>=18.0.0

commands =
    pytest {posargs:tests/}

[testenv:lint]
# Code formatting and style checks
deps =
    black>=23.0.0
    flake8>=6.0.0
    isort>=5.12.0

commands =
    black --check saasready tests
    flake8 saasready tests
    isort --check-only saasready tests

[testenv:format]
# Auto-format code
deps =
    black>=23.0.0
    isort>=5.12.0

commands =
    black saasready tests
    isort saasready tests

[testenv:type]
# Type checking with mypy
deps =
    mypy>=1.0.0
    types-requests>=2.25.0

commands =
    mypy saasready

[testenv:coverage]
# Generate coverage report
deps =
    pytest>=7.0.0
    pytest-cov>=4.0.0
    pytest-mock>=3.10.0
    responses>=0.23.0

commands =
    pytest --cov=saasready --cov-report=html --cov-report=term-missing --cov-report=xml tests/

[testenv:docs]
# Build documentation
deps =
    sphinx>=6.0.0
    sphinx-rtd-theme>=1.2.0
    sphinx-autodoc-typehints>=1.22.0

commands =
    sphinx-build -W -b html docs docs/_build/html

[testenv:build]
# Build distribution packages
deps =
    build>=0.10.0
    twine>=4.0.0

commands =
    python -m build
    twine check dist/*

[flake8]
max-line-length = 100
extend-ignore = E203, E266, E501, W503
exclude =
    .git,
    __pycache__,
    .tox,
    .eggs,
    *.egg,
    build,
    dist,
    .venv,
    venv

[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    -ra
    -q
    --strict-markers
    --cov=saasready
    --cov-report=term-missing
    --cov-report=html

[coverage:run]
source = saasready
omit =
    */tests/*
    */__pycache__/*

[coverage:report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    if TYPE_CHECKING:
    @abstractmethod