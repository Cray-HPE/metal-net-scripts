# Network Configuration

Small Python3 module for network scripts.

## Usage

```bash
# build
python3 setup.py build

# install
python3 setup.py install

# run the installed script "hello_world"
/usr/bin/hello_world
```

## Docs

Build documentation with Sphinx:
```bash
pip3 install .[docs]
```

## Lint & Test

Lint tests can install dependencies with:
```bash
pip3 install .[lint]
```

Unit tests can install dependencies with:
```bash
pip3 install .[unit]
```

### Automation (CI)

Use a virtualenv to run all tests.
> TODO: Add `tox.ini` file.
```bash
pip3 install .[ci]
tox -e py3
```
