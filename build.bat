rd /s /q i2ftps.egg-info
rd /s /q build
move /y dist\* history\
python setup.py build sdist bdist_wheel