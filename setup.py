from setuptools import find_packages, setup

setup(
    name='u2parser',
    version='1.0.5',
    author='Diego Fernandez',
    author_email='di3g0bs0n@gmail.com',
    description=('A parser for Unified2 logs (Snort).'),
    long_description='A unified2 log parser which reads a file, and returns all records in json format.',
    license='GPLv3',
    keywords='snort unified2 parser',
    packages=['.'],
    url='',
    install_requires=['netaddr==0.7.18'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2.7',
        'Topic :: Utilities'
    ]
)