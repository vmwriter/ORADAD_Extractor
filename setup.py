from setuptools import setup, find_packages

setup(
    name="oradad_extractor",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'plotly>=5.18.0',
        'jinja2>=3.1.2',
        'python-dateutil>=2.8.2',
        'networkx>=3.1',
        'pyvis>=0.3.1'
    ],
    entry_points={
        'console_scripts': [
            'oradad-extract=oradad_extractor.main:main',
        ],
    },
    python_requires='>=3.8',
) 