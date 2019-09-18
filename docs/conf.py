import sphinx_rtd_theme

from sphinx.cmd.build import main

extensions = [
    'sphinx_rtd_theme'
]

html_theme = "sphinx_rtd_theme"
html_static_path = ['_static']

project = 'Jetconf'
copyright = '2019, CZ.NIC, z. s. p. o.'
author = 'Aleš Mrázek'

master_doc = 'index'
