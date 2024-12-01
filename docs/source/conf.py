# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'shaman'
copyright = '2024, Munawwar Hussain Shelia'
author = 'Munawwar Hussain Shelia'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []
extensions = ['myst_parser', 'breathe', 'sphinx.ext.autodoc', 'sphinx.ext.githubpages']

breathe_projects = { "MyProject": "../build/oxy_docs_xml" } 

breathe_default_project = "MyProject"

html_theme = "sphinx_rtd_theme"

html_show_sourcelink = False

html_theme_options = {
    'includehidden': True,
    'analytics_id': 'G-DSS2DJ0XF1'

}
source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_static_path = ['_static']
