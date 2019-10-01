.. include:: references.rst
.. _developers:

**************
For Developers
**************

.. warning::

    It is highly recommended to set up a virtual environment for Jetconf
    development. The following procedure uses the ``venv`` module for this
    purpose (it is included in the standard Python library since
    version 3.3).

Development Environment
=======================

#. Install the latest stable **Python3** version.
#. Clone the Jetconf project in a directory of your choice::

    $ git clone https://github.com/CZ-NIC/jetconf.git

#. Create the virtual environment::

    $ python3 -m venv jetconf

#. Activate the virtual environment::

    $ cd jetconf
    $ source bin/activate

#. Install required standard packages inside the virtual environment::

    $ make install-deps

If you are prompted to upgrade ``pip``, you can do that, too.

When you are inside the virtual environment, the shell prompt should change to
something like::

    (jetconf) $


To leave the virtual environment, just do::

    $ deactivate

.. tip::
    The virtual environment can be entered anytime later by executing step 4.
    The steps preceding it need to be performed just once.

The setup described above has a few consequences that have to be kept in mind:

- Any project files that need to go to ``bin`` (executable Python scripts),``include`` or ``lib`` have to be added as exceptions to *.gitignore*, for example::

    !bin/jetconf

- After adding a new Python module dependency, it is necessary to run::

    $ make deps

and commit the new content of ``requirements.txt``.



.. Tools and Rules
    ===============

    Programming Style
    -----------------

    We can mostly follow `Google Python Style Guide <https://google.github.io/styleguide/pyguide.html>`_.


    All module-level functions and class/object methods should be annotated with type hints.
    For other values, type hints should be used where it seems important.
    See `PEP 0484`_.

    Static Type Checking
    --------------------

    Later we might use mypy_.
    Currently it doesn't work well will Python 3.5.

    Unit Tests
    ----------

    We use pytest_.

    Documentation
    -------------

    We use Sphinx_ for creating documentation.
    Docstrings in the code should therefore use Sphinx directives,
    see this `example <http://www.sphinx-doc.org/en/stable/domains.html#info-field-lists>`_.

Run from source
===============
For development purposes, Jetconf can also be started directly
from git repository with ``run.py`` script::

    $ ./run.py -c <path_to_config_file.yaml>

