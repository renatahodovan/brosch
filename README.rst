======
BroSCH
======
*Browser Security Commit History Mining Tool*


Preparations
============

The tool is written in Python 3, so make sure Python_ and pip_ are installed.

.. _Python: https://www.python.org
.. _pip: https://pip.pypa.io

If the basic Python environment is ready, clone the project::

    git clone https://github.com/renatahodovan/brosch.git

Then, install Python requirements (a good practice is to do that in an isolated
virtual environment)::

    cd brosch
    python3 -m venv venv
    source venv/bin/activate
    pip3 install -r requirements.txt


Mining Security-related Commits from Browser Projects
=====================================================

The retrieval of security-related commits is a three-step process. First, the
commit history (log) of a project is processed and all referenced issue (bug)
IDs are *collected* from the commit messages. Then, the issue tracker of the
project is queried to *identify* those issue IDs (from the list previously
collected) that are security-related. Finally, the commit history is processed
again and the security-related issue IDs are *matched* to commits.

Currently, the tool supports the mining of two open source browser projects:
WebKit_ and Firefox_.

.. _WebKit: https://webkit.org
.. _Firefox: https://www.mozilla.org/en-US/firefox/

As the tool requires the commit history of the projects, the repositories should
be cloned locally. The projects use various version control systems (Subversion
and Mercurial) but fortunately both have official Git mirrors, so the tool is
written to support the mining of git logs. So, both projects can be processed
uniformly::

    git clone git://git.webkit.org/WebKit.git
    git clone https://github.com/mozilla/gecko-dev.git

Once all necessary components (the tool and the repositories) are available, the
mining can start along the above outlined steps. To get the security-related
commits of WebKit, run::

    ./brosch.py -b webkit collect -r ./WebKit
    ./brosch.py -b webkit identify
    ./brosch.py -b webkit match -r ./WebKit

The same works for Firefox, too::

    ./brosch.py -b firefox collect -r ./gecko-dev
    ./brosch.py -b firefox identify
    ./brosch.py -b firefox match -r ./gecko-dev

The first two steps generate various intermediate files but the final result of
the tool is written to a JSON_ file named ``${PROJECTNAME}_sec_commits.json``.
The structure of the output is documented in a schema_. (For its interpretation,
see the `JSON Schema`_ specification.)

.. _schema: brosch-schema.json

**Notes:**

- The working directory of the tool is the current directory. If you don't want
  to pollute this directory, pass ``-o DIR`` to the tool.
- The *identify* step can be heavily time-consuming as the issue trackers **must
  not** be flooded with requests. Even so, network or server errors my occur.
  Thus, the *identify* step accepts ``--retry N`` to recover from transient
  failures. Should the step still fail, leading to the halt of the tool, it can
  be restarted by passing ``--from ID`` on the command line, so that already
  queried issue IDs are not queried again.
- The *collect* and *match* steps can be limited to a given time range with the
  ``--before DATETIME`` and ``--after DATETIME`` options (which are useful for
  reproducibility).
- The default output format of the *match* step is JSON_ but for the sake of
  readibility, YAML_ format is also supported via the ``--format EXT`` option.
- By default, the tool only outputs hard facts for commits in the *match* step,
  i.e., commit ID, author date, committed date, and the list of referenced
  security-related issue IDs. When ``--extended`` is passed, the output gets
  more verbose and includes author, committer, and commit message information as
  well.
- The description of the available command line options is also available via
  the ``--help`` option.

.. _JSON: https://www.json.org
.. _JSON Schema: https://json-schema.org
.. _YAML: https://yaml.org

**Example:**

A typical invocation of the tool is as follows (utilizing some of the above
mentioned additional options)::

    ./brosch.py -b webkit -o out-wk collect -r ./WebKit --before "2019-01-01 00:00:00"
    ./brosch.py -b webkit -o out-wk identify --retry 2
    ./brosch.py -b webkit -o out-wk match -r ./WebKit --before "2019-01-01 00:00:00" --format yaml --extended

These steps will result the list of commits of the WebKit project that reference
security-related issues and have been landed in the repository up until the end
of year 2018, in YAML format, including author, commiter, and commit message
details.

**Dataset:**

Results of the tool are published separately in the `BroSCH Dataset`_
repository.

.. _BroSCH Dataset: https://github.com/renatahodovan/brosch-dataset


Copyright and Licensing
=======================

The project is licensed under the BSD 3-Clause License_.

.. _License: LICENSE.rst
