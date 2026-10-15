# Third-party notices

The browser terminal bundles **@xterm/xterm 5.5.0**, distributed under the MIT license. Preserve [the complete copyright and license notice](atlas/static/vendor/xterm-LICENSE.txt) with these files. [Bundle provenance](atlas/static/vendor/xterm-provenance.json) records the verified official npm tarball integrity. The library is served locally; no CDN script is required.

Node, Python, Playwright/Chromium, cryptography, h2, aioquic and wsproto are separately installed runtimes/dependencies rather than source-package bundles. Preserve their upstream notices in deployed runtime distributions. Atlas's original code remains all rights reserved; see [LICENSE](LICENSE).

Desktop installation separately obtains pywebview 6.2.1 (BSD-3-Clause), pythonnet/clr_loader on Windows, and Qt/PySide6 on Linux through their published packages. These are not bundled into the Atlas source/wheel or relicensed by its original-code notice. Retain the notices and applicable terms shipped with those dependencies; Qt module terms differ and must be reviewed before distributing a bundled native runtime. This release supplies Python installer scripts and does not ship a frozen Qt/Windows executable. Sources: [pywebview package](https://pypi.org/project/pywebview/), [Qt for Python licensing](https://doc.qt.io/qtforpython-6/licenses.html).

Public advisory records have separate provider terms and attribution, described in [vulnerability scans](docs/vulnerability-scans.md).

The explicit Linux system-Qt profile reuses distribution-provided Qt 6 bindings and QtPy instead of bundling them. Preserve the notices supplied by those packages. The source/wheel release contains no frozen Qt runtime.
