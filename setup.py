from distutils.core import setup
setup(name = "Analytics", version = "2.0", description = "CMSWEB Analytics",
      author = "Lassi Tuura", author_email = "lat@iki.fi",
      packages = ["Analytics"], package_dir = { "Analytics": "src" },
      data_files = [('bin', ['bin/genstats', 'bin/genstats.py'])])
