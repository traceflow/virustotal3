import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="virustotal3",
    version="1.0.6",
    author="tr4cefl0w",
    author_email="tr4cefl0w@protonmail.com",
    description="Python 3 implementation of the VirusTotal v3 API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tr4cefl0w/virustotal3.git",
    packages=['virustotal3'],
    install_requires=[
          'requests',
      ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
