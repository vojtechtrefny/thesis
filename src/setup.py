# -*- coding: utf-8 -*-
# setup.py
#
# Copyright (c) 2019 Vojtech Trefny
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

from setuptools import setup, find_packages


setup(name="bitlockersetup",
      version="0.1",
      description="Tool for working with BitLocker devices in GNU/Linux",
      url="https://github.com/vojtechtrefny/thesis",
      author="Vojtech Trefny",
      author_email="mail@vojtechtrefny.cz",
      classifiers=[
          "Development Status :: 3 - Alpha",
          "Environment :: Console",
          "Intended Audience :: System Administrators",
          "License :: OSI Approved :: MIT License",
          "Operating System :: POSIX :: Linux",
          "Programming Language :: Python :: 3 :: Only",
          "Topic :: System :: Filesystems",
      ],
      packages=find_packages(),
      python_requires=">=3.5",
      install_requires=["pycryptodomex", "cryptography"],
      extras_require={"test": ["pocketlint"]},
      entry_points={"console_scripts": ["bitlockersetup=bitlockersetup.bitlockersetup:main"]}
)
