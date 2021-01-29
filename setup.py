from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to pytest")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = '-s -vv --color=yes'

    def run_tests(self):
        import sys
        import shlex
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(shlex.split(self.pytest_args))
        sys.exit(errno)


setup(name='pythf',
      version='1.0.2',
      author='Group-IB THF',
      author_email='tds@group-ib.com',
      license='MIT',
      description='Group-IB THF REST API Python Bindings',
      long_description=open("README.md").read(),
      long_description_content_type="text/markdown",
      packages=find_packages(exclude=['tests']),
      include_package_data=True,
      py_modules=['pythf', 'client', 'const', 'error'],
      install_requires=[
          'requests'
      ],
      tests_require=[
          'pytest==3.2.2'
      ],
      zip_safe=False,
      cmdclass={'test': PyTest},
      keywords="security sandbox gib polygon",
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Topic :: Security',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
    ]
)
