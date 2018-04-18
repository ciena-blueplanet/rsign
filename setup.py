from distutils.core import setup
from setuptools.command.test import test as TestCommand  # noqa
import sys


class Tox(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import tox
        errno = tox.cmdline(self.test_args)
        sys.exit(errno)


setup(
    name='rsign',
    version='0.1.3',
    author='Cyan Inc.',
    author_email='alan.braithwaite@cyaninc.com',
    packages=['rsign'],
    url='https://github.com/cyaninc/rsign',
    description="Sign HTTP(S) requests using HMAC",
    long_description=open('README.md').read(),
    tests_require=["tox"],
    cmdclass={"test": Tox},
    classifiers=[
        'License :: OSI Approved :: BSD License',
    ],
)
