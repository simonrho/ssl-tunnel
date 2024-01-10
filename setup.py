# DO NOT UPLOAD
from setuptools import setup, find_packages

setup(
    name='ssl-tunnel',
    version='0.3',
    packages=find_packages(),
    install_requires=[
        "pyroute2",
        "cryptography",
        "requests",
        "watchdog",
        "cffi"
    ],
    entry_points={
        'console_scripts': [
            'ssl-tunnel=ssl_tunnel.main:main',
        ],
    },
    python_requires='>=3.7',  # Specify the minimum Python version
    author='Simon Rho',
    author_email='srho@juniper.net',
    description='SSL Tunnel Tool for secure and flexible network tunneling',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
)
