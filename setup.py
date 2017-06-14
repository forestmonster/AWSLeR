from distutils.core import setup

setup(
    name='AWSLeR',
    author='Forest Monsen',
    author_email='forest.monsen@gmail.com',
    install_requires=['boto3', 'docopt'],
    long_description=open('README.md').read(),
    packages=find_packages(exclude=['docs', 'tests']),
    url='https://github.com/forestmonster/AWSLeR',
    license='Apache 2.0',
    version='0.3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ]
)
