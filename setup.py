from setuptools import setup

setup(
    name='roxbury',
    package=['roxbury'],
    url='https://github.com/theavey/roxbury',
    license='Apache License 2.0',
    author='Thomas Heavey',
    author_email='thomasjheavey@gmail.com',
    description='Class for controlling some LG soundbars',
    install_requires=[
        'pycryptodome'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3'
    ],
    zip_safe=True,
)
