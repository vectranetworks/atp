import setuptools

with open('requirements.txt') as f:
    required = f.read().splitlines()

setuptools.setup(
    name="atp",
    version="1.0",
    author="Vectra AI, Inc",
    author_email="mp@vectra.ai",
    description="Microsoft ATP API to Cognito Detect API integration",
    url="https://github.com/vectranetworks/atp",
    packages=setuptools.find_packages(),
    install_requires=required,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
    entry_points={
          'console_scripts': [
            'atp = ATP.ATP:main',
          ],
    },
    python_requires='>=3.5',
)