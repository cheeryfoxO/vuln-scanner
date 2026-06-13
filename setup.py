from setuptools import setup, find_packages

setup(
    name="scanner",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["requests", "colorama", "tqdm"],
    entry_points={
        "console_scripts": [
            "scanner=scanner.cli:main",
        ],
    },
)
