from setuptools import setup, find_packages

setup(
    name="role_intelligence",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "networkx>=3.1",
        "scikit-learn>=1.3.0",
        "python-jose>=3.3.0",
        "pydantic>=2.0.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "python-dotenv>=1.0.0",
        "openai>=1.0.0",
        "langchain>=0.0.300",
        "neo4j>=5.0.0",
    ],
    python_requires=">=3.9",
) 