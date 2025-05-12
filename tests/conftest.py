import os
import pytest
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Test configuration
TEST_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "test-api-key")
TEST_TENANT_ID = "test_tenant"

@pytest.fixture
def openai_api_key():
    """Fixture to provide OpenAI API key for tests."""
    return TEST_OPENAI_API_KEY

@pytest.fixture
def tenant_id():
    """Fixture to provide tenant ID for tests."""
    return TEST_TENANT_ID 