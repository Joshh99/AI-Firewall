from airia_logger import AiriaLogger
import requests
import os

def test_airia_logging():
    logger = AiriaLogger()
    
    # Simulate a detection
    result = logger.log_interaction(
        original_prompt="My SSN is 123-45-6789",
        sanitized_prompt="My SSN is ***[REDACTED: SSN]***",
        detections=[
            {"type": "SSN", "snippet": "123-45-6789", "severity": "high"}
        ],
        model_used="gpt-4o-mini",
        blocked=False
    )
    
    print("Airia Test Result:", result)

def test_airia_auth():
    """Test basic Airia API authentication"""
    response = requests.get(
        f"{os.getenv('AIRIA_BASE_URL')}/v1/AgentCard",
        headers={"X-API-Key": os.getenv('AIRIA_API_KEY')},
        params={"PageSize": 1}
    )
    print(f"Airia Auth Test: {response.status_code}")
    if response.status_code == 200:
        print("Auth verified - API key has full access")
    else:
        print(f"Auth issue: {response.text}")

if __name__ == "__main__":
    test_airia_logging()
    test_airia_auth()