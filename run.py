import uvicorn
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    # Get port from environment variable or use default
    port = int(os.getenv("PORT", "8000"))
    
    # Run the FastAPI application
    uvicorn.run(
        "role_intelligence.main:app",
        host="0.0.0.0",
        port=port,
        reload=True  # Enable auto-reload for development
    ) 