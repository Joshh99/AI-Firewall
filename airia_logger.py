import os
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

class AiriaLogger:
    """Handles logging to Airia agent"""
    
    def __init__(self):
        self.api_key = os.getenv('AIRIA_API_KEY')
        self.api_url = os.getenv('AIRIA_API_URL')
        self.enabled = bool(self.api_key and self.api_url)
        
        if not self.enabled:
            print("Airia logging disabled (missing credentials)")
    
    def log_interaction(self, original_prompt, sanitized_prompt, detections, 
                   model_used, llm_response=None, blocked=False):
        """Log a firewall interaction to Airia"""
        if not self.enabled:
            return {"success": False, "reason": "Airia disabled"}
        
        try:
            # Generate a user GUID (or use a fixed one for hackathon)
            user_guid = "00000000-0000-0000-0000-000000000001"  # Fixed for demo
            
            # Format the log message
            log_message = self._format_log_message(
                original_prompt, 
                sanitized_prompt, 
                detections, 
                model_used,
                blocked
            )
            
            # Correct payload structure
            payload = {
                "request": {
                    "userId": user_guid,
                    "userInput": log_message,
                    "asyncOutput": False
                }
            }
            
            headers = {
                "X-API-KEY": self.api_key,
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                return {"success": True, "response": response.json()}
            else:
                print(f"Airia log failed: {response.status_code} - {response.text}")
                return {
                    "success": False, 
                    "status": response.status_code,
                    "error": response.text
                }
                
        except Exception as e:
            print(f"Airia error: {e}")
            return {"success": False, "error": str(e)}
    
    def _format_log_message(self, original, sanitized, detections, model, blocked):
        """Format interaction data for Airia"""
        
        # Count detections by type
        detection_summary = {}
        for d in detections:
            dtype = d.get('type', 'unknown')
            detection_summary[dtype] = detection_summary.get(dtype, 0) + 1
        
        # Risk level
        risk_level = "HIGH" if blocked or len(detections) >= 3 else \
                     "MEDIUM" if len(detections) > 0 else "LOW"
        
        message = f"""
AI Firewall Security Log
========================
Timestamp: {datetime.now().isoformat()}
Risk Level: {risk_level}
Action: {'BLOCKED' if blocked else 'ALLOWED'}

Detection Summary:
{json.dumps(detection_summary, indent=2)}

Original Prompt Length: {len(original)} chars
Sanitized Prompt Length: {len(sanitized)} chars
Issues Detected: {len(detections)}

Model Used: {model}
"""
        return message