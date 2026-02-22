import os
from google import genai
from pydantic import BaseModel
from dotenv import load_dotenv
load_dotenv(".env")

class LLMTimeWindow(BaseModel):
    value: int
    unit: str

class LLMCondition(BaseModel):
    metric: str
    operator: str
    value: float
    time_window: LLMTimeWindow | None = None
    aggregation: str | None = None
    currency: str | None = None

class LLMRule(BaseModel):
    rule_id: str | None = None
    rule_name: str
    description: str
    entities: list[str] | None = None
    rule_type: str
    conditions: list[LLMCondition]
    action: str
    severity: str
    confidence: float
    ambiguous: bool
    ambiguity_reasons: list[str] | None = None
    source_text: str

api_key = os.environ.get("GEMINI_API_KEY")

prompt = """Extract rules from this text:
Section 2.1: Currency Transaction Reports
All cash transactions exceeding $10,000 must be reported to FinCEN via a 
Currency Transaction Report (CTR) within 15 business days.
Aggregated transactions by the same customer totaling over $10,000 in a 24-hour 
period must also be reported.
Wire transfers of $3,000 or more require collection of originator information."""

client = genai.Client(api_key=api_key)

try:
    response = client.models.generate_content(
        model="gemini-2.5-flash", 
        contents=prompt,
        config={
            "temperature": 0.1,
            "response_mime_type": "application/json",
            "response_schema": list[LLMRule],
        },
    )
    print("SUCCESS 2.5 FLASH")
    print(response.text)
except Exception as e:
    print(f"FAILED 2.5 FLASH: {e}")

try:
    response = client.models.generate_content(
        model="gemini-1.5-pro", 
        contents=prompt,
        config={
            "temperature": 0.1,
            "response_mime_type": "application/json",
            "response_schema": list[LLMRule],
        },
    )
    print("\nSUCCESS 1.5 PRO")
    print(response.text)
except Exception as e:
    print(f"\nFAILED 1.5 PRO: {e}")
