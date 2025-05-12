# AI/LLM Integration

This module leverages OpenAI and LangChain for advanced analytics, recommendations, and natural language processing.

## Purpose
- Enable natural language queries about roles, permissions, and risks.
- Provide AI-driven recommendations and anomaly detection.
- Generate human-readable reports and explanations.

## Key Functions
- `analyze_access_patterns()`: Detects unusual or risky access patterns.
- `generate_natural_language_report()`: Summarizes system state in plain language.
- `answer_natural_language_query(query: str)`: Answers user questions about the IAM system.

## Inputs
- User queries (text)
- System data (roles, permissions, logs)

## Outputs
- Natural language answers, recommendations, and reports.

## Example Usage
```python
answer = ai_engine.answer_natural_language_query("Which roles have the highest risk?")
print(answer)
``` 