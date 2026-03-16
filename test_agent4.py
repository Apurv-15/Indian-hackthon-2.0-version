import sys, os
sys.path.append(os.path.join(os.getcwd(), 'ai_agent'))
from agents.agent4_prompt import PromptInjectionAgent
print("Starting initialization...")
try:
    agent = PromptInjectionAgent()
    print("Success!")
except Exception as e:
    print(f"Error: {e}")
