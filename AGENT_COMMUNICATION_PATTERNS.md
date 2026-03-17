# 🤝 Agent Communication & Integration Patterns

## Inter-Agent Communication Architecture

### Communication Flow Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│  MAIN ORCHESTRATOR (app.py - ThreatDetectionSystem class)       │
│                                                                 │
│  def analyze(self, user_input):                                │
│      ┌─────────────────────────────────────────────────────┐   │
│      │ PHASE 1: Preprocessing                             │   │
│      │ processed = self.preprocessor.preprocess()         │   │
│      └─────────────────────────────────────────────────────┘   │
│                 │                                              │
│                 ▼                                              │
│      ┌─────────────────────────────────────────────────────┐   │
│      │ PHASE 2: Parallel Agent Analysis                   │   │
│      │                                                     │   │
│      │ results1 = self.agent1.analyze(processed)  ──┐     │   │
│      │ results2 = self.agent2.analyze(processed)  ──┼─┐   │   │
│      │ results4 = self.agent4.analyze(user_input) ──┼─┼─┐ │   │
│      │                                              │ │ │ │   │
│      └──────────────────────────────────────────────┼─┼─┼─┘   │
│                    (Agents run in parallel)         │ │ │      │
│                                                     ▼ ▼ ▼      │
│      ┌─────────────────────────────────────────────────────┐   │
│      │ PHASE 3: Synthesis & Consensus                     │   │
│      │                                                     │   │
│      │ final = self.agent3.synthesize(                    │   │
│      │     agent1_results,                                │   │
│      │     agent2_results,                                │   │
│      │     agent4_results                                 │   │
│      │ )                                                  │   │
│      └─────────────────────────────────────────────────────┘   │
│                 │                                              │
│                 ▼                                              │
│      ┌─────────────────────────────────────────────────────┐   │
│      │ PHASE 4: Output Formatting                         │   │
│      │ return {                                           │   │
│      │     riskLevel, threatType, confidence,            │   │
│      │     explanation, recommendations,                 │   │
│      │     detailedScores                                │   │
│      │ }                                                  │   │
│      └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Agent Contracts & Data Structures

### **Input Contracts**

```python
# Agent 1 & 2: Preprocessed Input
input_data = {
    'cleaned_text': str,        # Normalized text
    'urls': List[str],          # Extracted URLs
    'domains': List[str],       # Parsed domains
    'has_urls': bool,           # Flag for URL presence
    'text_length': int          # Length of cleaned text
}

# Agent 4: Raw Input (for better prompt injection detection)
user_input = str               # Original, unmodified text
```

### **Output Contracts**

#### **Agent 1 Output Structure**
```python
agent1_results = {
    'url_risk': float,              # 0-1, heuristic-based
    'url_ml_risk': float,           # 0-1, from SVM model
    'domain_similarity': float,     # 0-1, fuzzy matching
    'suspicious_patterns': List[str],
    'risk_factors': List[str],      # Detailed findings
    'overall_risk': float           # 0-1, combined
}
```

#### **Agent 2 Output Structure**
```python
agent2_results = {
    'phishing_probability': float,      # 0-1, ensemble
    'spam_probability': float,          # 0-1, from MNB
    'spam_ml_score': float,             # 0-1, raw MNB score
    'ai_generated_probability': float,  # 0-1, pattern-based
    'keyword_matches': List[str],
    'urgency_matches': List[str],
    'prompt_injection': bool,           # Heuristic flag
    'prompt_injection_patterns': List[str],
    'sentiment_label': str,             # "POSITIVE"/"NEGATIVE"/"UNKNOWN"
    'sentiment_score': float,           # 0-1
    'connection_score': float,          # 0-1, text-URL alignment
    'connection_message': str,          # Human-readable explanation
    'transformer_score': float,         # DeBERTa output
    'using_transformer': bool
}
```

#### **Agent 4 Output Structure**
```python
agent4_results = {
    'prompt_injection_detected': bool,      # Final decision
    'confidence': float,                    # 0-1, combined score
    'risk_score': float,                    # Alias for confidence
    'matched_patterns': List[str],          # Matched regex patterns
    'attack_categories': List[str],         # [instruction_override, ...]
    'explanation': List[str]                # Human-readable reasons
}
```

#### **Agent 3 (Synthesizer) Output Structure**
```python
final_result = {
    'risk_score': float,                # 0-1, weighted ensemble
    'risk_level': str,                  # "MINIMAL"/"LOW"/"MEDIUM"/"HIGH"
    'threat_types': List[str],          # Detected threat classes
    'confidence': float,                # % agents agree
    'explanation': {
        'reasons': List[str],           # Detailed forensic findings
        'actions': List[str]            # Recommended actions
    },
    'detailed_results': {
        'agent1': dict,                 # Agent 1 full output
        'agent2': dict,                 # Agent 2 full output
        'agent4': dict                  # Agent 4 full output
    },
    'processing_time': float            # Milliseconds
}
```

---

## Agent Coordination Patterns

### **Pattern 1: Parallel Execution**
```python
# All agents run simultaneously (independent analysis)
# Fastest pattern for independent data streams

def analyze_parallel(self, user_input):
    preprocessed = self.preprocessor.preprocess(user_input)
    
    # Agents run in parallel threads (conceptually)
    results1 = self.agent1.analyze(preprocessed)   # URL analysis
    results2 = self.agent2.analyze(preprocessed)   # Content analysis
    results4 = self.agent4.analyze(user_input)     # Injection detection
    
    # Agent 3 waits for all to complete, then synthesizes
    final = self.agent3.synthesize(results1, results2, results4)
    
    return final
```

### **Pattern 2: Cascading with Feedback**
```python
# Sequential execution with feedback loops
# Useful if later agents need earlier results for context

def analyze_cascading(self, user_input):
    preprocessed = self.preprocessor.preprocess(user_input)
    
    # Agent 1 runs first
    results1 = self.agent1.analyze(preprocessed)
    
    # Pass Agent 1 findings to Agent 2 for context
    enhanced_input = {
        **preprocessed,
        'url_risk': results1['url_risk'],           # URL risk context
        'found_suspicious_urls': results1['risk_factors']
    }
    results2 = self.agent2.analyze(enhanced_input)
    
    # Agent 4 independent
    results4 = self.agent4.analyze(user_input)
    
    # Synthesize with enhanced context
    final = self.agent3.synthesize(results1, results2, results4)
    return final
```

### **Pattern 3: Adaptive Routing**
```python
# Dynamically choose agents based on input type

def analyze_adaptive(self, user_input):
    preprocessed = self.preprocessor.preprocess(user_input)
    
    if len(preprocessed['urls']) > 0:
        # Heavy URL content → prioritize Agent 1
        results1 = self.agent1.analyze(preprocessed)
        weight_override = {'url_risk': 0.50}  # Increase importance
    else:
        weight_override = None
    
    # Always run content and injection analysis
    results2 = self.agent2.analyze(preprocessed)
    results4 = self.agent4.analyze(user_input)
    
    # Synthesize with adaptive weights
    final = self.agent3.synthesize(results1, results2, results4, 
                                    weight_override=weight_override)
    return final
```

---

## Agreement Detection & Confidence Boosting

### **Consensus Matrix**
```python
# How to detect when agents agree

def calculate_consensus_confidence(self, results1, results2, results4):
    """
    Returns confidence boost when multiple agents agree on threat
    """
    agreement_matrix = {
        'high_risk_url_and_phishing': (
            results1['url_ml_risk'] > 0.7 and 
            results2['phishing_probability'] > 0.7
        ),
        'high_risk_all_three': (
            results1['url_risk'] > 0.6 and
            results2['phishing_probability'] > 0.6 and
            results4['confidence'] > 0.6
        ),
        'divergence_detected_by_both': (
            results1['domain_similarity'] > 0.5 and
            results2['connection_score'] < 0.4
        ),
        'all_urgent_indicators': (
            len(results2['urgency_matches']) > 0 and
            results2['sentiment_label'] == 'NEGATIVE' and
            results4['prompt_injection_detected']
        )
    }
    
    # Confidence = number of agreement conditions met
    agreement_count = sum(agreement_matrix.values())
    base_confidence = results3_synthesizer.confidence
    boosted_confidence = min(base_confidence + (0.05 * agreement_count), 1.0)
    
    return boosted_confidence
```

---

## Algorithm Decision Tables (Agent Coordination)

### **When to Trust Agent 1 (URL Analysis)**
```
Scenario                          → Action
─────────────────────────────────────────────────────────────
High SVM confidence (>0.8)        → Trust ML strongly, boost score
ML models unavailable             → Use heuristics only
No URLs present                   → Skip, mark 0 risk
Domain spoofing detected (>0.7)   → Alert high, compound with A2
Mixed signals (high heuristic,    → Wait for Agent 3 synthesis
low ML)
```

### **When to Trust Agent 2 (Content Analysis)**
```
Scenario                          → Action
─────────────────────────────────────────────────────────────
Multiple phishing keywords        → High confidence in MNB
Transformer & MNB disagree        → Use transformer (more robust)
High urgency + negative sentiment → Likely social engineering
Connection score < 0.2            → Text ≠ URL = HIGH alert
Benign content (greetings, etc)   → Early exit, minimal risk
```

### **When to Trust Agent 4 (Prompt Injection)**
```
Scenario                          → Action
─────────────────────────────────────────────────────────────
DeBERTa MNLI high contradiction   → Likely real injection attempt
Rule patterns match obvious       → Catch-all for known attacks
Both MNLI & rules agree           → Maximum confidence
False positive prone (high rules) → Reduce weight, trust MNLI more
No prompt injection patterns      → Confidence ≈ 0.05 baseline
```

---

## Error Handling & Fallback Strategies

### **Agent Failure Modes**
```python
class AgentFallback:
    """Graceful degradation when agents fail"""
    
    def handle_agent1_failure(self):
        """If URL analysis fails"""
        return {
            'url_risk': 0.35,           # Conservative middle ground
            'url_ml_risk': 0.0,         # No ML available
            'domain_similarity': 0.0,
            'risk_factors': ['URL analysis unavailable, using heuristics'],
            'overall_risk': 0.0
        }
    
    def handle_agent2_failure(self):
        """If content analysis fails"""
        return {
            'phishing_probability': 0.25,  # Assume lower risk
            'spam_probability': 0.1,
            'sentiment_label': 'UNKNOWN',
            'connection_score': 1.0,       # Assume aligned by default
            'keyword_matches': [],
            'urgency_matches': []
        }
    
    def handle_agent4_failure(self):
        """If prompt injection detection fails"""
        return {
            'prompt_injection_detected': False,
            'confidence': 0.0,
            'risk_score': 0.0,
            'explanation': ['Prompt injection detection unavailable']
        }
    
    def system_analyze_with_fallback(self, user_input):
        """Main entry point with full fallback support"""
        preprocessed = self.preprocessor.preprocess(user_input)
        
        try:
            results1 = self.agent1.analyze(preprocessed)
        except Exception as e:
            print(f"Agent 1 failed: {e}, using fallback")
            results1 = self.handle_agent1_failure()
        
        try:
            results2 = self.agent2.analyze(preprocessed)
        except Exception as e:
            print(f"Agent 2 failed: {e}, using fallback")
            results2 = self.handle_agent2_failure()
        
        try:
            results4 = self.agent4.analyze(user_input)
        except Exception as e:
            print(f"Agent 4 failed: {e}, using fallback")
            results4 = self.handle_agent4_failure()
        
        # Synthesizer should handle any combination gracefully
        final_result = self.agent3.synthesize(results1, results2, results4)
        return final_result
```

---

## Performance Optimization Tips

### **Parallel Processing**
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def analyze_parallel_optimized(self, user_input):
    preprocessed = self.preprocessor.preprocess(user_input)
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all agents in parallel
        future_a1 = executor.submit(self.agent1.analyze, preprocessed)
        future_a2 = executor.submit(self.agent2.analyze, preprocessed)
        future_a4 = executor.submit(self.agent4.analyze, user_input)
        
        # Collect results as they complete (no blocking)
        results1 = future_a1.result()
        results2 = future_a2.result()
        results4 = future_a4.result()
    
    # Synthesis is sequential but happens after parallel work
    final = self.agent3.synthesize(results1, results2, results4)
    return final
```

### **Caching & Memoization**
```python
from functools import lru_cache

class OptimizedSynthesizer:
    @lru_cache(maxsize=1000)
    def calculate_risk_score_cached(self, url_risk, phishing_prob, spam_prob):
        """Cache risk scores for identical inputs"""
        return (url_risk * 0.30) + (phishing_prob * 0.40) + (spam_prob * 0.15)
        
    def analyze_with_cache(self, results1, results2, results4):
        # Use cached calculations when possible
        risk_base = self.calculate_risk_score_cached(
            results1['url_risk'],
            results2['phishing_probability'],
            results2['spam_probability']
        )
        # ... continue synthesis
```

---

## Integration Checklist

- [ ] All agents return consistent output schemas
- [ ] Preprocessor standardizes input before agent analysis
- [ ] Agent 3 handles missing/failed agent results gracefully
- [ ] Error messages are informative for debugging
- [ ] Performance monitoring is in place
- [ ] Agreement detection boosts confidence when agents agree
- [ ] Fallback mechanisms prevent complete system failure
- [ ] Logging captures agent outputs for audit trails
- [ ] Unit tests cover each agent independently
- [ ] Integration tests cover multi-agent scenarios

---

**Last Updated**: March 2026  
**Version**: 2.0 - MAS Architecture & Patterns
