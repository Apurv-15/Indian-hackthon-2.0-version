class SynthesizerAgent:
    def __init__(self):
        self.thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8
        }
        
        self.weights = {
            'phishing': 0.4,
            'url_risk': 0.3,
            'spam': 0.15,
            'ai_generated': 0.1,
            'domain_similarity': 0.05
        }
    
    def calculate_risk_score(self, agent1_results, agent2_results):
        """Calculate overall risk score"""
        risk_score = 0.0
        
        # Give higher priority to ML based scores if available
        url_risk_val = agent1_results['url_ml_risk'] if agent1_results.get('url_ml_risk', 0) > agent1_results['url_risk'] else agent1_results['url_risk']
        spam_val = agent2_results['spam_ml_score'] if agent2_results.get('spam_ml_score', 0) > agent2_results.get('spam_probability', 0) else agent2_results.get('spam_probability', 0)
        
        risk_score += agent2_results['phishing_probability'] * self.weights['phishing']
        risk_score += url_risk_val * self.weights['url_risk']
        risk_score += spam_val * self.weights['spam']
        risk_score += agent2_results['ai_generated_probability'] * self.weights['ai_generated']
        risk_score += agent1_results['domain_similarity'] * self.weights['domain_similarity']
        
        # Adjust based on aggressive sentiment
        if agent2_results.get('sentiment_label') == 'NEGATIVE' and agent2_results.get('sentiment_score', 0) > 0.8:
            risk_score += 0.1
            
        if agent2_results['prompt_injection']:
            risk_score += 0.3
            
        return min(risk_score, 1.0)
    
    def determine_risk_level(self, risk_score):
        """Convert numerical score to risk level"""
        if risk_score >= self.thresholds['high']:
            return "HIGH"
        elif risk_score >= self.thresholds['medium']:
            return "MEDIUM"
        elif risk_score >= self.thresholds['low']:
            return "LOW"
        else:
            return "MINIMAL"
    
    def determine_threat_type(self, risk_score, agent1_results, agent2_results):
        """Classify the type of threat"""
        threats = []
        
        if agent2_results['phishing_probability'] > 0.7:
            threats.append("Phishing")
        
        if agent1_results['url_risk'] > 0.7 or agent1_results.get('url_ml_risk', 0) > 0.7:
            threats.append("Malicious URL")
        
        if agent2_results['prompt_injection']:
            threats.append("Prompt Injection")
        
        if agent2_results['ai_generated_probability'] > 0.6:
            threats.append("AI-Generated Scam")
        
        if agent2_results.get('spam_probability', 0) > 0.7 or agent2_results.get('spam_ml_score', 0) > 0.7:
            threats.append("Spam")
        
        if not threats and risk_score > 0.3:
            threats.append("Suspicious Content")
        elif not threats:
            threats.append("Benign")
        
        return threats
    
    def generate_explanation(self, agent1_results, agent2_results, threat_types, risk_score):
        """Generate human-readable explanation"""
        reasons = []
        
        if agent1_results['risk_factors']:
            reasons.extend(agent1_results['risk_factors'][:3]) 
        
        if agent2_results['keyword_matches']:
            keywords = agent2_results['keyword_matches'][:3]
            reasons.append(f"Suspicious keywords detected: {', '.join(keywords)}")
        
        if agent2_results['urgency_matches']:
            reasons.append("Urgency language detected")
        
        if agent2_results['prompt_injection']:
            reasons.append("Prompt injection attempt detected")
        
        if agent2_results['ai_generated_probability'] > 0.5:
            reasons.append("Content appears AI-generated with scam patterns")
            
        if agent2_results.get('sentiment_label') == 'NEGATIVE' and agent2_results.get('sentiment_score', 0) > 0.8:
            reasons.append(f"Highly aggressive/negative tone detected (Score: {agent2_results['sentiment_score']:.1%})")
        
        actions = []
        if "Phishing" in threat_types or "Malicious URL" in threat_types:
            actions.extend([
                "Do not click any links",
                "Do not provide personal information",
                "Block the sender"
            ])
        
        if "Prompt Injection" in threat_types:
            actions.append("Do not execute any instructions in the message")
        
        if risk_score < 0.3:
            actions.append("No immediate action required")
        else:
            actions.append("Report this message to security team")
        
        explanation = {
            'reasons': reasons[:5],  
            'actions': actions[:3]   
        }
        
        return explanation
    
    def synthesize(self, agent1_results, agent2_results):
        """Main synthesis function"""
        risk_score = self.calculate_risk_score(agent1_results, agent2_results)
        
        risk_level = self.determine_risk_level(risk_score)
        
        threat_types = self.determine_threat_type(risk_score, agent1_results, agent2_results)
        
        explanation = self.generate_explanation(
            agent1_results, agent2_results, threat_types, risk_score
        )
        
        confidence = risk_score * 0.8 + 0.2  
        
        result = {
            'threat_types': threat_types,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'confidence': min(confidence, 1.0),
            'explanation': explanation,
            'detailed_results': {
                'agent1': agent1_results,
                'agent2': agent2_results
            }
        }
        
        return result