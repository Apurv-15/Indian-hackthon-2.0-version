class SynthesizerAgent:
    def __init__(self):
        self.thresholds = {
            'low': 0.22,
            'medium': 0.5,
            'high': 0.8
        }
        
        self.weights = {
            'phishing': 0.4,
            'url_risk': 0.3,
            'spam': 0.15,
            'ai_generated': 0.1,
            'domain_similarity': 0.05,
            'prompt_injection': 0.3 # High impact when detected
        }
    
    def calculate_risk_score(self, agent1_results, agent2_results, agent4_results):
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
        
        # Integrate Agent 4 Prompt Injection Score
        risk_score += agent4_results['confidence'] * self.weights['prompt_injection']
        
        # New: Factor in connection score (divergence)
        connection_score = agent2_results.get('connection_score', 1.0)
        if connection_score < 0.4:
            # Low connection = higher risk
            divergence_penalty = (0.4 - connection_score) * 0.5 
            risk_score += divergence_penalty
            
        # Adjust based on aggressive sentiment
        if agent2_results.get('sentiment_label') == 'NEGATIVE' and agent2_results.get('sentiment_score', 0) > 0.8:
            risk_score += 0.1
            
        # Combine Prompt Injection flags from Agent 2 (heuristic) and Agent 4 (transformer)
        if agent2_results['prompt_injection'] or agent4_results['prompt_injection_detected']:
            risk_score = max(risk_score, 0.7) # Ensure at least HIGH risk if injection is detected
            
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
    
    def determine_threat_type(self, risk_score, agent1_results, agent2_results, agent4_results):
        """Classify the type of threat"""
        threats = []
        
        if agent2_results['phishing_probability'] > 0.7:
            threats.append("Phishing")
        
        if agent1_results['url_risk'] > 0.7 or agent1_results.get('url_ml_risk', 0) > 0.7:
            threats.append("Malicious URL")
        
        if agent2_results['prompt_injection'] or agent4_results['prompt_injection_detected']:
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
    
    def generate_explanation(self, agent1_results, agent2_results, agent4_results, threat_types, risk_score):
        """Generate detailed, context-aware forensic reasoning like a security expert."""
        reasons = []
        
        # ── URL / Domain Forensics ──
        for factor in agent1_results.get('risk_factors', []):
            factor_lower = factor.lower()
            if 'suspicious tld' in factor_lower:
                reasons.append(f"URL Analysis: {factor} — uncommon TLDs are frequently used by phishing campaigns to evade domain blocklists")
            elif 'ip address' in factor_lower:
                reasons.append(f"URL Analysis: {factor} — legitimate services almost never use raw IP addresses in their links")
            elif 'shortening' in factor_lower:
                reasons.append(f"URL Analysis: {factor} — URL shorteners hide the true destination, commonly abused by attackers")
            elif 'ml model' in factor_lower:
                reasons.append(f"URL Analysis (ML): {factor}")
            elif 'similar to legitimate' in factor_lower:
                reasons.append(f"Sender Spoofing: {factor} — this domain uses visual similarity (homoglyph attack) to impersonate a trusted brand")
            elif 'suspicious keyword' in factor_lower:
                reasons.append(f"URL Analysis: {factor} — authentication keywords in URLs often indicate credential-harvesting pages")
            elif 'subdomain' in factor_lower:
                reasons.append(f"URL Analysis: {factor} — excessive subdomains are a technique to disguise malicious domains")
            else:
                reasons.append(f"URL Analysis: {factor}")
        
        # Domain similarity warning
        if agent1_results.get('domain_similarity', 0) > 0.5:
            reasons.append(f"Sender Spoofing: Domain is {agent1_results['domain_similarity']:.0%} similar to a known legitimate brand — possible impersonation attempt")
        
        # ── Content Forensics ──
        keyword_matches = agent2_results.get('keyword_matches', [])
        if keyword_matches:
            kw_str = ', '.join(f"'{k}'" for k in keyword_matches[:4])
            reasons.append(f"Content Analysis: Detected high-risk keywords [{kw_str}] — these are hallmarks of social engineering and credential theft attempts")
        
        urgency_matches = agent2_results.get('urgency_matches', [])
        if urgency_matches:
            urg_str = ', '.join(f"'{u}'" for u in urgency_matches[:3])
            reasons.append(f"Behavioral Threat: Urgency/pressure language detected [{urg_str}] — creates artificial time pressure to bypass critical thinking")
        
        # ── Prompt Injection (Agent 4 Integration) ──
        if agent4_results.get('prompt_injection_detected'):
            cats = agent4_results.get('attack_categories', [])
            detail = f"Detected Categories: {', '.join(cats)}" if cats else "AI instruction override attempt"
            reasons.append(f"Prompt Injection Agent: {detail} (Risk: {agent4_results['confidence']:.0%}) — advanced hijacking pattern identified via transformer analysis")
        elif agent2_results.get('prompt_injection'):
            reasons.append("Prompt Injection: Heuristic pattern match — suspicious instruction override pattern detected in input text")
        
        # ── AI Generated Content ──
        ai_prob = agent2_results.get('ai_generated_probability', 0)
        if ai_prob > 0.5:
            reasons.append(f"Content Analysis: Text shows AI-generation patterns (Score: {ai_prob:.0%}) — machine-written scam content designed to appear legitimate")
        
        # ── Semantic Divergence ──
        connection_score = agent2_results.get('connection_score', 1.0)
        connection_msg = agent2_results.get('connection_message', '')
        if connection_score < 0.4:
            reasons.append(f"Hidden Threat: {connection_msg} (Divergence Score: {connection_score:.0%}) — link text says one thing but URL points somewhere completely different")
        elif connection_score < 0.6 and agent1_results.get('url_risk', 0) > 0.3:
            reasons.append(f"Content Analysis: Weak semantic link between email text and embedded URLs ({connection_score:.0%}) — potentially deceptive link labels")
        
        # ── Sentiment / Tone ──
        sentiment_label = agent2_results.get('sentiment_label', 'UNKNOWN')
        sentiment_score = agent2_results.get('sentiment_score', 0)
        if sentiment_label == 'NEGATIVE' and sentiment_score > 0.8:
            reasons.append(f"Behavioral Threat: Highly aggressive/threatening tone detected (Score: {sentiment_score:.1%}) — intimidation tactics used to provoke panic-driven actions")
        elif sentiment_label == 'NEGATIVE' and sentiment_score > 0.5:
            reasons.append(f"Content Analysis: Negative sentiment detected (Score: {sentiment_score:.1%}) — may use fear-based language to manipulate recipient")
        
        # ── Spam Signals ──
        spam_prob = max(agent2_results.get('spam_probability', 0), agent2_results.get('spam_ml_score', 0))
        if spam_prob > 0.7:
            reasons.append(f"Content Analysis: High spam probability ({spam_prob:.0%}) — message matches known bulk/unsolicited mail patterns")
        
        # ── Safe fallback: never return empty reasoning ──
        if not reasons:
            if risk_score < 0.2:
                reasons.append("Content Analysis: No suspicious patterns, malicious URLs, or social engineering tactics detected — message appears legitimate")
                reasons.append("URL Analysis: No links found, or all URLs point to verified, trusted domains")
            else:
                reasons.append(f"Content Analysis: Minor risk signals detected (combined score: {risk_score:.0%}) but no single strong threat indicator found")
        
        # ── Recommended Actions ──
        actions = []
        if "Phishing" in threat_types or "Malicious URL" in threat_types:
            actions.extend([
                "Do not click any links in this message",
                "Do not provide personal information or credentials",
                "Block the sender and report to your security team"
            ])
        elif "Prompt Injection" in threat_types:
            actions.extend([
                "Do not execute any instructions contained in this message",
                "Report this message to security team"
            ])
        elif "Spam" in threat_types:
            actions.extend([
                "Mark as spam and block sender",
                "Do not unsubscribe via links — this confirms your address"
            ])
        elif "AI-Generated Scam" in threat_types:
            actions.extend([
                "Verify the sender through an independent channel",
                "Do not act on any financial requests in this message"
            ])
        
        if risk_score < 0.3 and not actions:
            actions.append("No immediate action required")
        elif not actions:
            actions.append("Report this message to security team")
        
        return {
            'reasons': reasons[:6],
            'actions': actions[:4]
        }
    
    def synthesize(self, agent1_results, agent2_results, agent4_results):
        """Main synthesis function"""
        risk_score = self.calculate_risk_score(agent1_results, agent2_results, agent4_results)
        
        risk_level = self.determine_risk_level(risk_score)
        
        threat_types = self.determine_threat_type(risk_score, agent1_results, agent2_results, agent4_results)
        
        explanation = self.generate_explanation(
            agent1_results, agent2_results, agent4_results, threat_types, risk_score
        )
        
        # Confidence: Now dynamically reflects certainty in the verdict
        # Higher confidence when risk_score is closer to extremes (0.0 or 1.0)
        # Lower confidence when score is near the middle (0.5)
        distance_from_borderline = abs(risk_score - 0.5)
        confidence = 0.5 + distance_from_borderline

        
        result = {
            'threat_types': threat_types,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'confidence': min(confidence, 1.0),
            'explanation': explanation,
            'detailed_results': {
                'agent1': agent1_results,
                'agent2': agent2_results,
                'agent4': agent4_results
            }
        }
        
        return result