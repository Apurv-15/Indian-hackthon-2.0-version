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
        
        is_legit_domain = agent1_results.get('domain_similarity', 0) == 1.0
        trust_multiplier = 0.5 if is_legit_domain else 1.0
        
        risk_score += agent2_results['phishing_probability'] * self.weights['phishing'] * trust_multiplier
        risk_score += url_risk_val * self.weights['url_risk']
        risk_score += spam_val * self.weights['spam'] * trust_multiplier
        risk_score += agent2_results['ai_generated_probability'] * self.weights['ai_generated'] * trust_multiplier
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
                reasons.append(f"URL Analysis: Unusual web address — helper:This website address ends in an unusual way (like .info or .top), which is often used in scam emails.")
            elif 'ip address' in factor_lower:
                reasons.append(f"URL Analysis: Hidden website name — helper:This link uses numbers instead of a name, which is a common trick used to hide a website's true identity.")
            elif 'shortening' in factor_lower:
                reasons.append(f"URL Analysis: Hidden link destination — helper:The link has been shortened to hide where it actually goes, making it harder to spot a scam.")
            elif 'ml model' in factor_lower:
                reasons.append(f"URL Analysis (AI): Artificial Intelligence Detection — helper:Our AI detected patterns in this link that match known malicious websites.")
            elif 'similar to legitimate' in factor_lower:
                reasons.append(f"Sender Spoofing: Fake website name — helper:This website address looks almost identical to a trusted brand but has tiny changes to trick you.")
            elif 'suspicious keyword' in factor_lower:
                reasons.append(f"URL Analysis: Suspicious keywords — helper:The link contains words related to logging in or passwords, which is often a sign of a fake login page.")
            elif 'subdomain' in factor_lower:
                reasons.append(f"URL Analysis: Overly complex link — helper:The website address is unnecessarily long and complex, which scammers use to confuse and hide the destination.")
            else:
                reasons.append(f"URL Analysis: {factor}")
        
        # Domain similarity warning
        if agent1_results.get('domain_similarity', 0) > 0.5:
            reasons.append(f"Sender Spoofing: Impersonation attempt — helper:This website address is {agent1_results['domain_similarity']:.0%} similar to a well-known brand, likely trying to trick you.")
        
        # ── Content Forensics ──
        keyword_matches = agent2_results.get('keyword_matches', [])
        if keyword_matches:
            kw_str = ', '.join(f"'{k}'" for k in keyword_matches[:4])
            reasons.append(f"Content Analysis: Risky words detected — helper:The email uses words like {kw_str} that are commonly used to trick people into giving away personal information.")
        
        urgency_matches = agent2_results.get('urgency_matches', [])
        if urgency_matches:
            urg_str = ', '.join(f"'{u}'" for u in urgency_matches[:3])
            reasons.append(f"Behavioral Threat: False sense of urgency — helper:The use of '{urg_str}' is trying to rush you into making a quick decision without thinking.")
        
        # ── Prompt Injection (Agent 4 Integration) ──
        if agent4_results.get('prompt_injection_detected'):
            reasons.append(f"AI Safety: Instruction override — helper:Our AI detected a sophisticated attempt to force the system to ignore its safety rules.")
        elif agent2_results.get('prompt_injection'):
            reasons.append("AI Safety: Suspicious instructions — helper:This email contains text that looks like it's trying to trick an AI into doing something unsafe.")
        
        # ── AI Generated Content ──
        ai_prob = agent2_results.get('ai_generated_probability', 0)
        if ai_prob > 0.5:
            reasons.append(f"Content Analysis: AI-written content — helper:This message looks like it was written by a computer (Score: {ai_prob:.0%}), which is often used for automated scams.")
        
        # ── Semantic Divergence ──
        connection_score = agent2_results.get('connection_score', 1.0)
        connection_msg = agent2_results.get('connection_message', '')
        if connection_score < 0.4:
            reasons.append(f"Hidden Threat: Misleading link text — helper:The link text says one thing, but the actual destination is completely different (Match: {connection_score:.0%}).")
        elif connection_score < 0.6 and agent1_results.get('url_risk', 0) > 0.3:
            reasons.append(f"Content Analysis: Suspicious link labels — helper:The words used for the links don't quite match where the links actually go.")
        
        # ── Sentiment / Tone ──
        sentiment_label = agent2_results.get('sentiment_label', 'UNKNOWN')
        sentiment_score = agent2_results.get('sentiment_score', 0)
        # ── Sentiment / Tone / Behavioral Analysis ──
        sentiment_label = agent2_results.get('sentiment_label', 'UNKNOWN')
        sentiment_score = agent2_results.get('sentiment_score', 0)
        urgency_matches = agent2_results.get('urgency_matches', [])
        
        # Only flag "Aggressive Tone" if sentiment is VERY negative AND there is pressure language,
        # OR if sentiment is extremely negative (>95%) which indicates direct verbal aggression.
        if sentiment_label == 'NEGATIVE':
            if sentiment_score > 0.95:
                reasons.append(f"Behavioral Threat: Extremely aggressive tone — helper:The email uses a very harsh or hostile tone that is typical of direct intimidation.")
            elif sentiment_score > 0.85 and urgency_matches:
                reasons.append(f"Behavioral Threat: High-pressure aggressive tone — helper:The email combines negative sentiment with urgency to scare you into taking quick action.")
            elif sentiment_score > 0.7:
                # Downgrade to "Suspicious Tone" rather than "Aggressive" for lower scores
                reasons.append(f"Content Analysis: Unusually negative tone — helper:The language used in this email is more negative than typical professional correspondence.")
        
        # ── Spam Signals ──
        spam_prob = max(agent2_results.get('spam_probability', 0), agent2_results.get('spam_ml_score', 0))
        is_legit_domain = agent1_results.get('domain_similarity', 0) == 1.0
        
        # For trusted domains, only flag as spam if the score is definitive (>90%)
        spam_threshold = 0.9 if is_legit_domain else 0.7
        if spam_prob > spam_threshold:
            reasons.append(f"Content Analysis: Bulk mail patterns — helper:This email matches patterns found in mass-mailed content (Spam Score: {spam_prob:.0%}).")
        elif spam_prob > 0.6 and not is_legit_domain:
            reasons.append(f"Content Analysis: Commercial language — helper:The language used is typical of promotional or commercial messages.")
        
        # ── Safe fallback: never return empty reasoning ──
        if not reasons:
            if risk_score < 0.2:
                reasons.append("Content Analysis: Safe content — helper:We didn't find any suspicious patterns, malicious links, or tricks in this email.")
                reasons.append("URL Analysis: Trusted links — helper:All links in this email point to safe and well-known websites.")
            else:
                reasons.append(f"Content Analysis: Minor concerns — helper:While we found some minor signs of risk, there isn't one big reason to worry.")
        
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