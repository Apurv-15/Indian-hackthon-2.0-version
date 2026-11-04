"""
==============================================================================
                    AGENT 3: SYNTHESIZER AGENT                            
                Multi-Agent Consensus & Risk Aggregation                 
==============================================================================

ALGORITHM: Weighted Ensemble Voting with Inter-Agent Communication

Purpose:
- Aggregates results from Agent 1 (URL analysis), Agent 2 (Content analysis), 
  and Agent 4 (Prompt injection detection)
- Applies weighted consensus voting
- Detects agreement patterns between agents
- Escalates confidence when multiple agents agree

Weighting Strategy:
    Risk Score = (A1.url_risk * 0.30) + (A2.phishing * 0.40) + 
                 (A2.spam * 0.15) + (A2.ai_gen * 0.10) + 
                 (A1.domain_sim * 0.05) + (A4.injection * 0.30) + 
                 Divergence_Penalty + Sentiment_Aggression

Key Features:
1. Weighted scoring from multiple ML models
2. Divergence penalty for URL/text mismatches
3. Threat type classification based on agent consensus
4. Forensic explanation generation with evidence citation
5. Threshold-based risk level classification
"""

class SynthesizerAgent:
    def __init__(self):
        # =========================================================================
        # [FORMULA: RISK THRESHOLDS]
        # Maps numerical scores (0.0 to 1.0) into discrete threat classifications
        # Search tag: [FORMULA: THRESHOLDS]
        # =========================================================================
        self.thresholds = {
            'low': 0.22,
            'medium': 0.5,
            'high': 0.8,
            'critical': 0.95
        }
        
        # =========================================================================
        # [FORMULA: ENSEMBLE WEIGHTS]
        # Baseline contribution weights for each specialized agent in full messages
        # Search tag: [FORMULA: WEIGHTS]
        # =========================================================================
        self.weights = {
            'phishing': 0.4,           # 40% Agent 2: Content Phishing (DeBERTa + MNB)
            'url_risk': 0.3,           # 30% Agent 1: URL/Domain Risk (SVM + Heuristics)
            'spam': 0.15,              # 15% Agent 2: Spam Pattern Match
            'ai_generated': 0.1,       # 10% Agent 2: Machine Generated Copy
            'domain_similarity': 0.05, #  5% Agent 1: Homoglyph / Typosquatting
            'prompt_injection': 0.3    # 30% Agent 4: Adversarial Prompt Injection Guard
        }

    def _safe_float(self, val, default=0.0):
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default
    
    def calculate_risk_score(self, agent1_results, agent2_results, agent4_results):
        """Calculate overall risk score"""
        agent1_results = agent1_results or {}
        agent2_results = agent2_results or {}
        agent4_results = agent4_results or {}

        # =========================================================================
        # [FORMULA: RAW URL HOVER SCORING]
        # Formula used by Browser Extension on link hover / click
        # Score = max(URL, Typosquat) * 0.70 + Keywords * 0.30 + Divergence Penalty
        # Search tag: [FORMULA: URL_SCORE]
        # =========================================================================
        if agent2_results.get('is_raw_url'):
            url_risk_val = max(self._safe_float(agent1_results.get('url_ml_risk')), self._safe_float(agent1_results.get('url_risk')))
            domain_similarity = self._safe_float(agent1_results.get('domain_similarity'))
            # Typosquatting risk only applies if domain similarity is high (>= 0.75)
            sim_risk = 0.95 if domain_similarity >= 0.75 else 0.0
            a2_phishing = self._safe_float(agent2_results.get('phishing_probability'))

            # Factor in anchor-text semantic divergence if provided
            connection_score = self._safe_float(agent2_results.get('connection_score'), default=1.0)
            divergence_penalty = 0.0
            if connection_score < 0.25:
                divergence_penalty = 0.65
            elif connection_score < 0.5:
                divergence_penalty = 0.35

            # If the URL is clean (no heuristic flags, no typosquatting, no phishing keywords/divergence)
            if self._safe_float(agent1_results.get('url_risk')) == 0.0 and sim_risk == 0.0 and a2_phishing == 0.0 and divergence_penalty == 0.0:
                # Clean verified URL - ML noise must not raise threat level, but set baseline at 0.05
                return 0.05

            # Weighted: 70% Agent1 URL analysis, 30% Agent2 URL-text analysis + divergence
            combined = max(url_risk_val, sim_risk) * 0.7 + a2_phishing * 0.3 + divergence_penalty
            return min(max(combined, url_risk_val, sim_risk, divergence_penalty), 1.0)

        # =========================================================================
        # [FORMULA: FULL MESSAGE CONSENSUS SCORING]
        # Formula used for full email / message / scanner text inputs
        # Weighted sum across all 4 agents + dynamic situational penalties
        # Search tag: [FORMULA: CONSENSUS]
        # =========================================================================
        risk_score = 0.0
        
        # Give higher priority to ML based scores if available
        a1_url_ml = self._safe_float(agent1_results.get('url_ml_risk'))
        a1_url_risk = self._safe_float(agent1_results.get('url_risk'))
        url_risk_val = a1_url_ml if a1_url_ml > a1_url_risk else a1_url_risk

        a2_spam_ml = self._safe_float(agent2_results.get('spam_ml_score'))
        a2_spam_prob = self._safe_float(agent2_results.get('spam_probability'))
        spam_val = a2_spam_ml if a2_spam_ml > a2_spam_prob else a2_spam_prob
        
        phish_prob = self._safe_float(agent2_results.get('phishing_probability'))
        ai_gen_prob = self._safe_float(agent2_results.get('ai_generated_probability'))
        dom_sim = self._safe_float(agent1_results.get('domain_similarity'))
        a4_conf = self._safe_float(agent4_results.get('confidence'))

        # Weighted Agent Summation
        risk_score += phish_prob * self.weights['phishing']
        risk_score += url_risk_val * self.weights['url_risk']
        risk_score += spam_val * self.weights['spam']
        risk_score += ai_gen_prob * self.weights['ai_generated']
        risk_score += dom_sim * self.weights['domain_similarity']
        
        # Integrate Agent 4 Prompt Injection Score
        risk_score += a4_conf * self.weights['prompt_injection']
        
        # [PENALTY: SEMANTIC DIVERGENCE]
        # Penalizes mismatch between visible anchor text and actual destination URL
        connection_score = self._safe_float(agent2_results.get('connection_score', 1.0))
        if connection_score < 0.4:
            divergence_penalty = (0.4 - connection_score) * 0.5 
            risk_score += divergence_penalty
            
        # [PENALTY: URGENCY / THREAT SENTIMENT BOOST]
        # Penalizes aggressive coercive pressure detected by DistilBERT
        if agent2_results.get('sentiment_label') == 'NEGATIVE' and self._safe_float(agent2_results.get('sentiment_score')) > 0.8:
            risk_score += 0.1
            
        # [OVERRIDE: PROMPT INJECTION SAFETY FLOOR]
        # Ensures that confirmed prompt injection attacks cannot drop below HIGH risk
        a2_pi = bool(agent2_results.get('prompt_injection', False))
        a4_pi = bool(agent4_results.get('prompt_injection_detected', False))
        if a2_pi or a4_pi:
            risk_score = max(risk_score, 0.7) # Ensure at least HIGH risk if injection is detected
            
        return min(risk_score, 1.0)
    
    # =========================================================================
    # [FORMULA: RISK LEVEL GATING]
    # Maps calculated continuous score to categorical risk level
    # Search tag: [FORMULA: LEVEL_GATING]
    # =========================================================================
    def determine_risk_level(self, risk_score):
        """Convert numerical score to risk level"""
        if risk_score >= self.thresholds['critical']:
            return "CRITICAL"
        elif risk_score >= self.thresholds['high']:
            return "HIGH"
        elif risk_score >= self.thresholds['medium']:
            return "MEDIUM"
        elif risk_score >= self.thresholds['low']:
            return "LOW"
        else:
            return "MINIMAL"
    
    def determine_threat_type(self, risk_score, agent1_results, agent2_results, agent4_results):
        """Classify the type of threat"""
        agent1_results = agent1_results or {}
        agent2_results = agent2_results or {}
        agent4_results = agent4_results or {}
        threats = []
        
        a2_phish = self._safe_float(agent2_results.get('phishing_probability'))
        a1_dom_sim = self._safe_float(agent1_results.get('domain_similarity'))
        if a2_phish > 0.7 or a1_dom_sim > 0.7:
            threats.append("Phishing")
        
        a1_url_risk = self._safe_float(agent1_results.get('url_risk'))
        a1_url_ml = self._safe_float(agent1_results.get('url_ml_risk'))
        if a1_url_risk > 0.7 or a1_url_ml > 0.7:
            threats.append("Malicious URL")
        
        a2_pi = bool(agent2_results.get('prompt_injection', False))
        a4_pi = bool(agent4_results.get('prompt_injection_detected', False))
        if a2_pi or a4_pi:
            threats.append("Prompt Injection")
        
        a2_ai_gen = self._safe_float(agent2_results.get('ai_generated_probability'))
        if a2_ai_gen > 0.6:
            threats.append("AI-Generated Scam")
        
        a2_spam = max(self._safe_float(agent2_results.get('spam_probability')), self._safe_float(agent2_results.get('spam_ml_score')))
        if a2_spam > 0.7:
            threats.append("Spam")
        
        conn_score = self._safe_float(agent2_results.get('connection_score'), default=1.0)
        if conn_score < 0.4:
            threats.append("Deceptive Link Label (Divergence)")
        
        if not threats and risk_score > 0.3:
            threats.append("Suspicious Content")
        elif not threats:
            threats.append("Benign")
        
        return threats
    
    def generate_explanation(self, agent1_results, agent2_results, agent4_results, threat_types, risk_score, risk_level=None):
        """Generate detailed, context-aware forensic reasoning like a security expert."""
        risk_level = risk_level or self.determine_risk_level(risk_score)
        agent1_results = agent1_results or {}
        agent2_results = agent2_results or {}
        agent4_results = agent4_results or {}
        reasons = []
        
        # ── URL / Domain Forensics ──
        for factor in agent1_results.get('risk_factors', []):
            factor_lower = str(factor).lower()
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
        dom_sim = self._safe_float(agent1_results.get('domain_similarity'))
        if dom_sim > 0.7:
            reasons.append(f"Sender Spoofing: Domain is {dom_sim:.0%} similar to a known legitimate brand — possible impersonation attempt")
        
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
            a4_conf = self._safe_float(agent4_results.get('confidence'))
            reasons.append(f"Prompt Injection Agent: {detail} (Risk: {a4_conf:.0%}) — advanced hijacking pattern identified via transformer analysis")
        elif agent2_results.get('prompt_injection'):
            reasons.append("Prompt Injection: Heuristic pattern match — suspicious instruction override pattern detected in input text")
        
        # ── AI Generated Content ──
        ai_prob = self._safe_float(agent2_results.get('ai_generated_probability'))
        if ai_prob > 0.5:
            reasons.append(f"Content Analysis: Text shows AI-generation patterns (Score: {ai_prob:.0%}) — machine-written scam content designed to appear legitimate")

        # ── Semantic Divergence ──
        connection_score = self._safe_float(agent2_results.get('connection_score'), default=1.0)
        connection_msg = agent2_results.get('connection_message', '')
        if connection_score < 0.4:
            reasons.append(f"Hidden Threat: {connection_msg} (Divergence Score: {connection_score:.0%}) — link text says one thing but URL points somewhere completely different")
        elif connection_score < 0.6 and self._safe_float(agent1_results.get('url_risk')) > 0.3:
            reasons.append(f"Content Analysis: Weak semantic link between email text and embedded URLs ({connection_score:.0%}) — potentially deceptive link labels")
        
        # —— Sentiment / Tone ——
        sentiment_label = agent2_results.get('sentiment_label', 'UNKNOWN')
        sentiment_score = agent2_results.get('sentiment_score', 0)
        if sentiment_label == 'NEGATIVE' and sentiment_score > 0.8:
            reasons.append(f"Behavioral Threat: Highly aggressive/threatening tone detected (Score: {sentiment_score:.1%}) — intimidation tactics used to provoke panic-driven actions")
        elif sentiment_label == 'NEGATIVE' and sentiment_score > 0.5:
            reasons.append(f"Content Analysis: Negative sentiment detected (Score: {sentiment_score:.1%}) — may use fear-based language to manipulate recipient")
        
        # —— Spam Signals ——
        spam_prob = max(agent2_results.get('spam_probability', 0), agent2_results.get('spam_ml_score', 0))
        if spam_prob > 0.7:
            reasons.append(f"Content Analysis: High spam probability ({spam_prob:.0%}) — message matches known bulk/unsolicited mail patterns")
        
        # —— Safe fallback: never return empty reasoning ——
        if not reasons:
            if risk_score < 0.2:
                reasons.append("Content Analysis: No suspicious patterns, malicious URLs, or social engineering tactics detected — message appears legitimate")
                reasons.append("URL Analysis: No links found, or all URLs point to verified, trusted domains")
            else:
                reasons.append(f"Content Analysis: Minor risk signals detected (combined score: {risk_score:.0%}) but no single strong threat indicator found")
        
        # —— Recommended Actions ——
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
                "Do not unsubscribe via links — this confirms your address"
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
        
        # ── Human-Friendly Summary & Clean Reasons ──
        human_reasons = []
        for r in reasons:
            clean = r
            # Strip technical prefixes
            for pfx in ["URL Analysis (ML): ", "URL Analysis: ", "Content Analysis: ", "Sender Spoofing: ", "Behavioral Threat: ", "Prompt Injection Agent: ", "Prompt Injection: ", "Hidden Threat: "]:
                if clean.startswith(pfx):
                    clean = clean[len(pfx):]
            # Strip helper tails
            clean = clean.split(" — helper:")[0].strip()
            if clean and clean not in human_reasons:
                human_reasons.append(clean)

        # Generate 1-sentence plain-English human summary
        summary = ""
        if risk_level in ["HIGH", "CRITICAL"]:
            if "Phishing" in threat_types or any("brand" in r.lower() or "mimic" in r.lower() or "impersonat" in r.lower() for r in human_reasons):
                summary = "Dangerous link: Appears to mimic a trusted brand to steal your account credentials."
            elif "Prompt Injection" in threat_types:
                summary = "Security risk: Contains hidden adversarial commands designed to hijack AI systems."
            elif "Malicious URL" in threat_types:
                summary = "Unsafe destination: Links to an unverified or potentially compromised web address."
            else:
                summary = "High risk detected: This link exhibits strong signs of deceptive or malicious activity."
        elif risk_level == "MEDIUM":
            summary = "Suspicious link: Exhibits unusual patterns or unverified domain attributes. Proceed with caution."
        elif risk_level == "LOW":
            summary = "Minor warnings: Mostly benign, but includes uncommon links or external redirection."
        else:
            summary = "Verified safe: No phishing patterns, malicious redirects, or brand spoofing detected."

        action_advice = actions[0] if actions else "Safe to proceed."

        return {
            'reasons': reasons[:6],
            'actions': actions[:4],
            'summary': summary,
            'human_reasons': human_reasons[:4],
            'action_advice': action_advice
        }
    
    def synthesize(self, agent1_results, agent2_results, agent4_results):
        """Main synthesis function"""
        risk_score = self.calculate_risk_score(agent1_results, agent2_results, agent4_results)
        
        risk_level = self.determine_risk_level(risk_score)
        
        threat_types = self.determine_threat_type(risk_score, agent1_results, agent2_results, agent4_results)
        
        explanation = self.generate_explanation(
            agent1_results, agent2_results, agent4_results, threat_types, risk_score, risk_level
        )
        
        # Confidence: Dynamically reflects certainty in the verdict
        # Grounded in model agreement, domain verification, and signal completeness.
        # Avoid static blanket percentages (e.g. static 0.97).
        a1_factors = agent1_results.get('risk_factors', [])
        a1_ml_risk = self._safe_float(agent1_results.get('url_ml_risk'))
        a1_url_risk = self._safe_float(agent1_results.get('url_risk'))
        a2_phish = self._safe_float(agent2_results.get('phishing_probability'))
        a4_conf = self._safe_float(agent4_results.get('confidence'))

        is_verified_official = any("verified official" in str(f).lower() for f in a1_factors)
        is_internal_nav = any("internal navigation" in str(f).lower() for f in a1_factors)

        # Baseline variance between models (consensus)
        model_scores = [a1_ml_risk, a1_url_risk, a2_phish]
        if a4_conf > 0:
            model_scores.append(a4_conf)
        score_spread = max(model_scores) - min(model_scores) if model_scores else 0.0

        if risk_level == "MINIMAL":
            if is_verified_official:
                # Highly confident for recognized brand domains (96% - 99%)
                confidence = 0.96 + min(0.03, (0.15 - risk_score) * 0.2)
            elif is_internal_nav:
                confidence = 0.92 + min(0.05, (0.15 - risk_score) * 0.3)
            else:
                # Unknown / normal unflagged domains: genuine confidence based on model consensus
                # Higher consensus (lower spread) -> higher confidence, typically 78% - 92%
                consensus_factor = max(0.0, 1.0 - score_spread * 1.5)
                confidence = 0.76 + (0.16 * consensus_factor)
        elif risk_level == "LOW":
            confidence = 0.72 + (0.15 * max(0.0, 1.0 - score_spread))
        elif risk_level in ("HIGH", "CRITICAL"):
            # Strong indicator presence boosts threat detection confidence
            high_signal_count = sum(1 for s in (a1_ml_risk, a1_url_risk, a2_phish, a4_conf) if s > 0.6)
            confidence = 0.82 + min(0.16, 0.05 * high_signal_count + (risk_score - 0.7) * 0.3)
        else:  # MEDIUM
            # Moderate ambiguity
            margin = abs(risk_score - self.thresholds['medium'])
            confidence = 0.65 + (margin * 0.5)

        # Compute dedicated safety score (0.0 - 100.0%)
        # Inverts risk score and scales to a human-readable safety percentage
        safety_score = max(0.0, min(100.0, (1.0 - risk_score) * 100.0))
        
        result = {
            'threat_types': threat_types,
            'risk_level': risk_level,
            'risk_score': risk_score,
            'confidence': round(min(max(confidence, 0.50), 0.99), 4),
            'safety_score': round(safety_score, 1),
            'explanation': explanation,
            'detailed_results': {
                'agent1': agent1_results,
                'agent2': agent2_results,
                'agent4': agent4_results
            }
        }
        
        return result