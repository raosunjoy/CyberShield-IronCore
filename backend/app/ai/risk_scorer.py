"""
Advanced Risk Scoring Algorithm

Calculates comprehensive risk scores (0-100 scale) based on multiple
threat indicators, anomaly scores, and contextual information.
Uses weighted scoring with dynamic thresholds and temporal analysis.
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import asyncio
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level classifications"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(Enum):
    """Threat category classifications"""
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DDOS = "DDOS"
    INSIDER_THREAT = "INSIDER_THREAT"
    APT = "APT"
    UNKNOWN = "UNKNOWN"


@dataclass
class RiskComponent:
    """Individual risk component with weight and score"""
    name: str
    score: float
    weight: float
    confidence: float
    category: ThreatCategory
    evidence: List[str]
    metadata: Dict[str, Any]


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result"""
    
    overall_score: float
    risk_level: RiskLevel
    confidence: float
    primary_threats: List[ThreatCategory]
    components: List[RiskComponent]
    timestamp: datetime
    
    # Detailed breakdowns
    network_risk: float
    system_risk: float
    user_risk: float
    email_risk: float
    
    # Contextual factors
    business_impact: float
    likelihood: float
    urgency: float
    
    # Recommendations
    recommended_actions: List[str]
    escalation_required: bool
    
    # Explainability
    explanation: str
    key_indicators: Dict[str, float]


class RiskScorer:
    """
    Enterprise Risk Scoring Engine
    
    Calculates comprehensive risk scores using:
    - ML-based anomaly scores
    - Threat intelligence indicators  
    - Behavioral baselines
    - Business context
    - Historical patterns
    - Temporal analysis
    """
    
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None,
        max_workers: int = 4
    ):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Default component weights (sum to 1.0)
        self.weights = weights or {
            'anomaly_score': 0.25,
            'threat_intelligence': 0.20,
            'behavioral_baseline': 0.15,
            'network_indicators': 0.15,
            'system_indicators': 0.10,
            'user_indicators': 0.10,
            'temporal_factors': 0.05
        }
        
        # Risk level thresholds
        self.thresholds = thresholds or {
            'low_medium': 30.0,
            'medium_high': 60.0,
            'high_critical': 85.0
        }
        
        # Threat severity multipliers
        self.threat_multipliers = {
            ThreatCategory.APT: 1.5,
            ThreatCategory.DATA_EXFILTRATION: 1.4,
            ThreatCategory.PRIVILEGE_ESCALATION: 1.3,
            ThreatCategory.MALWARE: 1.2,
            ThreatCategory.PHISHING: 1.1,
            ThreatCategory.INSIDER_THREAT: 1.3,
            ThreatCategory.DDOS: 1.0,
            ThreatCategory.NETWORK_ANOMALY: 0.9,
            ThreatCategory.UNKNOWN: 0.8
        }
        
        # Business impact factors
        self.business_impact_factors = {
            'asset_criticality': 0.4,
            'data_sensitivity': 0.3,
            'user_privilege': 0.2,
            'network_position': 0.1
        }
        
        # Temporal decay factor (events lose relevance over time)
        self.temporal_decay_hours = 24
        
    async def calculate_risk_score(
        self,
        anomaly_score: float,
        threat_indicators: Dict[str, Any],
        context: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> RiskAssessment:
        """
        Calculate comprehensive risk score
        
        Args:
            anomaly_score: ML-based anomaly score (0-1)
            threat_indicators: Threat intelligence indicators
            context: Business and environmental context
            historical_data: Historical events for baseline comparison
        
        Returns:
            Comprehensive risk assessment
        """
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self._calculate_risk_score_sync,
            anomaly_score,
            threat_indicators,
            context,
            historical_data
        )
    
    def _calculate_risk_score_sync(
        self,
        anomaly_score: float,
        threat_indicators: Dict[str, Any],
        context: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]]
    ) -> RiskAssessment:
        """Synchronous risk score calculation"""
        
        components = []
        
        # 1. Anomaly Score Component
        anomaly_component = self._calculate_anomaly_component(anomaly_score)
        components.append(anomaly_component)
        
        # 2. Threat Intelligence Component
        threat_intel_component = self._calculate_threat_intel_component(threat_indicators)
        components.append(threat_intel_component)
        
        # 3. Network Indicators Component
        network_component = self._calculate_network_component(
            threat_indicators.get('network_data', {}),
            context.get('network_context', {})
        )
        components.append(network_component)
        
        # 4. System Indicators Component
        system_component = self._calculate_system_component(
            threat_indicators.get('system_data', {}),
            context.get('system_context', {})
        )
        components.append(system_component)
        
        # 5. User Behavior Component
        user_component = self._calculate_user_component(
            threat_indicators.get('user_data', {}),
            context.get('user_context', {})
        )
        components.append(user_component)
        
        # 6. Email Security Component
        email_component = self._calculate_email_component(
            threat_indicators.get('email_data', {}),
            context.get('email_context', {})
        )
        components.append(email_component)
        
        # 7. Temporal Analysis Component
        temporal_component = self._calculate_temporal_component(
            historical_data or [],
            context.get('time_context', {})
        )
        components.append(temporal_component)
        
        # Calculate weighted overall score
        overall_score = sum(
            comp.score * comp.weight 
            for comp in components
        )
        
        # Apply threat category multipliers
        primary_threats = self._identify_primary_threats(components)
        threat_multiplier = max(
            [self.threat_multipliers.get(threat, 1.0) for threat in primary_threats],
            default=1.0
        )
        
        overall_score = min(overall_score * threat_multiplier, 100.0)
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(context)
        
        # Apply business impact adjustment
        overall_score = min(overall_score * (1 + business_impact * 0.2), 100.0)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(components, context)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            overall_score, 
            components, 
            primary_threats
        )
        
        # Generate explanation
        explanation = self._generate_explanation(
            overall_score,
            components,
            primary_threats,
            business_impact
        )
        
        # Calculate component breakdowns
        network_risk = network_component.score
        system_risk = system_component.score
        user_risk = user_component.score
        email_risk = email_component.score
        
        # Key indicators for frontend display
        key_indicators = {
            comp.name: comp.score for comp in components[:5]  # Top 5 components
        }
        
        return RiskAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            confidence=confidence,
            primary_threats=primary_threats,
            components=components,
            timestamp=datetime.now(),
            network_risk=network_risk,
            system_risk=system_risk,
            user_risk=user_risk,
            email_risk=email_risk,
            business_impact=business_impact,
            likelihood=self._calculate_likelihood(components),
            urgency=self._calculate_urgency(overall_score, primary_threats),
            recommended_actions=recommendations,
            escalation_required=overall_score >= self.thresholds['high_critical'],
            explanation=explanation,
            key_indicators=key_indicators
        )
    
    def _calculate_anomaly_component(self, anomaly_score: float) -> RiskComponent:
        """Calculate risk component from ML anomaly score"""
        
        # Convert 0-1 anomaly score to 0-100 risk score
        risk_score = min(anomaly_score * 100, 100.0)
        
        # Determine threat category based on score
        if risk_score > 80:
            category = ThreatCategory.APT
        elif risk_score > 60:
            category = ThreatCategory.NETWORK_ANOMALY
        else:
            category = ThreatCategory.UNKNOWN
        
        evidence = [
            f"ML anomaly score: {anomaly_score:.3f}",
            f"Deviation from normal behavior pattern"
        ]
        
        return RiskComponent(
            name="ML Anomaly Detection",
            score=risk_score,
            weight=self.weights['anomaly_score'],
            confidence=0.9,  # High confidence in ML models
            category=category,
            evidence=evidence,
            metadata={'raw_anomaly_score': anomaly_score}
        )
    
    def _calculate_threat_intel_component(
        self, 
        threat_indicators: Dict[str, Any]
    ) -> RiskComponent:
        """Calculate risk component from threat intelligence"""
        
        risk_score = 0.0
        evidence = []
        category = ThreatCategory.UNKNOWN
        
        # IoC matches
        ioc_matches = threat_indicators.get('ioc_matches', 0)
        if ioc_matches > 0:
            risk_score += min(ioc_matches * 20, 60)
            evidence.append(f"IoC matches: {ioc_matches}")
            category = ThreatCategory.MALWARE
        
        # Malware family matches
        malware_matches = threat_indicators.get('malware_families', [])
        if malware_matches:
            risk_score += min(len(malware_matches) * 15, 40)
            evidence.append(f"Malware families: {', '.join(malware_matches[:3])}")
            category = ThreatCategory.MALWARE
        
        # APT group indicators
        apt_indicators = threat_indicators.get('apt_groups', [])
        if apt_indicators:
            risk_score += min(len(apt_indicators) * 25, 50)
            evidence.append(f"APT groups: {', '.join(apt_indicators[:2])}")
            category = ThreatCategory.APT
        
        # Reputation scores
        reputation_score = threat_indicators.get('reputation_score', 0)
        if reputation_score < -50:
            risk_score += 30
            evidence.append(f"Low reputation score: {reputation_score}")
        
        risk_score = min(risk_score, 100.0)
        
        return RiskComponent(
            name="Threat Intelligence",
            score=risk_score,
            weight=self.weights['threat_intelligence'],
            confidence=0.85,
            category=category,
            evidence=evidence,
            metadata=threat_indicators
        )
    
    def _calculate_network_component(
        self,
        network_data: Dict[str, Any],
        network_context: Dict[str, Any]
    ) -> RiskComponent:
        """Calculate network-based risk component"""
        
        risk_score = 0.0
        evidence = []
        category = ThreatCategory.NETWORK_ANOMALY
        
        # Suspicious connections
        suspicious_connections = network_data.get('suspicious_connections', 0)
        if suspicious_connections > 0:
            risk_score += min(suspicious_connections * 10, 40)
            evidence.append(f"Suspicious connections: {suspicious_connections}")
        
        # Traffic volume anomalies
        traffic_anomaly = network_data.get('traffic_anomaly_score', 0)
        if traffic_anomaly > 0.7:
            risk_score += 25
            evidence.append(f"Traffic volume anomaly: {traffic_anomaly:.2f}")
            category = ThreatCategory.DATA_EXFILTRATION
        
        # Port scanning activity
        port_scans = network_data.get('port_scans', 0)
        if port_scans > 0:
            risk_score += min(port_scans * 5, 20)
            evidence.append(f"Port scanning detected: {port_scans} attempts")
        
        # Botnet communication patterns
        botnet_indicators = network_data.get('botnet_indicators', 0)
        if botnet_indicators > 0:
            risk_score += min(botnet_indicators * 15, 35)
            evidence.append(f"Botnet communication patterns: {botnet_indicators}")
            category = ThreatCategory.MALWARE
        
        # DDoS patterns
        ddos_indicators = network_data.get('ddos_indicators', 0)
        if ddos_indicators > 0:
            risk_score += min(ddos_indicators * 20, 50)
            evidence.append(f"DDoS patterns detected: {ddos_indicators}")
            category = ThreatCategory.DDOS
        
        risk_score = min(risk_score, 100.0)
        
        return RiskComponent(
            name="Network Indicators",
            score=risk_score,
            weight=self.weights['network_indicators'],
            confidence=0.8,
            category=category,
            evidence=evidence,
            metadata=network_data
        )
    
    def _calculate_system_component(
        self,
        system_data: Dict[str, Any],
        system_context: Dict[str, Any]
    ) -> RiskComponent:
        """Calculate system-based risk component"""
        
        risk_score = 0.0
        evidence = []
        category = ThreatCategory.UNKNOWN
        
        # Failed login attempts
        failed_logins = system_data.get('failed_logins', 0)
        if failed_logins > 10:
            risk_score += min(failed_logins * 2, 30)
            evidence.append(f"Failed login attempts: {failed_logins}")
        
        # Privilege escalation attempts
        privilege_escalation = system_data.get('privilege_escalation', 0)
        if privilege_escalation > 0:
            risk_score += min(privilege_escalation * 20, 50)
            evidence.append(f"Privilege escalation attempts: {privilege_escalation}")
            category = ThreatCategory.PRIVILEGE_ESCALATION
        
        # Suspicious process activity
        suspicious_processes = system_data.get('suspicious_processes', 0)
        if suspicious_processes > 0:
            risk_score += min(suspicious_processes * 15, 40)
            evidence.append(f"Suspicious processes: {suspicious_processes}")
            category = ThreatCategory.MALWARE
        
        # File system anomalies
        file_anomalies = system_data.get('file_anomalies', 0)
        if file_anomalies > 0:
            risk_score += min(file_anomalies * 10, 25)
            evidence.append(f"File system anomalies: {file_anomalies}")
        
        # System configuration changes
        config_changes = system_data.get('config_changes', 0)
        if config_changes > 5:
            risk_score += min(config_changes * 3, 20)
            evidence.append(f"System config changes: {config_changes}")
        
        risk_score = min(risk_score, 100.0)
        
        return RiskComponent(
            name="System Indicators",
            score=risk_score,
            weight=self.weights['system_indicators'],
            confidence=0.75,
            category=category,
            evidence=evidence,
            metadata=system_data
        )
    
    def _calculate_user_component(
        self,
        user_data: Dict[str, Any],
        user_context: Dict[str, Any]
    ) -> RiskComponent:
        """Calculate user behavior risk component"""
        
        risk_score = 0.0
        evidence = []
        category = ThreatCategory.INSIDER_THREAT
        
        # Unusual access patterns
        unusual_access = user_data.get('unusual_access_patterns', 0)
        if unusual_access > 0:
            risk_score += min(unusual_access * 15, 35)
            evidence.append(f"Unusual access patterns: {unusual_access}")
        
        # Off-hours activity
        off_hours_activity = user_data.get('off_hours_activity', 0)
        if off_hours_activity > 0:
            risk_score += min(off_hours_activity * 10, 25)
            evidence.append(f"Off-hours activity: {off_hours_activity} events")
        
        # Data access anomalies
        data_access_anomalies = user_data.get('data_access_anomalies', 0)
        if data_access_anomalies > 0:
            risk_score += min(data_access_anomalies * 20, 45)
            evidence.append(f"Data access anomalies: {data_access_anomalies}")
            category = ThreatCategory.DATA_EXFILTRATION
        
        # Geographic anomalies
        geo_anomalies = user_data.get('geographic_anomalies', 0)
        if geo_anomalies > 0:
            risk_score += min(geo_anomalies * 25, 40)
            evidence.append(f"Geographic anomalies: {geo_anomalies}")
        
        risk_score = min(risk_score, 100.0)
        
        return RiskComponent(
            name="User Behavior",
            score=risk_score,
            weight=self.weights['user_indicators'],
            confidence=0.7,
            category=category,
            evidence=evidence,
            metadata=user_data
        )
    
    def _calculate_email_component(
        self,
        email_data: Dict[str, Any],
        email_context: Dict[str, Any]
    ) -> RiskComponent:
        """Calculate email security risk component"""
        
        risk_score = 0.0
        evidence = []
        category = ThreatCategory.PHISHING
        
        # Phishing indicators
        phishing_score = email_data.get('phishing_score', 0)
        if phishing_score > 0.5:
            risk_score += min(phishing_score * 60, 60)
            evidence.append(f"Phishing indicators: {phishing_score:.2f}")
        
        # Malicious attachments
        malicious_attachments = email_data.get('malicious_attachments', 0)
        if malicious_attachments > 0:
            risk_score += min(malicious_attachments * 30, 50)
            evidence.append(f"Malicious attachments: {malicious_attachments}")
            category = ThreatCategory.MALWARE
        
        # Suspicious URLs
        suspicious_urls = email_data.get('suspicious_urls', 0)
        if suspicious_urls > 0:
            risk_score += min(suspicious_urls * 20, 40)
            evidence.append(f"Suspicious URLs: {suspicious_urls}")
        
        # Sender reputation
        sender_reputation = email_data.get('sender_reputation', 0)
        if sender_reputation < -50:
            risk_score += 25
            evidence.append(f"Low sender reputation: {sender_reputation}")
        
        risk_score = min(risk_score, 100.0)
        
        return RiskComponent(
            name="Email Security",
            score=risk_score,
            weight=0.1,  # Lower weight as not always applicable
            confidence=0.8,
            category=category,
            evidence=evidence,
            metadata=email_data
        )
    
    def _calculate_temporal_component(
        self,
        historical_data: List[Dict[str, Any]],
        time_context: Dict[str, Any]
    ) -> RiskComponent:
        """Calculate temporal analysis risk component"""
        
        risk_score = 0.0
        evidence = []
        category = ThreatCategory.UNKNOWN
        
        if not historical_data:
            return RiskComponent(
                name="Temporal Analysis",
                score=0.0,
                weight=self.weights['temporal_factors'],
                confidence=0.5,
                category=category,
                evidence=["No historical data available"],
                metadata={}
            )
        
        # Calculate event frequency trends
        recent_events = [
            event for event in historical_data
            if (datetime.now() - datetime.fromisoformat(event.get('timestamp', '2000-01-01'))).total_seconds() < 3600
        ]
        
        if len(recent_events) > len(historical_data) * 0.5:
            risk_score += 30
            evidence.append(f"High recent activity: {len(recent_events)} events in last hour")
        
        # Escalation patterns
        severity_trend = self._calculate_severity_trend(historical_data)
        if severity_trend > 0.3:
            risk_score += 20
            evidence.append(f"Escalating severity trend: {severity_trend:.2f}")
        
        risk_score = min(risk_score, 100.0)
        
        return RiskComponent(
            name="Temporal Analysis",
            score=risk_score,
            weight=self.weights['temporal_factors'],
            confidence=0.6,
            category=category,
            evidence=evidence,
            metadata={'recent_events': len(recent_events)}
        )
    
    def _calculate_business_impact(self, context: Dict[str, Any]) -> float:
        """Calculate business impact factor (0-1)"""
        
        impact = 0.0
        
        # Asset criticality
        asset_criticality = context.get('asset_criticality', 0.5)  # 0-1 scale
        impact += asset_criticality * self.business_impact_factors['asset_criticality']
        
        # Data sensitivity
        data_sensitivity = context.get('data_sensitivity', 0.5)
        impact += data_sensitivity * self.business_impact_factors['data_sensitivity']
        
        # User privilege level
        user_privilege = context.get('user_privilege', 0.5)
        impact += user_privilege * self.business_impact_factors['user_privilege']
        
        # Network position criticality
        network_position = context.get('network_position', 0.5)
        impact += network_position * self.business_impact_factors['network_position']
        
        return min(impact, 1.0)
    
    def _identify_primary_threats(self, components: List[RiskComponent]) -> List[ThreatCategory]:
        """Identify primary threat categories"""
        
        # Get threat categories with significant scores
        threat_scores = {}
        for comp in components:
            if comp.score > 20:  # Only consider significant threats
                threat_scores[comp.category] = threat_scores.get(comp.category, 0) + comp.score * comp.weight
        
        # Sort by weighted score
        sorted_threats = sorted(threat_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Return top threats (max 3)
        return [threat for threat, score in sorted_threats[:3]]
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        
        if score >= self.thresholds['high_critical']:
            return RiskLevel.CRITICAL
        elif score >= self.thresholds['medium_high']:
            return RiskLevel.HIGH
        elif score >= self.thresholds['low_medium']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_confidence(
        self, 
        components: List[RiskComponent], 
        context: Dict[str, Any]
    ) -> float:
        """Calculate overall confidence in risk assessment"""
        
        # Weighted average of component confidences
        weighted_confidence = sum(
            comp.confidence * comp.weight 
            for comp in components
        ) / sum(comp.weight for comp in components)
        
        # Adjust based on data availability
        data_completeness = context.get('data_completeness', 0.8)
        
        return min(weighted_confidence * data_completeness, 1.0)
    
    def _calculate_likelihood(self, components: List[RiskComponent]) -> float:
        """Calculate likelihood of threat materialization"""
        
        # Higher scores indicate higher likelihood
        weighted_likelihood = sum(
            (comp.score / 100) * comp.weight * comp.confidence
            for comp in components
        )
        
        return min(weighted_likelihood, 1.0)
    
    def _calculate_urgency(self, score: float, threats: List[ThreatCategory]) -> float:
        """Calculate urgency factor"""
        
        base_urgency = score / 100
        
        # Increase urgency for certain threat types
        urgency_multipliers = {
            ThreatCategory.APT: 1.3,
            ThreatCategory.DATA_EXFILTRATION: 1.4,
            ThreatCategory.PRIVILEGE_ESCALATION: 1.2,
            ThreatCategory.DDOS: 1.5,
        }
        
        max_multiplier = max(
            [urgency_multipliers.get(threat, 1.0) for threat in threats],
            default=1.0
        )
        
        return min(base_urgency * max_multiplier, 1.0)
    
    def _calculate_severity_trend(self, historical_data: List[Dict[str, Any]]) -> float:
        """Calculate severity escalation trend"""
        
        if len(historical_data) < 2:
            return 0.0
        
        # Simple trend calculation (could be more sophisticated)
        recent_avg = np.mean([
            event.get('severity', 0) 
            for event in historical_data[-min(5, len(historical_data)):]
        ])
        
        older_avg = np.mean([
            event.get('severity', 0) 
            for event in historical_data[:max(1, len(historical_data)-5)]
        ])
        
        if older_avg == 0:
            return 0.0
        
        return (recent_avg - older_avg) / older_avg
    
    def _generate_recommendations(
        self,
        score: float,
        components: List[RiskComponent],
        threats: List[ThreatCategory]
    ) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        if score >= self.thresholds['high_critical']:
            recommendations.append("IMMEDIATE: Isolate affected systems and initiate incident response")
            recommendations.append("IMMEDIATE: Notify CISO and security team")
        
        if score >= self.thresholds['medium_high']:
            recommendations.append("Increase monitoring on affected assets")
            recommendations.append("Review and verify security controls")
        
        # Threat-specific recommendations
        for threat in threats:
            if threat == ThreatCategory.MALWARE:
                recommendations.append("Run full antimalware scan on affected systems")
                recommendations.append("Update threat signatures and definitions")
            elif threat == ThreatCategory.PHISHING:
                recommendations.append("Block suspicious email senders")
                recommendations.append("Educate users about phishing indicators")
            elif threat == ThreatCategory.DATA_EXFILTRATION:
                recommendations.append("Monitor data access patterns closely")
                recommendations.append("Implement data loss prevention controls")
            elif threat == ThreatCategory.APT:
                recommendations.append("Conduct threat hunting activities")
                recommendations.append("Review logs for lateral movement indicators")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _generate_explanation(
        self,
        score: float,
        components: List[RiskComponent],
        threats: List[ThreatCategory],
        business_impact: float
    ) -> str:
        """Generate human-readable explanation"""
        
        risk_level = self._determine_risk_level(score)
        
        explanation = f"Risk Level: {risk_level.value} (Score: {score:.1f}/100). "
        
        # Primary contributing factors
        top_components = sorted(components, key=lambda x: x.score * x.weight, reverse=True)[:3]
        
        if top_components:
            explanation += "Primary factors: "
            factors = []
            for comp in top_components:
                contribution = comp.score * comp.weight
                factors.append(f"{comp.name} ({contribution:.1f})")
            explanation += ", ".join(factors) + ". "
        
        # Threat categories
        if threats:
            explanation += f"Detected threats: {', '.join([t.value for t in threats])}. "
        
        # Business impact
        if business_impact > 0.7:
            explanation += "High business impact due to critical asset involvement. "
        elif business_impact > 0.4:
            explanation += "Medium business impact. "
        
        return explanation
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)