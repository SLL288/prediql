"""
Simple LLM-based vulnerability detector that analyzes response data using an LLM.
No dependencies on API, materializer, or complex detector infrastructure.
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from llama_initiator import get_llm_model

logger = logging.getLogger(__name__)

class SimpleLLMDetector:
    """Simple LLM-based vulnerability detector that analyzes response data"""
    
    def __init__(self):
        self.detection_results = []
        
    def detect_vulnerabilities(self, response_data: Dict[str, Any], node_name: str) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities using LLM analysis of response data
        
        Args:
            response_data: The GraphQL response data
            node_name: Name of the node being tested
            
        Returns:
            List of vulnerability detection results
        """
        vulnerabilities = []
        
        # Extract response data for analysis
        response_status = response_data.get('response_status', 'unknown')
        response_body = response_data.get('response_body', {})
        vulnerability_type = response_data.get('vulnerability_type', 'unknown')
        
        try:
            # Special handling for query deny bypass with two queries
            if vulnerability_type == 'query_deny_bypass' and 'query_deny_bypass_responses' in response_data:
                # Create analysis prompt for two-query case
                analysis_prompt = self._create_query_deny_bypass_analysis_prompt(response_data)
            else:
                # Create analysis prompt for single query case
                analysis_prompt = self._create_analysis_prompt(
                    response_body, 
                    response_status, 
                    vulnerability_type
                )
            
            # Get LLM analysis
            llm_response = get_llm_model(analysis_prompt)
            
            # Parse LLM response
            analysis_result = self._parse_llm_response(llm_response)
            
            if analysis_result and analysis_result.get('is_vulnerable', False):
                # Map severity to detection
                severity = analysis_result.get('severity', 'MEDIUM')
                if severity in ['CRITICAL', 'HIGH']:
                    detection = 'vulnerable'
                elif severity == 'MEDIUM':
                    detection = 'potential'
                else:
                    detection = 'safe'
                    
                vulnerabilities.append({
                    'detection_name': f"LLM: {analysis_result.get('vulnerability_type', 'Unknown Vulnerability')}",
                    'detection': detection,
                    'category': self._map_vulnerability_type_to_category(analysis_result.get('vulnerability_type', 'unknown')),
                    'description': analysis_result.get('explanation', 'LLM-detected vulnerability'),
                    'evidence': analysis_result.get('evidence', 'LLM analysis'),
                    'confidence': analysis_result.get('confidence', 0.5),
                    'llm_analysis': analysis_result
                })
                
        except Exception as e:
            logger.error(f"Error in LLM vulnerability detection: {e}")
        
        # Store results
        for vuln in vulnerabilities:
            self.detection_results.append({
                'timestamp': datetime.now().isoformat(),
                'node': node_name,
                'detection_name': vuln['detection_name'],
                'detection': vuln['detection'],
                'category': vuln['category'],
                'description': vuln['description'],
                'evidence': vuln['evidence'],
                'confidence': vuln.get('confidence', 0.5)
            })
        
        return vulnerabilities
    
    def _create_analysis_prompt(self, response_body: dict, response_status: int, vulnerability_type: str) -> str:
        """Create a prompt for the LLM to analyze the response"""
        
        # Format the response data
        response_json = json.dumps(response_body, indent=2) if isinstance(response_body, dict) else str(response_body)
        
        prompt = f"""
You are a cybersecurity expert analyzing GraphQL API responses for security vulnerabilities.

**TASK**: Analyze the following GraphQL response to determine if there is a {vulnerability_type} vulnerability.

**RESPONSE DATA**:
- Status Code: {response_status}
- Response Body: {response_json}

**ANALYSIS CRITERIA**:
Look for these types of vulnerabilities:
1. **SQL Injection**: Look for SQL error messages, unexpected data exposure, or signs of database manipulation
2. **XSS (Cross-Site Scripting)**: Look for script tags, HTML injection, or reflected content
3. **SSRF (Server-Side Request Forgery)**: Look for internal network access, file system access, or external requests
4. **Path Injection**: Look for file system access, directory traversal, or path manipulation
5. **OS Command Injection**: Look for command execution, system responses, or shell access
6. **HTML Injection**: Look for HTML tags, CSS injection, or markup manipulation
7. **Information Disclosure**: Look for schema exposure, field suggestions, or sensitive data leaks
8. **Access Control Bypass**: Look for unauthorized access, privilege escalation, or permission bypass

**IMPORTANT**:
- Only give report to the specific vulnerability type that is found which is {vulnerability_type}.
- Only mark as vulnerable if you find clear evidence of a security issue
- Be conservative - false positives are better than false negatives
- Focus on actual security risks, not just unusual responses
- Consider the context of GraphQL operations

**RESPONSE FORMAT**:
Respond with a JSON object in this exact format:
{{
    "is_vulnerable": true/false,
    "vulnerability_type": "specific_type_if_found",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
    "confidence": 0.0-1.0,
    "evidence": "specific_evidence_from_response",
    "explanation": "detailed_explanation_of_findings"
}}
"""

        return prompt
    
    def _create_query_deny_bypass_analysis_prompt(self, response_data: Dict[str, Any]) -> str:
        """Create a prompt for the LLM to analyze query deny bypass with two queries"""
        
        responses = response_data.get('query_deny_bypass_responses', {})
        non_aliased = responses.get('non_aliased', {})
        aliased = responses.get('aliased', {})
        
        # Format the response data
        non_aliased_json = json.dumps(non_aliased, indent=2) if isinstance(non_aliased, dict) else str(non_aliased)
        aliased_json = json.dumps(aliased, indent=2) if isinstance(aliased, dict) else str(aliased)
        
        prompt = f"""
You are a cybersecurity expert analyzing GraphQL API responses for query deny bypass vulnerabilities.

**TASK**: Analyze the following two GraphQL responses to determine if there is a query deny bypass vulnerability.

**QUERY DENY BYPASS DETECTION**:
This vulnerability occurs when:
1. A non-aliased query is blocked (returns 400 or contains errors)
2. An aliased query (using query aliases like "s: queryName") succeeds (returns 200 with data)
3. This indicates that access control can be bypassed using query aliases

**RESPONSE DATA**:

**Non-Aliased Query Response**:
- Status Code: {non_aliased.get('response_status', 'unknown')}
- Response Body: {non_aliased_json}

**Aliased Query Response**:
- Status Code: {aliased.get('response_status', 'unknown')}
- Response Body: {aliased_json}

**ANALYSIS CRITERIA**:
Look for these patterns that indicate query deny bypass:
1. **Non-aliased query blocked**: Status 400 or contains errors in response
2. **Aliased query succeeds**: Status 200 with data present
3. **Access control bypass**: The same operation succeeds with aliases but fails without
4. **Error patterns**: Look for access denied, forbidden, or similar error messages in non-aliased response
5. **Data presence**: Check if aliased query returns actual data

**DETECTION LOGIC**:
- If non-aliased query is blocked (400 status or errors) AND aliased query succeeds (200 status with data)
- If aliased query has errors but still returns data, mark as POTENTIAL vulnerability
- If aliased query succeeds cleanly without errors, mark as CONFIRMED vulnerability

**IMPORTANT**:
- Only mark as vulnerable if you find clear evidence of access control bypass
- Be conservative - false positives are better than false negatives
- Focus on the comparison between the two responses
- Consider the context of GraphQL query aliases

**RESPONSE FORMAT**:
Respond with a JSON object in this exact format:
{{
    "is_vulnerable": true/false,
    "vulnerability_type": "query_deny_bypass",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
    "confidence": 0.0-1.0,
    "evidence": "specific_evidence_from_responses",
    "explanation": "detailed_explanation_of_findings"
}}
"""

        return prompt
    
    def _parse_llm_response(self, llm_response: str) -> Dict[str, Any]:
        """Parse the LLM response to extract vulnerability analysis"""
        try:
            # Try to extract JSON from the response
            response_text = llm_response.strip()
            
            # Look for JSON in the response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            else:
                # Fallback: look for keywords in the response
                response_lower = llm_response.lower()
                vulnerability_indicators = [
                    'vulnerable', 'vulnerability', 'injection', 'xss', 'sql', 'ssrf',
                    'path injection', 'command injection', 'security issue', 'exploit'
                ]
                
                if any(indicator in response_lower for indicator in vulnerability_indicators):
                    return {
                        'is_vulnerable': True,
                        'vulnerability_type': 'unknown',
                        'severity': 'MEDIUM',
                        'confidence': 0.3,
                        'evidence': 'Found vulnerability indicators in response',
                        'explanation': llm_response
                    }
                
        except json.JSONDecodeError as e:
            logger.warning(f"Could not parse LLM response as JSON: {e}")
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            
        return {
            'is_vulnerable': False,
            'vulnerability_type': 'none',
            'severity': 'LOW',
            'confidence': 0.0,
            'evidence': 'No clear vulnerability indicators found',
            'explanation': 'Analysis inconclusive'
        }
    
    def _map_vulnerability_type_to_category(self, vuln_type: str) -> str:
        """Map vulnerability type to category"""
        vuln_type_lower = vuln_type.lower()
        
        if any(x in vuln_type_lower for x in ['sql', 'injection']):
            return 'Injection Attacks'
        elif any(x in vuln_type_lower for x in ['xss', 'script', 'html']):
            return 'Injection Attacks'
        elif any(x in vuln_type_lower for x in ['ssrf', 'request']):
            return 'Injection Attacks'
        elif any(x in vuln_type_lower for x in ['path', 'file', 'directory']):
            return 'Injection Attacks'
        elif any(x in vuln_type_lower for x in ['command', 'os', 'system']):
            return 'Injection Attacks'
        elif any(x in vuln_type_lower for x in ['introspection', 'schema', 'disclosure']):
            return 'Information Disclosure'
        elif any(x in vuln_type_lower for x in ['access', 'control', 'bypass']):
            return 'Access Control'
        else:
            return 'Unknown'
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics of detected vulnerabilities"""
        if not self.detection_results:
            return {
                'total_detections': 0,
                'confirmed_vulnerabilities': 0,
                'potential_vulnerabilities': 0,
                'category_breakdown': {},
                'response_breakdown': {}
            }
        
        total_detections = len(self.detection_results)
        confirmed_vulnerabilities = len([r for r in self.detection_results if r['detection'] == 'vulnerable'])
        potential_vulnerabilities = len([r for r in self.detection_results if r['detection'] == 'potential'])
        
        category_breakdown = {}
        response_breakdown = {}
        
        for result in self.detection_results:
            category = result['category']
            node = result['node']
            
            # Category breakdown
            category_breakdown[category] = category_breakdown.get(category, 0) + 1
            
            # Response breakdown
            if node not in response_breakdown:
                response_breakdown[node] = 0
            response_breakdown[node] += 1
        
        return {
            'total_detections': total_detections,
            'confirmed_vulnerabilities': confirmed_vulnerabilities,
            'potential_vulnerabilities': potential_vulnerabilities,
            'category_breakdown': category_breakdown,
            'response_breakdown': response_breakdown
        }
    
    def save_results_to_csv(self, filepath: str):
        """Save detection results to CSV file"""
        if not self.detection_results:
            return
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['timestamp', 'node', 'detection_name', 'detection', 'category', 'description', 'evidence', 'confidence']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.detection_results)
    
    def generate_classification_report(self, filepath: str):
        """Generate a classification report"""
        summary = self.get_summary_stats()
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'summary': summary,
            'detailed_results': self.detection_results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
