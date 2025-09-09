#!/usr/bin/env python3
"""
Ethical Email Domain Analysis Tool
Purpose: Analyzes email domains for organizational and enterprise indicators
Author: Security Research Tool
Disclaimer: For legitimate security research and personal protection only
"""

import requests
import dns.resolver
import argparse
import json
import sys
import re
import whois
from datetime import datetime
from urllib.parse import urlparse
import ssl
import socket

class EthicalEmailAnalyzer:
    def __init__(self):
        self.results = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def get_domain_registration_info(self, domain):
        """Get domain registration information via WHOIS"""
        try:
            domain_info = whois.whois(domain)
            return {
                'registrar': getattr(domain_info, 'registrar', 'Unknown'),
                'creation_date': str(getattr(domain_info, 'creation_date', 'Unknown')),
                'expiration_date': str(getattr(domain_info, 'expiration_date', 'Unknown')),
                'organization': getattr(domain_info, 'org', 'Unknown'),
                'country': getattr(domain_info, 'country', 'Unknown'),
                'name_servers': getattr(domain_info, 'name_servers', []),
                'status': getattr(domain_info, 'status', [])
            }
        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}
    
    def analyze_mx_records(self, domain):
        """Analyze MX records to identify email infrastructure"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = []
            email_provider = 'Unknown'
            enterprise_indicators = []
            
            for mx in mx_records:
                mx_host = str(mx.exchange).lower()
                mx_hosts.append({
                    'host': mx_host,
                    'priority': mx.preference
                })
                
                # Identify email providers and enterprise indicators
                if 'outlook' in mx_host or 'microsoft' in mx_host:
                    email_provider = 'Microsoft 365/Exchange Online'
                    enterprise_indicators.append('Microsoft 365 infrastructure')
                elif 'google' in mx_host or 'gmail' in mx_host:
                    if 'aspmx.l.google.com' in mx_host:
                        email_provider = 'Google Workspace'
                        enterprise_indicators.append('Google Workspace infrastructure')
                    else:
                        email_provider = 'Gmail (Consumer)'
                elif 'proofpoint' in mx_host:
                    email_provider = 'Proofpoint (Enterprise Security)'
                    enterprise_indicators.append('Enterprise email security')
                elif 'mimecast' in mx_host:
                    email_provider = 'Mimecast (Enterprise Security)'
                    enterprise_indicators.append('Enterprise email security')
                elif 'messagelabs' in mx_host or 'symanteccloud' in mx_host:
                    email_provider = 'Symantec Email Security'
                    enterprise_indicators.append('Enterprise email security')
            
            return {
                'mx_records': mx_hosts,
                'email_provider': email_provider,
                'enterprise_indicators': enterprise_indicators,
                'likely_enterprise': len(enterprise_indicators) > 0
            }
        except Exception as e:
            return {'error': f'MX lookup failed: {str(e)}'}
    
    def check_microsoft_services(self, domain):
        """Check for Microsoft 365/Azure AD indicators"""
        indicators = {}
        
        # Check Microsoft 365 tenant existence
        try:
            tenant_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid_configuration"
            response = requests.get(tenant_url, timeout=10, headers=self.headers)
            
            if response.status_code == 200:
                config = response.json()
                tenant_id = config.get('issuer', '').split('/')[-2] if 'issuer' in config else 'Unknown'
                indicators['microsoft_tenant'] = {
                    'exists': True,
                    'tenant_id': tenant_id,
                    'authorization_endpoint': config.get('authorization_endpoint', ''),
                    'token_endpoint': config.get('token_endpoint', ''),
                    'mdm_implications': 'Domain has Microsoft 365 tenant - may support Intune MDM'
                }
            else:
                indicators['microsoft_tenant'] = {'exists': False}
        except Exception as e:
            indicators['microsoft_tenant'] = {'error': str(e)}
        
        # Check for Exchange Autodiscover
        autodiscover_urls = [
            f"https://autodiscover.{domain}/autodiscover/autodiscover.xml",
            f"https://{domain}/autodiscover/autodiscover.xml"
        ]
        
        for url in autodiscover_urls:
            try:
                response = requests.get(url, timeout=5, headers=self.headers, allow_redirects=True)
                if response.status_code in [200, 401, 403]:  # These indicate service exists
                    indicators['exchange_autodiscover'] = {
                        'exists': True,
                        'url': url,
                        'status_code': response.status_code,
                        'mdm_implications': 'Exchange server detected - may support Exchange ActiveSync policies'
                    }
                    break
            except:
                continue
        
        if 'exchange_autodiscover' not in indicators:
            indicators['exchange_autodiscover'] = {'exists': False}
        
        return indicators
    
    def check_google_workspace_indicators(self, domain):
        """Check for Google Workspace indicators"""
        indicators = {}
        
        # Check Google Workspace MX pattern
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            google_mx_pattern = False
            mx_list = []
            
            for mx in mx_records:
                mx_host = str(mx.exchange).lower()
                mx_list.append(mx_host)
                if 'aspmx.l.google.com' in mx_host:
                    google_mx_pattern = True
            
            indicators['workspace_mx'] = {
                'has_workspace_pattern': google_mx_pattern,
                'mx_records': mx_list,
                'mdm_implications': 'Google Workspace detected - may support mobile device management' if google_mx_pattern else None
            }
        except Exception as e:
            indicators['workspace_mx'] = {'error': str(e)}
        
        # Check for Google SPF record patterns
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            google_spf = False
            for record in txt_records:
                record_text = str(record)
                if 'include:_spf.google.com' in record_text:
                    google_spf = True
                    break
            
            indicators['google_spf'] = {
                'uses_google_spf': google_spf,
                'implication': 'Uses Google email infrastructure' if google_spf else None
            }
        except Exception as e:
            indicators['google_spf'] = {'error': str(e)}
        
        return indicators
    
    def analyze_dns_security_posture(self, domain):
        """Analyze DNS security configuration"""
        security_records = {}
        
        # SPF Record Analysis
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            spf_record = None
            for record in txt_records:
                record_text = str(record).strip('"')
                if record_text.startswith('v=spf1'):
                    spf_record = record_text
                    break
            
            if spf_record:
                security_records['spf'] = {
                    'exists': True,
                    'record': spf_record,
                    'strictness': 'strict' if '~all' in spf_record or '-all' in spf_record else 'permissive',
                    'enterprise_indicator': True
                }
            else:
                security_records['spf'] = {'exists': False, 'enterprise_indicator': False}
        except Exception as e:
            security_records['spf'] = {'error': str(e)}
        
        # DMARC Record Analysis
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc_record = None
            for record in dmarc_records:
                record_text = str(record).strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_record = record_text
                    break
            
            if dmarc_record:
                policy = 'none'
                if 'p=quarantine' in dmarc_record:
                    policy = 'quarantine'
                elif 'p=reject' in dmarc_record:
                    policy = 'reject'
                
                security_records['dmarc'] = {
                    'exists': True,
                    'record': dmarc_record,
                    'policy': policy,
                    'enterprise_indicator': policy in ['quarantine', 'reject']
                }
            else:
                security_records['dmarc'] = {'exists': False, 'enterprise_indicator': False}
        except Exception as e:
            security_records['dmarc'] = {'exists': False, 'note': 'No DMARC record found'}
        
        # DKIM Analysis (common selectors)
        dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 's2']
        dkim_found = []
        
        for selector in dkim_selectors:
            try:
                dkim_query = f'{selector}._domainkey.{domain}'
                dkim_records = dns.resolver.resolve(dkim_query, 'TXT')
                for record in dkim_records:
                    if 'v=DKIM1' in str(record):
                        dkim_found.append(selector)
                        break
            except:
                continue
        
        security_records['dkim'] = {
            'selectors_found': dkim_found,
            'exists': len(dkim_found) > 0,
            'enterprise_indicator': len(dkim_found) > 0
        }
        
        return security_records
    
    def classify_domain_type(self, domain, whois_info, mx_analysis):
        """Classify the domain based on various indicators"""
        classification = {}
        
        # Free email providers
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
            'aol.com', 'icloud.com', 'me.com', 'mac.com', 'protonmail.com',
            'proton.me', 'tutanota.com', 'zoho.com', 'yandex.com', 'mail.com'
        }
        
        classification['is_free_provider'] = domain.lower() in free_providers
        classification['is_government'] = domain.endswith(('.gov', '.mil', '.gov.uk', '.gc.ca'))
        classification['is_education'] = domain.endswith(('.edu', '.ac.uk', '.edu.au'))
        classification['is_nonprofit'] = domain.endswith('.org')
        
        # Analyze organization indicators from WHOIS
        org_indicators = []
        if not whois_info.get('error'):
            org = whois_info.get('organization', '').lower()
            if org and org != 'unknown':
                if any(term in org for term in ['corporation', 'corp', 'inc', 'llc', 'ltd', 'company']):
                    org_indicators.append('Corporate entity in WHOIS')
                if any(term in org for term in ['university', 'college', 'school', 'education']):
                    org_indicators.append('Educational institution')
                if any(term in org for term in ['government', 'federal', 'state', 'county', 'city']):
                    org_indicators.append('Government organization')
        
        # Enterprise email infrastructure
        if mx_analysis.get('likely_enterprise', False):
            org_indicators.append('Enterprise email infrastructure')
        
        classification['organization_indicators'] = org_indicators
        classification['likely_organizational'] = (
            len(org_indicators) > 0 or 
            classification['is_government'] or 
            classification['is_education'] or
            (not classification['is_free_provider'] and mx_analysis.get('likely_enterprise', False))
        )
        
        return classification
    
    def calculate_mdm_risk_assessment(self, analysis_results):
        """Calculate MDM enrollment likelihood based on all indicators"""
        risk_factors = []
        risk_score = 0
        
        # Microsoft 365 tenant (+30 points)
        ms_indicators = analysis_results.get('microsoft_indicators', {})
        if ms_indicators.get('microsoft_tenant', {}).get('exists', False):
            risk_score += 30
            risk_factors.append('Microsoft 365 tenant detected (Intune MDM capable)')
        
        # Exchange Autodiscover (+20 points)
        if ms_indicators.get('exchange_autodiscover', {}).get('exists', False):
            risk_score += 20
            risk_factors.append('Exchange server detected (ActiveSync policies possible)')
        
        # Google Workspace (+25 points)
        google_indicators = analysis_results.get('google_indicators', {})
        if google_indicators.get('workspace_mx', {}).get('has_workspace_pattern', False):
            risk_score += 25
            risk_factors.append('Google Workspace detected (mobile device management capable)')
        
        # Enterprise email infrastructure (+15 points)
        mx_analysis = analysis_results.get('mx_analysis', {})
        if mx_analysis.get('likely_enterprise', False):
            risk_score += 15
            risk_factors.append(f"Enterprise email provider: {mx_analysis.get('email_provider', 'Unknown')}")
        
        # Strong email security posture (+10 points)
        dns_security = analysis_results.get('dns_security', {})
        security_score = 0
        if dns_security.get('spf', {}).get('enterprise_indicator', False):
            security_score += 3
        if dns_security.get('dmarc', {}).get('enterprise_indicator', False):
            security_score += 4
        if dns_security.get('dkim', {}).get('exists', False):
            security_score += 3
        
        if security_score >= 7:
            risk_score += 15
            risk_factors.append('Strong email security configuration (enterprise-grade)')
        elif security_score >= 4:
            risk_score += 10
            risk_factors.append('Moderate email security configuration')
        
        # Organizational domain (+20 points)
        domain_classification = analysis_results.get('domain_classification', {})
        if domain_classification.get('is_government', False):
            risk_score += 25
            risk_factors.append('Government domain (high MDM likelihood)')
        elif domain_classification.get('is_education', False):
            risk_score += 20
            risk_factors.append('Educational domain (moderate MDM likelihood)')
        elif domain_classification.get('likely_organizational', False):
            risk_score += 15
            risk_factors.append('Corporate/organizational domain')
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'HIGH'
            recommendation = 'Strong indicators suggest this email may be subject to MDM enrollment'
        elif risk_score >= 40:
            risk_level = 'MODERATE'
            recommendation = 'Some enterprise indicators present - MDM enrollment possible'
        elif risk_score >= 20:
            risk_level = 'LOW'
            recommendation = 'Minimal enterprise indicators - personal email likely'
        else:
            risk_level = 'MINIMAL'
            recommendation = 'No significant enterprise indicators detected'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': recommendation,
            'max_score': 100
        }
    
    def generate_user_guidance(self, email, risk_assessment, analysis_results):
        """Generate specific guidance for the user"""
        guidance = {
            'summary': '',
            'what_to_check': [],
            'red_flags': [],
            'next_steps': []
        }
        
        risk_level = risk_assessment['risk_level']
        domain = email.split('@')[1]
        
        if risk_level == 'HIGH':
            guidance['summary'] = f"⚠️ HIGH RISK: The email domain '{domain}' shows strong indicators of enterprise management."
            guidance['red_flags'] = [
                "Check your devices for any MDM profiles you didn't install",
                "Look for work/school accounts in device settings that you didn't add",
                "Watch for company portal apps or certificates",
                "Be aware of any device restrictions or policies"
            ]
            guidance['next_steps'] = [
                "Document any suspicious device behavior",
                "Contact the domain administrator if you didn't authorize this email",
                "Consider legal consultation if enrollment was unauthorized",
                "Review any agreements you may have signed"
            ]
        
        elif risk_level == 'MODERATE':
            guidance['summary'] = f"⚠️ MODERATE RISK: The domain '{domain}' has some enterprise characteristics."
            guidance['what_to_check'] = [
                "Review device settings for any management profiles",
                "Check if you knowingly added this email for work/school",
                "Look for any automatic app installations",
                "Verify email account permissions on your devices"
            ]
        
        else:
            guidance['summary'] = f"✅ LOW RISK: The domain '{domain}' appears to be consumer-oriented."
            guidance['what_to_check'] = [
                "Continue normal security practices",
                "Monitor for any unexpected device behavior",
                "Be cautious if adding this email to work devices"
            ]
        
        return guidance
    
    def analyze_email(self, email):
        """Main analysis function"""
        if not self.validate_email(email):
            return {'error': 'Invalid email format provided'}
        
        domain = email.split('@')[1].lower()
        
        print(f"🔍 Analyzing email: {email}")
        print(f"📧 Domain: {domain}")
        print("⏳ Running analysis...")
        
        # Perform all analyses
        analysis_results = {
            'email': email,
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'whois_info': self.get_domain_registration_info(domain),
            'mx_analysis': self.analyze_mx_records(domain),
            'microsoft_indicators': self.check_microsoft_services(domain),
            'google_indicators': self.check_google_workspace_indicators(domain),
            'dns_security': self.analyze_dns_security_posture(domain)
        }
        
        # Domain classification
        analysis_results['domain_classification'] = self.classify_domain_type(
            domain, 
            analysis_results['whois_info'], 
            analysis_results['mx_analysis']
        )
        
        # Risk assessment
        analysis_results['risk_assessment'] = self.calculate_mdm_risk_assessment(analysis_results)
        
        # User guidance
        analysis_results['user_guidance'] = self.generate_user_guidance(
            email, 
            analysis_results['risk_assessment'], 
            analysis_results
        )
        
        return analysis_results

def print_detailed_report(results):
    """Print comprehensive analysis report"""
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    email = results['email']
    domain = results['domain']
    
    print("\n" + "="*80)
    print(f"📧 COMPREHENSIVE EMAIL DOMAIN ANALYSIS")
    print("="*80)
    print(f"Email: {email}")
    print(f"Domain: {domain}")
    print(f"Analysis Date: {results['timestamp']}")
    
    # Risk Assessment Summary
    risk = results['risk_assessment']
    print(f"\n🎯 RISK ASSESSMENT SUMMARY")
    print("-" * 40)
    print(f"Risk Level: {risk['risk_level']}")
    print(f"Risk Score: {risk['risk_score']}/100")
    print(f"Assessment: {risk['recommendation']}")
    
    if risk['risk_factors']:
        print(f"\n📍 Key Risk Factors Identified:")
        for factor in risk['risk_factors']:
            print(f"  • {factor}")
    
    # User Guidance
    guidance = results['user_guidance']
    print(f"\n💡 USER GUIDANCE")
    print("-" * 40)
    print(guidance['summary'])
    
    if guidance['red_flags']:
        print(f"\n🚩 Important Checks:")
        for flag in guidance['red_flags']:
            print(f"  • {flag}")
    
    if guidance['what_to_check']:
        print(f"\n🔍 What to Check:")
        for check in guidance['what_to_check']:
            print(f"  • {check}")
    
    if guidance['next_steps']:
        print(f"\n📋 Recommended Next Steps:")
        for step in guidance['next_steps']:
            print(f"  • {step}")
    
    # Technical Details
    print(f"\n🔧 TECHNICAL ANALYSIS DETAILS")
    print("-" * 40)
    
    # Domain Classification
    domain_class = results['domain_classification']
    print(f"\n📂 Domain Classification:")
    print(f"  Free Provider: {'YES' if domain_class['is_free_provider'] else 'NO'}")
    print(f"  Government: {'YES' if domain_class['is_government'] else 'NO'}")
    print(f"  Educational: {'YES' if domain_class['is_education'] else 'NO'}")
    print(f"  Organizational: {'YES' if domain_class['likely_organizational'] else 'NO'}")
    
    if domain_class['organization_indicators']:
        print(f"  Org Indicators: {', '.join(domain_class['organization_indicators'])}")
    
    # Email Infrastructure
    mx_analysis = results['mx_analysis']
    if 'error' not in mx_analysis:
        print(f"\n📮 Email Infrastructure:")
        print(f"  Provider: {mx_analysis['email_provider']}")
        print(f"  Enterprise Grade: {'YES' if mx_analysis['likely_enterprise'] else 'NO'}")
        if mx_analysis['enterprise_indicators']:
            print(f"  Enterprise Features: {', '.join(mx_analysis['enterprise_indicators'])}")
    
    # Microsoft Services
    ms_indicators = results['microsoft_indicators']
    if ms_indicators.get('microsoft_tenant', {}).get('exists', False):
        tenant = ms_indicators['microsoft_tenant']
        print(f"\n🏢 Microsoft 365 Tenant:")
        print(f"  Exists: YES")
        print(f"  Tenant ID: {tenant['tenant_id']}")
        print(f"  MDM Capability: Intune enrollment possible")
    
    if ms_indicators.get('exchange_autodiscover', {}).get('exists', False):
        print(f"  Exchange Server: DETECTED")
        print(f"  ActiveSync Policies: Possible")
    
    # Google Services
    google_indicators = results['google_indicators']
    if google_indicators.get('workspace_mx', {}).get('has_workspace_pattern', False):
        print(f"\n🌐 Google Workspace:")
        print(f"  Workspace Detected: YES")
        print(f"  MDM Capability: Mobile device management possible")
    
    # DNS Security
    dns_security = results['dns_security']
    print(f"\n🔒 Email Security Configuration:")
    
    spf = dns_security.get('spf', {})
    if spf.get('exists', False):
        print(f"  SPF: CONFIGURED ({spf.get('strictness', 'unknown')})")
    else:
        print(f"  SPF: NOT CONFIGURED")
    
    dmarc = dns_security.get('dmarc', {})
    if dmarc.get('exists', False):
        print(f"  DMARC: CONFIGURED (policy: {dmarc.get('policy', 'unknown')})")
    else:
        print(f"  DMARC: NOT CONFIGURED")
    
    dkim = dns_security.get('dkim', {})
    if dkim.get('exists', False):
        print(f"  DKIM: CONFIGURED (selectors: {', '.join(dkim.get('selectors_found', []))})")
    else:
        print(f"  DKIM: NOT CONFIGURED")
    
    # WHOIS Information
    whois_info = results['whois_info']
    if 'error' not in whois_info:
        print(f"\n🌐 Domain Registration:")
        print(f"  Registrar: {whois_info.get('registrar', 'Unknown')}")
        print(f"  Organization: {whois_info.get('organization', 'Unknown')}")
        print(f"  Country: {whois_info.get('country', 'Unknown')}")
        print(f"  Created: {whois_info.get('creation_date', 'Unknown')}")
    
    print("\n" + "="*80)
    print("ℹ️  This analysis is based on publicly available information only.")
    print("💡 For definitive MDM status, check device settings directly.")
    print("⚖️  If you suspect unauthorized enrollment, document findings and seek legal advice.")
    print("="*80)

def main():
    parser = argparse.ArgumentParser(
        description='Ethical Email Domain Analysis Tool',
        epilog='Example: python ethical_analyzer.py user@company.com --detailed'
    )
    parser.add_argument('email', help='Email address to analyze')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--detailed', action='store_true', help='Show detailed technical analysis')
    parser.add_argument('--save', help='Save results to specified file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output (just risk assessment)')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = EthicalEmailAnalyzer()
    
    # Run analysis
    try:
        results = analyzer.analyze_email(args.email)
    except KeyboardInterrupt:
        print("\n⏹️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Analysis failed: {str(e)}")
        sys.exit(1)
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    elif args.quiet:
        if 'error' in results:
            print(f"Error: {results['error']}")
        else:
            risk = results['risk_assessment']
            print(f"Risk Level: {risk['risk_level']} ({risk['risk_score']}/100)")
            print(f"Assessment: {risk['recommendation']}")
    else:
        print_detailed_report(results)
    
    # Save results if requested
    if args.save:
        try:
            with open(args.save, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to: {args.save}")
        except Exception as e:
            print(f"❌ Failed to save results: {str(e)}")

if __name__ == '__main__':
    main()
