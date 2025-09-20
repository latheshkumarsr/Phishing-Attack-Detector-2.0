interface PhishingFeatures {
  // URL-based features
  urlLength: number;
  domainLength: number;
  subdomainCount: number;
  hasIPAddress: boolean;
  hasShortener: boolean;
  hasSuspiciousTLD: boolean;
  hasHTTPS: boolean;
  
  // Content-based features
  urgencyWords: number;
  suspiciousWords: number;
  grammarErrors: number;
  spellingErrors: number;
  linkCount: number;
  imageCount: number;
  
  // Email-specific features
  hasPersonalGreeting: boolean;
  hasGenericGreeting: boolean;
  requestsPersonalInfo: boolean;
  hasAttachments: boolean;
  
  // Social engineering indicators
  createsUrgency: boolean;
  offersReward: boolean;
  threatensPunishment: boolean;
  requestsAction: boolean;
}

interface MLResult {
  phishingProbability: number;
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;
  features: PhishingFeatures;
  explanation: string[];
}

export class PhishingMLDetector {
  private urgencyKeywords = [
    'urgent', 'immediate', 'asap', 'expires', 'deadline', 'limited time',
    'act now', 'hurry', 'last chance', 'final notice', 'time sensitive',
    'expires today', 'expires soon', 'don\'t delay', 'respond immediately'
  ];

  private suspiciousKeywords = [
    'verify', 'confirm', 'update', 'suspended', 'locked', 'security alert',
    'click here', 'download', 'install', 'winner', 'congratulations',
    'free', 'prize', 'lottery', 'inheritance', 'million', 'tax refund',
    'claim now', 'act fast', 'limited offer', 'exclusive deal'
  ];

  private personalInfoRequests = [
    'password', 'ssn', 'social security', 'credit card', 'bank account',
    'pin', 'login', 'username', 'personal information', 'date of birth',
    'mother\'s maiden name', 'security question', 'account number'
  ];

  private suspiciousTLDs = [
    '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download',
    '.zip', '.review', '.country', '.kim', '.cricket', '.science'
  ];

  private urlShorteners = [
    'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link',
    'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly'
  ];

  extractFeatures(content: string, type: 'email' | 'url' | 'sms' | 'social'): PhishingFeatures {
    const lowerContent = content.toLowerCase();
    
    // Extract URLs from content
    const urlRegex = /https?:\/\/[^\s]+/gi;
    const urls = content.match(urlRegex) || [];
    const firstUrl = urls[0] || '';
    
    // URL-based features
    const urlLength = firstUrl.length;
    const domainMatch = firstUrl.match(/https?:\/\/([^\/]+)/);
    const domain = domainMatch ? domainMatch[1] : '';
    const domainLength = domain.length;
    const subdomainCount = domain.split('.').length - 2;
    const hasIPAddress = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(firstUrl);
    const hasShortener = this.urlShorteners.some(shortener => firstUrl.includes(shortener));
    const hasSuspiciousTLD = this.suspiciousTLDs.some(tld => domain.endsWith(tld));
    const hasHTTPS = firstUrl.startsWith('https://');
    
    // Content analysis
    const urgencyWords = this.countKeywords(lowerContent, this.urgencyKeywords);
    const suspiciousWords = this.countKeywords(lowerContent, this.suspiciousKeywords);
    const grammarErrors = this.detectGrammarErrors(content);
    const spellingErrors = this.detectSpellingErrors(content);
    const linkCount = urls.length;
    const imageCount = (content.match(/<img|!\[.*\]/gi) || []).length;
    
    // Email-specific features
    const hasPersonalGreeting = /dear [a-z]+ [a-z]+/i.test(content);
    const hasGenericGreeting = /dear (customer|user|sir|madam|valued)/i.test(content);
    const requestsPersonalInfo = this.countKeywords(lowerContent, this.personalInfoRequests) > 0;
    const hasAttachments = /attachment|attached|download.*file/i.test(content);
    
    // Social engineering indicators
    const createsUrgency = urgencyWords > 0;
    const offersReward = /free|prize|winner|reward|bonus|gift/i.test(content);
    const threatensPunishment = /suspend|close|terminate|block|penalty/i.test(content);
    const requestsAction = /click|download|call|reply|respond|verify|confirm/i.test(content);

    return {
      urlLength,
      domainLength,
      subdomainCount,
      hasIPAddress,
      hasShortener,
      hasSuspiciousTLD,
      hasHTTPS,
      urgencyWords,
      suspiciousWords,
      grammarErrors,
      spellingErrors,
      linkCount,
      imageCount,
      hasPersonalGreeting,
      hasGenericGreeting,
      requestsPersonalInfo,
      hasAttachments,
      createsUrgency,
      offersReward,
      threatensPunishment,
      requestsAction
    };
  }

  private countKeywords(content: string, keywords: string[]): number {
    return keywords.reduce((count, keyword) => {
      const regex = new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
      const matches = content.match(regex);
      return count + (matches ? matches.length : 0);
    }, 0);
  }

  private detectGrammarErrors(content: string): number {
    let errors = 0;
    
    // Simple grammar error detection
    const patterns = [
      /\bi\s+am\s+are\b/gi,  // "I am are"
      /\byou\s+is\b/gi,      // "you is"
      /\bhe\s+are\b/gi,      // "he are"
      /\bthey\s+is\b/gi,     // "they is"
      /\ba\s+[aeiou]/gi,     // "a apple" (should be "an")
      /\ban\s+[^aeiou]/gi,   // "an car" (should be "a")
    ];
    
    patterns.forEach(pattern => {
      const matches = content.match(pattern);
      if (matches) errors += matches.length;
    });
    
    return errors;
  }

  private detectSpellingErrors(content: string): number {
    const commonMisspellings = [
      'recieve', 'seperate', 'occured', 'neccessary', 'accomodate',
      'definately', 'occassion', 'embarass', 'maintainance', 'existance',
      'beleive', 'acheive', 'begining', 'calender', 'cemetary'
    ];
    
    return this.countKeywords(content.toLowerCase(), commonMisspellings);
  }

  // ML-based scoring algorithm
  calculatePhishingScore(features: PhishingFeatures, type: 'email' | 'url' | 'sms' | 'social'): MLResult {
    let score = 0;
    const explanation: string[] = [];
    
    // URL-based scoring
    if (features.hasIPAddress) {
      score += 25;
      explanation.push('URL contains IP address instead of domain name');
    }
    
    if (features.hasShortener) {
      score += 20;
      explanation.push('Uses URL shortening service');
    }
    
    if (features.hasSuspiciousTLD) {
      score += 30;
      explanation.push('Uses suspicious top-level domain');
    }
    
    if (!features.hasHTTPS && features.linkCount > 0) {
      score += 15;
      explanation.push('Uses insecure HTTP protocol');
    }
    
    if (features.urlLength > 100) {
      score += 10;
      explanation.push('Unusually long URL detected');
    }
    
    if (features.subdomainCount > 3) {
      score += 15;
      explanation.push('Excessive subdomains in URL');
    }
    
    // Content-based scoring
    score += features.urgencyWords * 8;
    if (features.urgencyWords > 0) {
      explanation.push(`Contains ${features.urgencyWords} urgency-creating words`);
    }
    
    score += features.suspiciousWords * 6;
    if (features.suspiciousWords > 0) {
      explanation.push(`Contains ${features.suspiciousWords} suspicious keywords`);
    }
    
    score += features.grammarErrors * 5;
    if (features.grammarErrors > 0) {
      explanation.push(`${features.grammarErrors} grammar errors detected`);
    }
    
    score += features.spellingErrors * 7;
    if (features.spellingErrors > 0) {
      explanation.push(`${features.spellingErrors} spelling errors found`);
    }
    
    // Social engineering scoring
    if (features.requestsPersonalInfo) {
      score += 35;
      explanation.push('Requests personal or sensitive information');
    }
    
    if (features.hasGenericGreeting && !features.hasPersonalGreeting) {
      score += 10;
      explanation.push('Uses generic greeting instead of personal name');
    }
    
    if (features.offersReward) {
      score += 20;
      explanation.push('Offers unrealistic rewards or prizes');
    }
    
    if (features.threatensPunishment) {
      score += 25;
      explanation.push('Threatens negative consequences');
    }
    
    // Type-specific adjustments
    if (type === 'sms') {
      if (features.linkCount > 0) {
        score += 20;
        explanation.push('SMS contains suspicious links');
      }
      
      // Check for premium rate numbers
      if (/\b(900|976|550)\d{7}\b/.test('')) {
        score += 30;
        explanation.push('Contains premium rate phone number');
      }
    }
    
    if (type === 'email' && features.hasAttachments) {
      score += 15;
      explanation.push('Contains potentially malicious attachments');
    }
    
    if (type === 'social' && features.requestsAction) {
      score += 15;
      explanation.push('Requests immediate action or response');
    }
    
    // Normalize score to probability (0-100)
    const phishingProbability = Math.min(100, Math.max(0, score));
    
    // Determine risk level
    let riskLevel: 'low' | 'medium' | 'high';
    if (phishingProbability < 30) {
      riskLevel = 'low';
    } else if (phishingProbability < 60) {
      riskLevel = 'medium';
    } else {
      riskLevel = 'high';
    }
    
    // Calculate confidence based on number of features detected
    const featuresDetected = explanation.length;
    const confidence = Math.min(95, 60 + (featuresDetected * 5));
    
    return {
      phishingProbability,
      riskLevel,
      confidence,
      features,
      explanation
    };
  }

  analyze(content: string, type: 'email' | 'url' | 'sms' | 'social'): MLResult {
    const features = this.extractFeatures(content, type);
    return this.calculatePhishingScore(features, type);
  }
}