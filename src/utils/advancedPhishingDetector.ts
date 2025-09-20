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

  // NEW: Advanced features
  sentimentScore: number;
  readabilityScore: number;
  brandImpersonation: string[];
  cryptoScamIndicators: number;
  socialProofManipulation: number;
  timeBasedUrgency: number;
  technicalSophistication: number;
}

interface MLResult {
  phishingProbability: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  features: PhishingFeatures;
  explanation: string[];
  // NEW: Enhanced results
  threatCategory: string;
  attackVector: string[];
  similarAttacks: string[];
  preventionTips: string[];
  riskFactors: { factor: string; weight: number; detected: boolean }[];
}

export class AdvancedPhishingDetector {
  private urgencyKeywords = [
    'urgent', 'immediate', 'asap', 'expires', 'deadline', 'limited time',
    'act now', 'hurry', 'last chance', 'final notice', 'time sensitive',
    'expires today', 'expires soon', 'don\'t delay', 'respond immediately',
    'within 24 hours', 'before midnight', 'today only', 'while supplies last'
  ];

  private suspiciousKeywords = [
    'verify', 'confirm', 'update', 'suspended', 'locked', 'security alert',
    'click here', 'download', 'install', 'winner', 'congratulations',
    'free', 'prize', 'lottery', 'inheritance', 'million', 'tax refund',
    'claim now', 'act fast', 'limited offer', 'exclusive deal', 'selected',
    'chosen', 'lucky', 'special offer', 'once in a lifetime'
  ];

  private personalInfoRequests = [
    'password', 'ssn', 'social security', 'credit card', 'bank account',
    'pin', 'login', 'username', 'personal information', 'date of birth',
    'mother\'s maiden name', 'security question', 'account number',
    'routing number', 'cvv', 'security code', 'verification code'
  ];

  private suspiciousTLDs = [
    '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download',
    '.zip', '.review', '.country', '.kim', '.cricket', '.science',
    '.work', '.party', '.trade', '.date', '.racing', '.bid'
  ];

  private urlShorteners = [
    'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link',
    'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'lnkd.in'
  ];

  // NEW: Brand impersonation detection
  private legitimateBrands = [
    'amazon', 'paypal', 'microsoft', 'apple', 'google', 'facebook',
    'netflix', 'spotify', 'instagram', 'twitter', 'linkedin', 'ebay',
    'wells fargo', 'chase', 'bank of america', 'citibank', 'visa',
    'mastercard', 'american express', 'irs', 'fedex', 'ups', 'dhl'
  ];

  // NEW: Crypto scam indicators
  private cryptoKeywords = [
    'bitcoin', 'ethereum', 'crypto', 'blockchain', 'mining', 'wallet',
    'investment opportunity', 'guaranteed returns', 'double your money',
    'crypto giveaway', 'elon musk', 'tesla giveaway', 'btc', 'eth'
  ];

  // NEW: Social proof manipulation
  private socialProofKeywords = [
    'thousands of people', 'everyone is doing', 'don\'t miss out',
    'join millions', 'trending now', 'viral', 'going viral',
    'celebrities use', 'recommended by experts', 'as seen on tv'
  ];

  // NEW: Sentiment analysis (simplified)
  private positiveWords = [
    'amazing', 'incredible', 'fantastic', 'wonderful', 'excellent',
    'outstanding', 'perfect', 'brilliant', 'awesome', 'great'
  ];

  private negativeWords = [
    'terrible', 'awful', 'horrible', 'disaster', 'failure', 'problem',
    'issue', 'error', 'mistake', 'wrong', 'bad', 'worst'
  ];

  private fearWords = [
    'danger', 'risk', 'threat', 'warning', 'alert', 'emergency',
    'critical', 'urgent', 'serious', 'important', 'notice'
  ];

  extractAdvancedFeatures(content: string, type: 'email' | 'url' | 'sms' | 'social'): PhishingFeatures {
    const lowerContent = content.toLowerCase();
    
    // Extract URLs from content
    const urlRegex = /https?:\/\/[^\s]+/gi;
    const urls = content.match(urlRegex) || [];
    const firstUrl = urls[0] || '';
    
    // Basic URL features
    const urlLength = firstUrl.length;
    const domainMatch = firstUrl.match(/https?:\/\/([^\/]+)/);
    const domain = domainMatch ? domainMatch[1] : '';
    const domainLength = domain.length;
    const subdomainCount = domain.split('.').length - 2;
    const hasIPAddress = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(firstUrl);
    const hasShortener = this.urlShorteners.some(shortener => firstUrl.includes(shortener));
    const hasSuspiciousTLD = this.suspiciousTLDs.some(tld => domain.endsWith(tld));
    const hasHTTPS = firstUrl.startsWith('https://');
    
    // Basic content analysis
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

    // NEW: Advanced features
    const sentimentScore = this.calculateSentiment(content);
    const readabilityScore = this.calculateReadability(content);
    const brandImpersonation = this.detectBrandImpersonation(content);
    const cryptoScamIndicators = this.countKeywords(lowerContent, this.cryptoKeywords);
    const socialProofManipulation = this.countKeywords(lowerContent, this.socialProofKeywords);
    const timeBasedUrgency = this.detectTimeBasedUrgency(content);
    const technicalSophistication = this.assessTechnicalSophistication(content);

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
      requestsAction,
      sentimentScore,
      readabilityScore,
      brandImpersonation,
      cryptoScamIndicators,
      socialProofManipulation,
      timeBasedUrgency,
      technicalSophistication
    };
  }

  // NEW: Sentiment analysis
  private calculateSentiment(content: string): number {
    const words = content.toLowerCase().split(/\s+/);
    let score = 0;
    
    words.forEach(word => {
      if (this.positiveWords.includes(word)) score += 1;
      if (this.negativeWords.includes(word)) score -= 1;
      if (this.fearWords.includes(word)) score -= 2; // Fear words are more suspicious
    });
    
    return Math.max(-10, Math.min(10, score)); // Normalize to -10 to 10
  }

  // NEW: Readability assessment
  private calculateReadability(content: string): number {
    const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const words = content.split(/\s+/).filter(w => w.length > 0);
    const syllables = words.reduce((count, word) => count + this.countSyllables(word), 0);
    
    if (sentences.length === 0 || words.length === 0) return 0;
    
    // Simplified Flesch Reading Ease formula
    const avgSentenceLength = words.length / sentences.length;
    const avgSyllablesPerWord = syllables / words.length;
    
    const score = 206.835 - (1.015 * avgSentenceLength) - (84.6 * avgSyllablesPerWord);
    return Math.max(0, Math.min(100, score));
  }

  private countSyllables(word: string): number {
    word = word.toLowerCase();
    if (word.length <= 3) return 1;
    
    const vowels = 'aeiouy';
    let count = 0;
    let previousWasVowel = false;
    
    for (let i = 0; i < word.length; i++) {
      const isVowel = vowels.includes(word[i]);
      if (isVowel && !previousWasVowel) count++;
      previousWasVowel = isVowel;
    }
    
    if (word.endsWith('e')) count--;
    return Math.max(1, count);
  }

  // NEW: Brand impersonation detection
  private detectBrandImpersonation(content: string): string[] {
    const lowerContent = content.toLowerCase();
    const impersonatedBrands: string[] = [];
    
    this.legitimateBrands.forEach(brand => {
      if (lowerContent.includes(brand)) {
        impersonatedBrands.push(brand);
      }
    });
    
    return impersonatedBrands;
  }

  // NEW: Time-based urgency detection
  private detectTimeBasedUrgency(content: string): number {
    const timePatterns = [
      /within \d+ (hours?|minutes?|days?)/gi,
      /expires? (today|tonight|soon|in \d+)/gi,
      /\d+ (hours?|minutes?) (left|remaining)/gi,
      /(today only|limited time|while supplies last)/gi,
      /before (midnight|\d+:\d+|tomorrow)/gi
    ];
    
    let urgencyScore = 0;
    timePatterns.forEach(pattern => {
      const matches = content.match(pattern);
      if (matches) urgencyScore += matches.length;
    });
    
    return urgencyScore;
  }

  // NEW: Technical sophistication assessment
  private assessTechnicalSophistication(content: string): number {
    let sophisticationScore = 0;
    
    // Check for technical elements that might indicate advanced phishing
    const technicalIndicators = [
      /javascript:/gi,
      /data:text\/html/gi,
      /base64/gi,
      /eval\(/gi,
      /document\.write/gi,
      /window\.location/gi,
      /iframe/gi,
      /onclick=/gi,
      /onload=/gi
    ];
    
    technicalIndicators.forEach(pattern => {
      if (pattern.test(content)) sophisticationScore += 2;
    });
    
    // Check for obfuscation techniques
    if (/[a-zA-Z0-9+/]{20,}={0,2}/.test(content)) sophisticationScore += 3; // Base64-like strings
    if (/\\u[0-9a-fA-F]{4}/.test(content)) sophisticationScore += 2; // Unicode escapes
    if (/&#\d+;/.test(content)) sophisticationScore += 1; // HTML entities
    
    return sophisticationScore;
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
    
    const patterns = [
      /\bi\s+am\s+are\b/gi,
      /\byou\s+is\b/gi,
      /\bhe\s+are\b/gi,
      /\bthey\s+is\b/gi,
      /\ba\s+[aeiou]/gi,
      /\ban\s+[^aeiou]/gi,
      /\btheir\s+are\b/gi,
      /\bthere\s+is\s+\w+\s+are\b/gi
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
      'beleive', 'acheive', 'begining', 'calender', 'cemetary',
      'buisness', 'freind', 'wierd', 'thier', 'untill'
    ];
    
    return this.countKeywords(content.toLowerCase(), commonMisspellings);
  }

  // Enhanced ML scoring with new features
  calculateAdvancedPhishingScore(features: PhishingFeatures, type: 'email' | 'url' | 'sms' | 'social'): MLResult {
    let score = 0;
    const explanation: string[] = [];
    const riskFactors: { factor: string; weight: number; detected: boolean }[] = [];
    const attackVector: string[] = [];
    const similarAttacks: string[] = [];
    const preventionTips: string[] = [];

    // Helper function to add risk factor
    const addRiskFactor = (factor: string, weight: number, detected: boolean, points: number) => {
      riskFactors.push({ factor, weight, detected });
      if (detected) {
        score += points;
        explanation.push(factor);
      }
    };

    // URL-based scoring
    addRiskFactor('IP address instead of domain', 25, features.hasIPAddress, 25);
    addRiskFactor('URL shortening service', 20, features.hasShortener, 20);
    addRiskFactor('Suspicious domain extension', 30, features.hasSuspiciousTLD, 30);
    addRiskFactor('Insecure HTTP protocol', 15, !features.hasHTTPS && features.linkCount > 0, 15);
    addRiskFactor('Unusually long URL', 10, features.urlLength > 100, 10);
    addRiskFactor('Excessive subdomains', 15, features.subdomainCount > 3, 15);

    // Content-based scoring
    if (features.urgencyWords > 0) {
      score += features.urgencyWords * 8;
      explanation.push(`${features.urgencyWords} urgency-creating words detected`);
      attackVector.push('Urgency manipulation');
    }

    if (features.suspiciousWords > 0) {
      score += features.suspiciousWords * 6;
      explanation.push(`${features.suspiciousWords} suspicious keywords found`);
    }

    // NEW: Advanced feature scoring
    if (features.brandImpersonation.length > 0) {
      score += features.brandImpersonation.length * 20;
      explanation.push(`Impersonating brands: ${features.brandImpersonation.join(', ')}`);
      attackVector.push('Brand impersonation');
      similarAttacks.push('Fake bank notifications', 'Fake service alerts');
    }

    if (features.cryptoScamIndicators > 0) {
      score += features.cryptoScamIndicators * 15;
      explanation.push(`${features.cryptoScamIndicators} cryptocurrency scam indicators`);
      attackVector.push('Cryptocurrency fraud');
      similarAttacks.push('Fake crypto giveaways', 'Investment scams');
    }

    if (features.socialProofManipulation > 0) {
      score += features.socialProofManipulation * 10;
      explanation.push(`${features.socialProofManipulation} social proof manipulation tactics`);
      attackVector.push('Social proof exploitation');
    }

    if (features.timeBasedUrgency > 0) {
      score += features.timeBasedUrgency * 12;
      explanation.push(`${features.timeBasedUrgency} time-based urgency tactics`);
      attackVector.push('Time pressure manipulation');
    }

    if (features.technicalSophistication > 5) {
      score += 25;
      explanation.push('Advanced technical obfuscation detected');
      attackVector.push('Technical sophistication');
      similarAttacks.push('Advanced persistent threats', 'Sophisticated phishing');
    }

    // Sentiment analysis
    if (features.sentimentScore < -3) {
      score += 15;
      explanation.push('Negative emotional manipulation detected');
      attackVector.push('Emotional manipulation');
    }

    // Readability analysis
    if (features.readabilityScore < 30) {
      score += 10;
      explanation.push('Unusually complex or confusing language');
    }

    // Social engineering scoring
    if (features.requestsPersonalInfo) {
      score += 35;
      explanation.push('Requests personal or sensitive information');
      attackVector.push('Information harvesting');
      preventionTips.push('Never provide personal info via email/SMS');
    }

    if (features.hasGenericGreeting && !features.hasPersonalGreeting) {
      score += 10;
      explanation.push('Uses generic greeting instead of personal name');
      preventionTips.push('Legitimate companies use your real name');
    }

    if (features.offersReward) {
      score += 20;
      explanation.push('Offers unrealistic rewards or prizes');
      attackVector.push('Reward-based deception');
      similarAttacks.push('Lottery scams', 'Prize notifications');
    }

    if (features.threatensPunishment) {
      score += 25;
      explanation.push('Threatens negative consequences');
      attackVector.push('Fear-based manipulation');
      preventionTips.push('Legitimate companies don\'t threaten via email');
    }

    // Type-specific adjustments and recommendations
    if (type === 'email') {
      preventionTips.push('Check sender email address carefully');
      preventionTips.push('Verify through official company website');
      if (features.hasAttachments) {
        score += 15;
        explanation.push('Contains potentially malicious attachments');
        preventionTips.push('Don\'t open unexpected attachments');
      }
    }

    if (type === 'sms') {
      preventionTips.push('Don\'t click links in unexpected SMS');
      preventionTips.push('Verify by calling the company directly');
      if (features.linkCount > 0) {
        score += 20;
        explanation.push('SMS contains suspicious links');
        similarAttacks.push('Smishing attacks', 'SMS phishing');
      }
    }

    if (type === 'social') {
      preventionTips.push('Check account verification status');
      preventionTips.push('Look for suspicious follower patterns');
      if (features.requestsAction) {
        score += 15;
        explanation.push('Requests immediate action or response');
      }
    }

    if (type === 'url') {
      preventionTips.push('Check URL spelling carefully');
      preventionTips.push('Look for HTTPS and valid certificates');
      preventionTips.push('Use official bookmarks instead of links');
    }

    // Determine threat category
    let threatCategory = 'General Phishing';
    if (features.brandImpersonation.length > 0) threatCategory = 'Brand Impersonation';
    if (features.cryptoScamIndicators > 0) threatCategory = 'Cryptocurrency Scam';
    if (features.requestsPersonalInfo) threatCategory = 'Credential Harvesting';
    if (features.technicalSophistication > 5) threatCategory = 'Advanced Persistent Threat';

    // Normalize score and determine risk level
    const phishingProbability = Math.min(100, Math.max(0, score));
    
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';
    if (phishingProbability < 25) {
      riskLevel = 'low';
    } else if (phishingProbability < 50) {
      riskLevel = 'medium';
    } else if (phishingProbability < 80) {
      riskLevel = 'high';
    } else {
      riskLevel = 'critical';
    }

    // Calculate confidence
    const featuresDetected = explanation.length;
    const confidence = Math.min(98, 65 + (featuresDetected * 4));

    // Add general prevention tips
    preventionTips.push('When in doubt, verify through official channels');
    preventionTips.push('Use two-factor authentication when available');
    preventionTips.push('Keep software and browsers updated');

    return {
      phishingProbability,
      riskLevel,
      confidence,
      features,
      explanation,
      threatCategory,
      attackVector: [...new Set(attackVector)], // Remove duplicates
      similarAttacks: [...new Set(similarAttacks)],
      preventionTips: [...new Set(preventionTips)],
      riskFactors
    };
  }

  analyze(content: string, type: 'email' | 'url' | 'sms' | 'social'): MLResult {
    const features = this.extractAdvancedFeatures(content, type);
    return this.calculateAdvancedPhishingScore(features, type);
  }
}