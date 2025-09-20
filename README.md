# Phishing Attack Detector

A comprehensive multi-platform phishing detection application with AI-powered chatbot assistance.

## Features

- **Multi-Platform Detection**: Analyze emails, websites, SMS messages, and social media content
- **AI-Powered Analysis**: Advanced threat detection with confidence scoring
- **Interactive Chatbot**: Real-time cybersecurity assistance and education
- **Modern UI**: Dark cybersecurity theme with smooth animations
- **Comprehensive Reporting**: Detailed threat analysis and security recommendations

## Setup Instructions

### 1. Environment Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Supabase Configuration (required for AI chatbot)
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key

# AI Configuration (required for intelligent chatbot responses)
GEMINI_API_KEY=your_gemini_api_key_here
```

### 2. Getting API Keys

#### Supabase Setup:
1. Go to [Supabase](https://supabase.com) and create a new project
2. In your project dashboard, go to Settings > API
3. Copy the Project URL and anon/public key to your `.env` file

#### Gemini API Setup:
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Add it to your `.env` file as `GEMINI_API_KEY`

### 3. Deploy Edge Function

The AI chatbot uses a Supabase Edge Function. To deploy it:

1. Install Supabase CLI (if not already installed)
2. Login to Supabase: `supabase login`
3. Link your project: `supabase link --project-ref your-project-ref`
4. Set the environment variable: `supabase secrets set GEMINI_API_KEY=your_api_key`
5. Deploy the function: `supabase functions deploy chat`

### 4. Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

## Usage

1. **Select Detection Type**: Choose from Email, Website, SMS, or Social Media
2. **Input Content**: Paste suspicious content or URLs
3. **Analyze**: Click "Detect Phishing Attack" for comprehensive analysis
4. **Get Help**: Use the AI chatbot for real-time cybersecurity assistance

## Chatbot Features

The AI chatbot provides:
- Phishing attack explanations
- Security best practices
- Platform-specific safety advice
- Real-time threat assessment help
- Educational cybersecurity content

## Fallback Mode

If API keys are not configured, the application will:
- Use mock analysis for threat detection
- Provide basic chatbot responses with cybersecurity tips
- Continue to function with reduced AI capabilities

## Technologies Used

- React + TypeScript
- Tailwind CSS
- Supabase Edge Functions
- Google Gemini AI API
- Lucide React Icons