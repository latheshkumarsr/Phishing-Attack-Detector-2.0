import { serve } from "https://deno.land/std@0.168.0/http/server.ts"

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

interface ChatRequest {
  message: string;
  conversationHistory?: Array<{role: string, content: string}>;
}

serve(async (req) => {
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const { message, conversationHistory = [] }: ChatRequest = await req.json()

    // Get Gemini API key from environment
    const GEMINI_API_KEY = Deno.env.get('GEMINI_API_KEY')
    
    if (!GEMINI_API_KEY) {
      throw new Error('Gemini API key not configured')
    }

    // Prepare the conversation context with cybersecurity focus
    const systemPrompt = `You are an AI cybersecurity assistant specializing in phishing detection and online safety. Your role is to:

1. Help users understand different types of phishing attacks (email, SMS, social media, websites)
2. Provide practical security advice and best practices
3. Explain how to identify suspicious content and threats
4. Offer step-by-step guidance for staying safe online
5. Answer questions about cybersecurity tools and techniques

Keep responses concise, practical, and focused on actionable security advice. Use a professional but friendly tone. If asked about topics outside cybersecurity, politely redirect to security-related topics.`

    // Build conversation history for context
    const messages = [
      { role: 'user', parts: [{ text: systemPrompt }] },
      { role: 'model', parts: [{ text: 'I understand. I\'m ready to help with cybersecurity and phishing protection questions.' }] }
    ]

    // Add conversation history
    conversationHistory.forEach(msg => {
      messages.push({
        role: msg.role === 'user' ? 'user' : 'model',
        parts: [{ text: msg.content }]
      })
    })

    // Add current message
    messages.push({
      role: 'user',
      parts: [{ text: message }]
    })

    // Call Gemini API
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=${GEMINI_API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: messages,
        generationConfig: {
          temperature: 0.7,
          topK: 40,
          topP: 0.95,
          maxOutputTokens: 1024,
        },
        safetySettings: [
          {
            category: "HARM_CATEGORY_HARASSMENT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_HATE_SPEECH",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_DANGEROUS_CONTENT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          }
        ]
      })
    })

    if (!response.ok) {
      const errorData = await response.text()
      console.error('Gemini API error:', errorData)
      throw new Error(`Gemini API error: ${response.status}`)
    }

    const data = await response.json()
    
    if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
      throw new Error('Invalid response from Gemini API')
    }

    const aiResponse = data.candidates[0].content.parts[0].text

    return new Response(
      JSON.stringify({ 
        response: aiResponse,
        success: true 
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    )

  } catch (error) {
    console.error('Chat function error:', error)
    
    // Fallback response for errors
    const fallbackResponse = "I'm experiencing some technical difficulties right now. However, I can still help you with basic cybersecurity advice: Always verify sender identities, don't click suspicious links, use strong unique passwords, enable two-factor authentication, and when in doubt, verify through official channels. What specific security topic would you like to discuss?"

    return new Response(
      JSON.stringify({ 
        response: fallbackResponse,
        success: false,
        error: error.message 
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        status: 200 // Return 200 to show fallback response
      }
    )
  }
})