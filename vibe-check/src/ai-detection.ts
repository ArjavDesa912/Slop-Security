/**
 * 🤖 AI-Powered Security Detection
 * 
 * Uses LLM to analyze code for security vulnerabilities
 * with context-aware understanding.
 */

export interface LLMConfig {
    provider: 'openai' | 'anthropic' | 'ollama' | 'custom';
    apiKey?: string;
    model?: string;
    baseUrl?: string;
    timeout?: number;
}

export interface AIDetectionResult {
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    owaspId: string;
    owaspName: string;
    description: string;
    line?: number;
    snippet?: string;
    suggestion?: string;
    confidence: number; // 0-1
}

const SECURITY_ANALYSIS_PROMPT = `You are a security expert analyzing code for OWASP Top 10 vulnerabilities.

Analyze the following code and identify ALL security issues. For each issue, provide:
1. Severity: critical, high, medium, low, or info
2. OWASP ID (A01-A10) and name
3. Clear description of the vulnerability
4. Line number(s) affected
5. Code snippet showing the issue
6. Suggested fix

OWASP Top 10 Reference:
- A01: Broken Access Control
- A02: Cryptographic Failures (hardcoded secrets, weak crypto, insecure random)
- A03: Injection (SQL, XSS, Command, NoSQL, Template, LDAP, XPath)
- A04: Insecure Design
- A05: Security Misconfiguration (debug mode, default creds, verbose errors)
- A06: Vulnerable Components
- A07: Authentication Failures (brute force, weak passwords, session issues)
- A08: Software and Data Integrity Failures
- A09: Security Logging Failures
- A10: Server-Side Request Forgery (SSRF)

Be thorough. Check for:
- Hardcoded API keys, passwords, tokens (any string that looks like a secret)
- SQL queries with string interpolation/concatenation
- Unsanitized user input in HTML, shell commands, file paths
- Insecure crypto (MD5, SHA1, Math.random for security)
- eval(), Function constructor, dynamic code execution
- SSRF: fetch/axios/http with user-controlled URLs
- Missing authentication/authorization checks
- Sensitive data exposure in logs or errors
- Path traversal vulnerabilities
- Insecure deserialization
- Race conditions in auth flows

Return your analysis as a JSON array. If no issues found, return [].

CODE TO ANALYZE:
\`\`\`
{CODE}
\`\`\`

Respond ONLY with valid JSON array, no other text:`;

/**
 * Analyze code using AI/LLM
 */
export async function analyzeWithAI(
    code: string,
    filename: string,
    config: LLMConfig
): Promise<AIDetectionResult[]> {
    const prompt = SECURITY_ANALYSIS_PROMPT.replace('{CODE}', code);

    try {
        let response: string;

        switch (config.provider) {
            case 'openai':
                response = await callOpenAI(prompt, config);
                break;
            case 'anthropic':
                response = await callAnthropic(prompt, config);
                break;
            case 'ollama':
                response = await callOllama(prompt, config);
                break;
            case 'custom':
                response = await callCustom(prompt, config);
                break;
            default:
                throw new Error(`Unknown provider: ${config.provider}`);
        }

        // Parse the JSON response
        const results = parseAIResponse(response, filename);
        return results;
    } catch (error) {
        console.error(`AI analysis failed: ${(error as Error).message}`);
        return [];
    }
}

async function callOpenAI(prompt: string, config: LLMConfig): Promise<string> {
    const apiKey = config.apiKey || process.env.OPENAI_API_KEY;
    if (!apiKey) throw new Error('OpenAI API key not configured');

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
            model: config.model || 'gpt-4o-mini',
            messages: [
                { role: 'system', content: 'You are a security expert. Respond only with valid JSON.' },
                { role: 'user', content: prompt }
            ],
            temperature: 0.1,
            max_tokens: 4096,
        }),
    });

    if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status}`);
    }

    const data = await response.json() as any;
    return data.choices[0]?.message?.content || '[]';
}

async function callAnthropic(prompt: string, config: LLMConfig): Promise<string> {
    const apiKey = config.apiKey || process.env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error('Anthropic API key not configured');

    const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
            model: config.model || 'claude-3-haiku-20240307',
            max_tokens: 4096,
            messages: [{ role: 'user', content: prompt }],
        }),
    });

    if (!response.ok) {
        throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data = await response.json() as any;
    return data.content[0]?.text || '[]';
}

async function callOllama(prompt: string, config: LLMConfig): Promise<string> {
    const baseUrl = config.baseUrl || 'http://localhost:11434';

    const response = await fetch(`${baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            model: config.model || 'llama3.2',
            prompt,
            stream: false,
            options: { temperature: 0.1 },
        }),
    });

    if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status}`);
    }

    const data = await response.json() as any;
    return data.response || '[]';
}

async function callCustom(prompt: string, config: LLMConfig): Promise<string> {
    if (!config.baseUrl) throw new Error('Custom LLM requires baseUrl');

    const response = await fetch(config.baseUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...(config.apiKey ? { 'Authorization': `Bearer ${config.apiKey}` } : {}),
        },
        body: JSON.stringify({ prompt, model: config.model }),
    });

    if (!response.ok) {
        throw new Error(`Custom LLM API error: ${response.status}`);
    }

    const data = await response.json() as any;
    return data.response || data.content || data.text || '[]';
}

function parseAIResponse(response: string, filename: string): AIDetectionResult[] {
    try {
        // Extract JSON from response (handle markdown code blocks)
        let jsonStr = response;
        const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)```/);
        if (jsonMatch) {
            jsonStr = jsonMatch[1];
        }

        // Try to find JSON array in the response
        const arrayMatch = jsonStr.match(/\[[\s\S]*\]/);
        if (arrayMatch) {
            jsonStr = arrayMatch[0];
        }

        const parsed = JSON.parse(jsonStr);

        if (!Array.isArray(parsed)) {
            return [];
        }

        return parsed.map((item: any) => ({
            severity: item.severity?.toLowerCase() || 'medium',
            owaspId: item.owaspId || item.owasp_id || 'A00',
            owaspName: item.owaspName || item.owasp_name || 'Unknown',
            description: item.description || item.message || 'Security issue detected',
            line: item.line || item.lineNumber || undefined,
            snippet: item.snippet || item.code || undefined,
            suggestion: item.suggestion || item.fix || item.recommendation || undefined,
            confidence: item.confidence || 0.8,
        }));
    } catch (error) {
        console.error('Failed to parse AI response:', error);
        return [];
    }
}

/**
 * Get default LLM config from environment
 */
export function getDefaultLLMConfig(): LLMConfig | null {
    if (process.env.OPENAI_API_KEY) {
        return { provider: 'openai', model: 'gpt-4o-mini' };
    }
    if (process.env.ANTHROPIC_API_KEY) {
        return { provider: 'anthropic', model: 'claude-3-haiku-20240307' };
    }
    // Check if Ollama is available
    return { provider: 'ollama', model: 'llama3.2', baseUrl: 'http://localhost:11434' };
}
