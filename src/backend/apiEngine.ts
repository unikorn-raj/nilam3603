import { GoogleGenAI, Type } from "@google/genai";
import { createClient } from "@supabase/supabase-js";

// Helper to resolve environment variables from Cloudflare Workers `env` or `process.env`
function getEnvVar(env: any, key: string): string {
  if (env && typeof env[key] === "string" && env[key].trim() !== "") {
    return env[key].trim();
  }
  if (typeof process !== "undefined" && process.env && typeof process.env[key] === "string") {
    return process.env[key].trim();
  }
  return "";
}

// Helper for standard JSON HTTP Response with CORS & Security headers
function jsonResponse(data: any, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "SAMEORIGIN",
      ...extraHeaders,
    },
  });
}

// Prompt Injection Sanitizer for AI Safeguarding
function sanitizePromptInput(text: string): string {
  if (!text) return "";
  let clean = String(text);
  const dangerousPatterns = [
    /ignore (all )?(previous|above|system) instructions/gi,
    /disregard (all )?(previous|system) instructions/gi,
    /you are now a/gi,
    /system prompt/gi,
    /override security/gi,
    /reveal (api|key|secret|password|prompt|database)/gi,
    /jailbreak/gi,
    /<script\b[^>]*>([\s\S]*?)<\/script>/gi,
  ];
  for (const rx of dangerousPatterns) {
    clean = clean.replace(rx, "[SECURITY_FILTERED]");
  }
  return clean.replace(/```/g, "'''").trim();
}

// Verify Supabase Auth Token using Supabase JS client
async function verifySupabaseToken(request: Request, env: any): Promise<{ user: any | null; authStatus: string }> {
  const authHeader = request.headers.get("Authorization") || request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { user: null, authStatus: "Unauthenticated-Guest" };
  }

  const token = authHeader.split("Bearer ")[1]?.trim();
  if (!token || token === "undefined" || token === "null") {
    return { user: null, authStatus: "Unauthenticated-Guest" };
  }

  const supabaseUrl = getEnvVar(env, "VITE_SUPABASE_URL");
  const supabaseAnonKey = getEnvVar(env, "VITE_SUPABASE_ANON_KEY");

  if (!supabaseUrl || !supabaseAnonKey) {
    return { user: null, authStatus: "Unauthenticated-NoSupabaseClient" };
  }

  try {
    const supabaseClient = createClient(supabaseUrl, supabaseAnonKey);
    const { data: { user }, error } = await supabaseClient.auth.getUser(token);
    if (error || !user) {
      return { user: null, authStatus: "Invalid-Token" };
    }
    return {
      user: {
        uid: user.id,
        id: user.id,
        email: user.email,
        role: user.role || user.app_metadata?.role,
        ...user,
      },
      authStatus: "Authenticated-" + user.id,
    };
  } catch (err: any) {
    console.warn("Supabase Auth Token verification failed:", err?.message || err);
    return { user: null, authStatus: "Invalid-Token" };
  }
}

// Get Gemini Client initialized with GEMINI_API_KEY from Cloudflare Workers `env` or `process.env`
function getGeminiClient(env: any) {
  const apiKey = getEnvVar(env, "GEMINI_API_KEY");
  if (!apiKey) {
    throw new Error(
      "GEMINI_API_KEY environment variable is missing. Please set GEMINI_API_KEY in your Cloudflare Worker environment variables / secrets."
    );
  }
  return new GoogleGenAI({
    apiKey,
  });
}

// Helper function to generate content with retry and fallback for transient errors
async function generateContentWithRetry(
  ai: GoogleGenAI,
  options: {
    model: string;
    contents: any;
    config?: any;
  },
  maxRetries = 3
) {
  let delay = 1000;
  const modelsToTry = [options.model];

  for (const modelName of modelsToTry) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const res = await ai.models.generateContent({
          ...options,
          model: modelName,
        });
        return res;
      } catch (err: any) {
        const errStr = String(err?.message || err);
        const isTransient =
          err?.status === 503 ||
          err?.code === 503 ||
          err?.status === 500 ||
          err?.code === 500 ||
          err?.status === 429 ||
          err?.code === 429 ||
          errStr.includes("503") ||
          errStr.includes("500") ||
          errStr.includes("internal error") ||
          errStr.includes("UNAVAILABLE") ||
          errStr.includes("high demand") ||
          errStr.includes("429") ||
          errStr.includes("RESOURCE_EXHAUSTED");

        if (isTransient && attempt < maxRetries - 1) {
          console.warn(`Gemini API transient capacity notice (${errStr}). Retrying attempt ${attempt + 1}/${maxRetries} in ${delay}ms...`);
          await new Promise((r) => setTimeout(r, delay));
          delay *= 1.5;
        } else {
          if (attempt === maxRetries - 1) {
            console.warn(`Gemini model ${modelName} failed after ${maxRetries} attempts: ${errStr}`);
          } else {
            throw err;
          }
        }
      }
    }
  }

  return await ai.models.generateContent(options);
}

// Safely parse JSON from Gemini model output
function cleanAndParseJson(text: string): any {
  if (!text) return {};

  let cleaned = text.trim();
  if (cleaned.startsWith("```json")) {
    cleaned = cleaned.substring(7);
  } else if (cleaned.startsWith("```")) {
    cleaned = cleaned.substring(3);
  }
  if (cleaned.endsWith("```")) {
    cleaned = cleaned.slice(0, -3);
  }
  cleaned = cleaned.trim();

  try {
    return JSON.parse(cleaned);
  } catch (firstErr) {
    try {
      const sanitized = cleaned.replace(/[\u0000-\u001F\u007F-\u009F]/g, (match) => {
        if (match === "\n") return "\\n";
        if (match === "\r") return "\\r";
        if (match === "\t") return "\\t";
        return "";
      });
      return JSON.parse(sanitized);
    } catch (secondErr) {
      console.error("cleanAndParseJson failed to parse:", secondErr);
      throw secondErr;
    }
  }
}

// Complete 12-stage analysis schema
const caseAnalysisResponseSchema = {
  type: Type.OBJECT,
  required: [
    "stage0",
    "stage1",
    "stage2",
    "stage3",
    "stage4",
    "stage5",
    "stage6",
    "stage7",
    "stage8",
    "stage9",
    "stage10",
    "stage11",
    "stage12",
    "clientFacingReply",
    "documentsRequired",
    "immediateAction",
    "servicePackage",
    "customDocumentDraft",
  ],
  properties: {
    stage0: {
      type: Type.OBJECT,
      properties: {
        workspace: { type: Type.STRING },
        subWorkspace: { type: Type.STRING },
        module: { type: Type.STRING },
        engine: { type: Type.STRING },
        clientName: { type: Type.STRING },
        mobile: { type: Type.STRING },
        surveyNumber: { type: Type.STRING },
        village: { type: Type.STRING },
        taluk: { type: Type.STRING },
        district: { type: Type.STRING },
        oppositeParty: { type: Type.STRING },
        partyRelationship: { type: Type.STRING },
        courtOrForum: { type: Type.STRING },
        existingAdvocate: { type: Type.STRING },
        existingCaseNumber: { type: Type.STRING },
        limitationRisk: { type: Type.STRING },
      },
    },
    stage1: {
      type: Type.OBJECT,
      properties: {
        category: { type: Type.STRING },
        specificType: { type: Type.STRING },
      },
    },
    stage2: {
      type: Type.OBJECT,
      properties: {
        realIssue: { type: Type.STRING },
        rootCauseStatement: { type: Type.STRING },
      },
    },
    stage3: {
      type: Type.OBJECT,
      properties: {
        subjectType: { type: Type.STRING },
        partyRelationshipMap: { type: Type.STRING },
      },
    },
    stage4: {
      type: Type.OBJECT,
      properties: {
        timelineEvents: {
          type: Type.ARRAY,
          items: { type: Type.STRING },
        },
      },
    },
    stage5: {
      type: Type.OBJECT,
      properties: {
        rightsViolated: { type: Type.ARRAY, items: { type: Type.STRING } },
        dutiesBreached: { type: Type.ARRAY, items: { type: Type.STRING } },
        legalObligations: { type: Type.ARRAY, items: { type: Type.STRING } },
        possibleLiabilities: { type: Type.ARRAY, items: { type: Type.STRING } },
        availableProtections: { type: Type.ARRAY, items: { type: Type.STRING } },
      },
    },
    stage6: {
      type: Type.OBJECT,
      properties: {
        available: { type: Type.ARRAY, items: { type: Type.STRING } },
        missing: { type: Type.ARRAY, items: { type: Type.STRING } },
        documentary: { type: Type.ARRAY, items: { type: Type.STRING } },
        electronic: { type: Type.ARRAY, items: { type: Type.STRING } },
        witnesses: { type: Type.ARRAY, items: { type: Type.STRING } },
        officialRecords: { type: Type.ARRAY, items: { type: Type.STRING } },
        evidenceStrength: { type: Type.STRING },
      },
    },
    stage7: {
      type: Type.OBJECT,
      properties: {
        route: {
          type: Type.ARRAY,
          items: { type: Type.STRING },
        },
        primaryAuthority: { type: Type.STRING },
        appellateAuthority: { type: Type.STRING },
        forumType: { type: Type.STRING },
      },
    },
    stage8: {
      type: Type.OBJECT,
      properties: {
        category: { type: Type.STRING },
        primaryRemedy: { type: Type.STRING },
        remedyType: { type: Type.STRING },
        alternativeOptions: { type: Type.ARRAY, items: { type: Type.STRING } },
      },
    },
    stage9: {
      type: Type.OBJECT,
      properties: {
        factors: {
          type: Type.ARRAY,
          items: { type: Type.STRING },
        },
        score: { type: Type.INTEGER },
        rating: { type: Type.STRING },
        limitationStatus: { type: Type.STRING },
        urgencyLevel: { type: Type.STRING },
      },
    },
    stage10: {
      type: Type.OBJECT,
      properties: {
        packageName: { type: Type.STRING },
        priceRange: { type: Type.STRING },
        description: { type: Type.STRING },
        deliverablesList: { type: Type.ARRAY, items: { type: Type.STRING } },
      },
    },
    stage11: {
      type: Type.OBJECT,
      properties: {
        similarCasesCount: { type: Type.INTEGER },
        averageSimilarityScore: { type: Type.INTEGER },
        similarCases: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              id: { type: Type.STRING },
              caseName: { type: Type.STRING },
              citationNumber: { type: Type.STRING },
              court: { type: Type.STRING },
              judge: { type: Type.STRING },
              year: { type: Type.STRING },
              state: { type: Type.STRING },
              bench: { type: Type.STRING },
              caseType: { type: Type.STRING },
              similarityScore: { type: Type.INTEGER },
              factsComparison: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    feature: { type: Type.STRING },
                    currentCase: { type: Type.STRING },
                    referenceCase: { type: Type.STRING },
                    match: { type: Type.BOOLEAN },
                  },
                },
              },
              issuesCompared: { type: Type.ARRAY, items: { type: Type.STRING } },
              legalPrinciples: { type: Type.ARRAY, items: { type: Type.STRING } },
              courtReasoningSummary: { type: Type.STRING },
              finalOutcome: { type: Type.STRING },
              whyItMatters: { type: Type.STRING },
              authoritiesCited: { type: Type.ARRAY, items: { type: Type.STRING } },
            },
          },
        },
        overallPrinciples: { type: Type.ARRAY, items: { type: Type.STRING } },
        successProbability: {
          type: Type.OBJECT,
          properties: {
            percentage: { type: Type.INTEGER },
            rating: { type: Type.STRING },
            disclaimer: { type: Type.STRING },
          },
        },
        authoritiesSummary: {
          type: Type.OBJECT,
          properties: {
            supremeCourtCount: { type: Type.INTEGER },
            highCourtCount: { type: Type.INTEGER },
            governmentOrdersCount: { type: Type.INTEGER },
            circularsCount: { type: Type.INTEGER },
            statutesList: { type: Type.ARRAY, items: { type: Type.STRING } },
          },
        },
        strategyRecommendationFromPrecedents: { type: Type.STRING },
      },
    },
    stage12: {
      type: Type.OBJECT,
      properties: {
        strongestLegalRoute: {
          type: Type.OBJECT,
          properties: {
            routeName: { type: Type.STRING },
            routeType: { type: Type.STRING },
            justification: { type: Type.STRING },
            timeToResolutionEst: { type: Type.STRING },
          },
        },
        mostPersuasivePrecedents: { type: Type.ARRAY, items: { type: Type.STRING } },
        evidenceGapsToFill: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              missingElement: { type: Type.STRING },
              howToObtain: { type: Type.STRING },
              urgency: { type: Type.STRING },
            },
          },
        },
        likelyOppositeCounterarguments: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              argument: { type: Type.STRING },
              rebuttalStrategy: { type: Type.STRING },
            },
          },
        },
        recommendedAdditionalProof: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              type: { type: Type.STRING },
              title: { type: Type.STRING },
              purpose: { type: Type.STRING },
            },
          },
        },
        priorityNextActions: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              stepNumber: { type: Type.INTEGER },
              action: { type: Type.STRING },
              targetAuthority: { type: Type.STRING },
              timeline: { type: Type.STRING },
            },
          },
        },
      },
    },
    clientFacingReply: {
      type: Type.OBJECT,
      properties: {
        problemIdentified: { type: Type.STRING },
        legalPosition: { type: Type.STRING },
        immediateNextStep: { type: Type.STRING },
        expectedAuthority: { type: Type.STRING },
        estimatedTimeline: { type: Type.STRING },
      },
    },
    documentsRequired: {
      type: Type.OBJECT,
      properties: {
        mandatory: { type: Type.ARRAY, items: { type: Type.STRING } },
        revenue: { type: Type.ARRAY, items: { type: Type.STRING } },
        family: { type: Type.ARRAY, items: { type: Type.STRING } },
        court: { type: Type.ARRAY, items: { type: Type.STRING } },
        other: { type: Type.ARRAY, items: { type: Type.STRING } },
      },
    },
    immediateAction: {
      type: Type.OBJECT,
      properties: {
        within24Hours: { type: Type.ARRAY, items: { type: Type.STRING } },
        within7Days: { type: Type.ARRAY, items: { type: Type.STRING } },
        within30Days: { type: Type.ARRAY, items: { type: Type.STRING } },
      },
    },
    servicePackage: {
      type: Type.OBJECT,
      properties: {
        recommendedPackage: { type: Type.STRING },
        deliverables: { type: Type.ARRAY, items: { type: Type.STRING } },
        professionalFee: { type: Type.STRING },
        expectedOutcome: { type: Type.STRING },
      },
    },
    customDocumentDraft: {
      type: Type.OBJECT,
      properties: {
        documentTitle: { type: Type.STRING },
        documentContent: { type: Type.STRING },
      },
    },
  },
};

// Main Web Standards Request Handler for Cloudflare Workers & Node/Express
export async function handleApiRequest(request: Request, env: any): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // 1. GET /api/health
  if (pathname === "/api/health" && request.method === "GET") {
    return jsonResponse({
      status: "ok",
      platform: "cloudflare-worker",
      time: new Date().toISOString(),
    });
  }

  // 2. POST /api/analyze
  if (pathname === "/api/analyze" && request.method === "POST") {
    try {
      let body: any = {};
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON body provided in request." }, 400);
      }

      const { intake, rawDescription } = body;

      if (!rawDescription || typeof rawDescription !== "string") {
        return jsonResponse({ error: "Raw case description text is required for analysis." }, 400);
      }

      if (rawDescription.trim().length < 10) {
        return jsonResponse({ error: "Case description must be at least 10 characters long." }, 400);
      }

      if (rawDescription.length > 20000) {
        return jsonResponse({ error: "Case description exceeds maximum length limit of 20,000 characters." }, 400);
      }

      // Verify Auth Token if provided
      const { authStatus } = await verifySupabaseToken(request, env);

      const workspace = intake?.workspace || "Citizen360";
      const subWorkspace = intake?.subWorkspace || "Property360";
      const module = intake?.module || "Registration";
      const engine = intake?.engine || "CaseClassificationAI";

      const safeIntake = {
        workspace: String(workspace).slice(0, 50),
        subWorkspace: String(subWorkspace).slice(0, 50),
        module: String(module).slice(0, 50),
        engine: String(engine).slice(0, 50),
        clientName: String(intake?.clientName || "Unknown").slice(0, 100),
        mobile: String(intake?.mobile || "Unknown").slice(0, 20),
        surveyNumber: String(intake?.surveyNumber || "N/A").slice(0, 100),
        village: String(intake?.village || "N/A").slice(0, 100),
        taluk: String(intake?.taluk || "N/A").slice(0, 100),
        district: String(intake?.district || "Madurai").slice(0, 100),
        oppositeParty: String(intake?.oppositeParty || "Opposite Party").slice(0, 100),
        partyRelationship: String(intake?.partyRelationship || "Disputing Parties").slice(0, 100),
        courtOrForum: String(intake?.courtOrForum || "Jurisdictional Authority / Court").slice(0, 100),
        existingAdvocate: String(intake?.existingAdvocate || "No").slice(0, 50),
        existingCaseNumber: String(intake?.existingCaseNumber || "None").slice(0, 100),
        limitationRisk: String(intake?.limitationRisk || "No").slice(0, 50),
      };

      const safeNarrative = sanitizePromptInput(rawDescription.slice(0, 20000));
      const ai = getGeminiClient(env);

      let prompt = "";
      if (safeIntake.module === "Consumer360") {
        prompt = `
You are the Master Legal AI Engine for the UNIKORN360 – CONSUMER360 CASE SOLVING FRAMEWORK v2.0.
Your mandate is to answer one central question:
"Has a consumer suffered because a product or service provider failed in their legal duty, and what is the fastest way to obtain compensation or corrective relief?"

### CLIENT INTAKE DETAILS (Stage 0):
- SubWorkspace: Consumer360 (Citizen360)
- Module: Consumer360
- AI Engine / Agent: ${safeIntake.engine || "ProductDefectAI"}
- Client / Consumer Name: ${safeIntake.clientName}
- Mobile: ${safeIntake.mobile}
- Location / District: ${safeIntake.district}
- Consumer Forum / Authority: ${safeIntake.courtOrForum}
- Opposite Party (Seller/Manufacturer/Provider): ${safeIntake.oppositeParty}
- Party Relationship Context: ${safeIntake.partyRelationship}
- Existing Advocate / Case: ${safeIntake.existingAdvocate} (${safeIntake.existingCaseNumber})
- Limitation / Urgency Risk?: ${safeIntake.limitationRisk}

### RAW CONSUMER DISPUTE NARRATIVE:
"${safeNarrative}"

---

### UNIKORN360 CONSUMER360 12-STAGE CASE SOLVING FRAMEWORK:
STAGE 1. Case Classification -> Identify Consumer Category
STAGE 2. Core Consumer Issue -> Identify Root Issue
STAGE 3. Consumer Relationship -> Map relationships
STAGE 4. Transaction Timeline -> Chronological sequence
STAGE 5. Rights Violated -> Evaluate Rights under CPA 2019
STAGE 6. Evidence Assessment -> Audit available proof
STAGE 7. Proper Forum Recommendation -> Determine proper forum
STAGE 8. Resolution Strategy -> Recommend remedies
STAGE 9. Risk & Urgency Rating -> Rate Limitation & Urgency
STAGE 10. Deliverables -> Generate Consumer Case Summary & Draft
STAGE 11. Consumer Precedent Intelligence -> Real SC/NCDRC precedents
STAGE 12. Client Resolution Report -> Step-by-step action plan
`;
      } else if (safeIntake.subWorkspace === "Legal360") {
        prompt = `
You are the Master Legal AI Engine for the UNIKORN360 LEGAL CASE SOLUTION FRAMEWORK v2.0.
Perform a problem-solving centered legal analysis for the specified legal module: "${safeIntake.module}".

### CLIENT INTAKE DETAILS (Stage 0):
- SubWorkspace: Legal360 (Citizen360)
- Module: ${safeIntake.module}
- AI Engine / Agent: ${safeIntake.engine}
- Client / Complainant Name: ${safeIntake.clientName}
- Mobile: ${safeIntake.mobile}
- Location / District: ${safeIntake.district}
- Forum / Jurisdiction Authority: ${safeIntake.courtOrForum}
- Opposite Party: ${safeIntake.oppositeParty}
- Party Relationship Context: ${safeIntake.partyRelationship}
- Existing Advocate / Proceedings?: ${safeIntake.existingAdvocate} (${safeIntake.existingCaseNumber})
- Limitation / Urgency Risk?: ${safeIntake.limitationRisk}

### RAW CLIENT CASE NARRATIVE:
"${safeNarrative}"

---

### UNIKORN360 LEGAL CASE SOLUTION FRAMEWORK (12 STAGES):
1. STAGE 1. Case Classification
2. STAGE 2. Core Legal Problem
3. STAGE 3. Parties & Relationship
4. STAGE 4. Cause of Action
5. STAGE 5. Rights & Liabilities
6. STAGE 6. Evidence Assessment
7. STAGE 7. Legal Route
8. STAGE 8. Remedy Strategy
9. STAGE 9. Risk & Urgency Analysis
10. STAGE 10. Deliverables & Execution
11. STAGE 11. Precedent Intelligence Framework
12. STAGE 12. Strategy & Outcome Simulator
`;
      } else {
        prompt = `
You are the AI Orchestration Engine for the UNIKORN360 PROPERTY & LAND REVENUE CASE SOLVING SYSTEM.
Analyze the following raw property dispute from Tamil Nadu using the UNIKORN360 PROPERTY CASE SOLVING FRAMEWORK v2.0 with STAGE 11 PRECEDENT INTELLIGENCE & STAGE 12 STRATEGY SIMULATOR.

### CLIENT INTAKE DETAILS (Stage 0):
- Client Name: ${safeIntake.clientName}
- Mobile: ${safeIntake.mobile}
- Survey Number: ${safeIntake.surveyNumber}
- Village: ${safeIntake.village}
- Taluk: ${safeIntake.taluk}
- District: ${safeIntake.district}
- Opposite Party: ${safeIntake.oppositeParty}
- Existing Advocate?: ${safeIntake.existingAdvocate}
- Existing Case Number?: ${safeIntake.existingCaseNumber}
- Limitation Risk?: ${safeIntake.limitationRisk}

### RAW CLIENT CASE NARRATIVE:
"${safeNarrative}"

---

### INSTRUCTIONS:
Perform a deep and meticulous legal and administrative analysis based on Tamil Nadu property laws (including Patta mutation, SRO registration rules, Section 77A of Registration Act for fraudulent documents, UDR/FMB errors, and Civil Court remedies) including Stage 11 Precedent Intelligence and Stage 12 Strategy & Outcome Simulator.
`;
      }

      const systemInstruction = `
You are the Senior Legal Counsel and Master Case Solution Engine of Unikorn360, expert across Indian & Tamil Nadu legal practice areas (Civil, Criminal, Family, Consumer, Labour, Tax, Corporate, Cyber, Constitutional, and Land Revenue).
Analyze cases strictly using the 12-stage framework including Precedent Intelligence and Strategy Simulation.
Always respond in valid, clean JSON according to the schema provided.
Ensure the analysis is highly customized, actionable, and legally sound.

CRITICAL LANGUAGE MANDATE:
Since this platform serves clients and advocates across Tamil Nadu and South India, generate ALL user-facing analysis descriptions, legal positions, risk factor lists, client replies, action items, precedent summaries, court reasoning, strategy recommendations, and package descriptions in formal, clear, and professional Tamil (தமிழ்). Keep only the JSON keys in English as specified by the schema.
`;

      const response = await generateContentWithRetry(ai, {
        model: "gemini-3.6-flash",
        contents: prompt,
        config: {
          systemInstruction,
          responseMimeType: "application/json",
          responseSchema: caseAnalysisResponseSchema,
        },
      });

      const parsedData = cleanAndParseJson(response.text || "{}");
      return jsonResponse(parsedData, 200, { "X-Auth-Status": authStatus });
    } catch (error: any) {
      console.error("Analysis Error:", error);
      return jsonResponse({ error: error.message || "Failed to analyze case using Unikorn360 engine." }, 500);
    }
  }

  // 3. POST /api/draft
  if (pathname === "/api/draft" && request.method === "POST") {
    try {
      let body: any = {};
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON body provided in request." }, 400);
      }

      const { caseData, documentTitle, instructions } = body;

      if (!caseData || !instructions || typeof instructions !== "string") {
        return jsonResponse({ error: "Case data and drafting instructions string are required." }, 400);
      }

      if (instructions.trim().length < 3) {
        return jsonResponse({ error: "Drafting instructions must be at least 3 characters long." }, 400);
      }

      if (instructions.length > 5000) {
        return jsonResponse({ error: "Drafting instructions exceed maximum limit of 5,000 characters." }, 400);
      }

      const ai = getGeminiClient(env);
      const safeTitle = String(documentTitle || "Legal Notice / Petition").slice(0, 150);
      const safeInstructions = sanitizePromptInput(instructions.slice(0, 5000));

      const prompt = `
You are the expert property documentation specialist at Unikorn360.
Review the following case details:
- Client: ${String(caseData.stage0?.clientName || "Unknown").slice(0, 100)}
- Opposite Party: ${String(caseData.stage0?.oppositeParty || "Unknown").slice(0, 100)}
- Property Location: Village ${String(caseData.stage0?.village || "N/A").slice(0, 100)}, Taluk ${String(caseData.stage0?.taluk || "N/A").slice(0, 100)}, District ${String(caseData.stage0?.district || "N/A").slice(0, 100)}
- Survey Number: ${String(caseData.stage0?.surveyNumber || "N/A").slice(0, 100)}
- Root Issue: ${String(caseData.stage2?.rootCauseStatement || "N/A").slice(0, 300)}
- Primary Remedy: ${String(caseData.stage8?.primaryRemedy || "N/A").slice(0, 300)}

The current draft title is: "${safeTitle}"

### USER CUSTOMIZATION INSTRUCTIONS:
"${safeInstructions}"

Draft a comprehensive, legally rigorous, and fully customized Tamil Nadu property petition, objection notice, or official representation matching these requirements. 
Use formal, highly persuasive, and authoritative legal phrasing. Write the complete document content. Include placeholders like [Date], [Signature], and format with clean whitespace for easy copying and pasting.
`;

      const systemInstruction = `
You are a senior lawyer of the Madras High Court drafting property dispute pleadings, official notices to authorities (Tahsildars, District Registrars, SROs), and cease-and-desist notices.
Respond with a JSON object containing 'documentTitle' and 'documentContent'.

CRITICAL: Since this system serves Tier-2 Tamil Nadu, you MUST draft the complete documentTitle and documentContent in highly formal, legally rigorous, and persuasive Tamil (தமிழ்).
`;

      const response = await generateContentWithRetry(ai, {
        model: "gemini-3.6-flash",
        contents: prompt,
        config: {
          systemInstruction,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            required: ["documentTitle", "documentContent"],
            properties: {
              documentTitle: { type: Type.STRING },
              documentContent: { type: Type.STRING },
            },
          },
        },
      });

      let parsedData: any = {};
      try {
        parsedData = cleanAndParseJson(response.text || "{}");
      } catch (parseErr) {
        parsedData = {
          documentTitle: documentTitle || "சட்டப்பூர்வ ஆட்சேபனை மனு",
          documentContent: response.text || "வரைவு தயாரிப்பதில் பிழை ஏற்பட்டது. தயவுசெய்து மீண்டும் முயற்சிக்கவும்.",
        };
      }

      return jsonResponse(parsedData, 200);
    } catch (error: any) {
      console.error("Drafting Error:", error);
      return jsonResponse({ error: error.message || "Failed to draft custom legal document." }, 500);
    }
  }

  // Fallback for unknown /api/ endpoints
  if (pathname.startsWith("/api/")) {
    return jsonResponse({ error: `API endpoint '${pathname}' not found.` }, 404);
  }

  return new Response("Not Found", { status: 404 });
}
