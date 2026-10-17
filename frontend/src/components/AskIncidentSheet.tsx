"use client";

import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import {
  AlertCircle,
  Bot,
  CornerDownLeft,
  Loader2,
  ShieldAlert,
  Sparkles,
  Square,
} from "lucide-react";
import type React from "react";
import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";

interface AskIncidentSheetProps {
  incidentId: string;
}

const SUGGESTED_QUESTIONS = [
  "What evidence indicates a port scan versus benign scanner activity?",
  "Which source IPs and destination ports show the most extreme statistical deviations?",
  "What are the benign alternative explanations for this traffic burst?",
  "Summarize the timeline and key host interactions for incident triage.",
];

export function AskIncidentSheet({ incidentId }: AskIncidentSheetProps) {
  const [open, setOpen] = useState(false);
  const [inputQuestion, setInputQuestion] = useState("");

  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: "/api/chat",
        body: () => ({ incidentId }),
      }),
    [incidentId],
  );

  const {
    messages,
    sendMessage,
    status,
    stop,
    error: chatError,
  } = useChat({
    transport,
  });

  const isLoading = status === "submitted" || status === "streaming";

  const handleSend = async (questionText?: string) => {
    const textToSend = (questionText || inputQuestion).trim();
    if (!textToSend || isLoading) return;

    setInputQuestion("");
    await sendMessage({
      role: "user",
      parts: [{ type: "text", text: textToSend }],
    });
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger className="inline-flex items-center justify-center gap-1.5 h-8 px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-xs font-medium cursor-pointer transition-colors shadow-xs">
        <Sparkles className="h-3.5 w-3.5" />
        Ask AI Assistant
      </SheetTrigger>
      <SheetContent
        side="right"
        className="w-full sm:max-w-xl flex flex-col p-0 h-full border-l"
      >
        <SheetHeader className="p-4 sm:p-5 pb-3 border-b bg-card">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-md bg-primary/10 text-primary">
              <Bot className="h-4 w-4" />
            </div>
            <div>
              <SheetTitle className="text-sm font-semibold tracking-normal normal-case">
                GenAI Incident Assistant
              </SheetTitle>
              <SheetDescription className="text-xs">
                Incident: <span className="font-mono">{incidentId}</span>
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>

        {/* Conversation Message List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 && (
            <div className="space-y-4">
              <div className="rounded-lg border bg-muted/20 p-3.5 text-xs text-muted-foreground space-y-2">
                <div className="flex items-center gap-1.5 font-medium text-foreground">
                  <ShieldAlert className="h-3.5 w-3.5 text-primary" />
                  Evidence-Grounded Assistant
                </div>
                <p className="leading-relaxed">
                  Ask targeted triage questions about this incident. The
                  assistant synthesizes answers strictly from verified flow
                  records, baseline statistical feature deviations, and analyst
                  feedback notes with direct citation tags (e.g.{" "}
                  <code className="text-primary font-mono">[flow 102]</code>).
                </p>
              </div>

              <div className="space-y-2">
                <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Suggested Prompts
                </div>
                <div className="grid grid-cols-1 gap-1.5">
                  {SUGGESTED_QUESTIONS.map((q) => (
                    <button
                      type="button"
                      key={q}
                      onClick={() => handleSend(q)}
                      disabled={isLoading}
                      className="text-left text-xs p-2 rounded-md border border-input bg-background hover:bg-muted text-foreground transition-colors cursor-pointer"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Chat Messages */}
          {messages.map((msg) => {
            const isUser = msg.role === "user";
            let fullText = "";
            let meta: {
              provider?: string;
              model?: string;
              cited_flow_ids?: number[];
              invalid_citations?: number[];
            } | null = null;

            if (Array.isArray(msg.parts)) {
              for (const part of msg.parts) {
                if (part.type === "text" && "text" in part) {
                  fullText += (part as { text: string }).text;
                } else if (
                  part.type === "data-metadata" &&
                  "data" in part &&
                  part.data
                ) {
                  meta = part.data as {
                    provider?: string;
                    model?: string;
                    cited_flow_ids?: number[];
                    invalid_citations?: number[];
                  };
                }
              }
            } else if (
              typeof (msg as unknown as { content: string }).content ===
              "string"
            ) {
              fullText = (msg as unknown as { content: string }).content;
            }

            return (
              <div
                key={msg.id}
                className={`flex flex-col space-y-1.5 ${
                  isUser ? "items-end" : "items-start"
                }`}
              >
                <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground px-1">
                  {isUser ? (
                    <span>Analyst</span>
                  ) : (
                    <span className="flex items-center gap-1">
                      <Sparkles className="h-3 w-3 text-primary" />
                      <span>
                        {meta?.provider || "Assistant"}{" "}
                        {meta?.model ? `(${meta.model})` : ""}
                      </span>
                    </span>
                  )}
                </div>

                <div
                  className={`max-w-[90%] rounded-lg p-3 text-xs leading-relaxed ${
                    isUser
                      ? "bg-primary text-primary-foreground font-medium"
                      : "bg-muted/40 border text-foreground space-y-2"
                  }`}
                >
                  {isUser ? (
                    <div className="whitespace-pre-wrap">{fullText}</div>
                  ) : (
                    <div className="prose prose-sm dark:prose-invert max-w-none space-y-2 text-xs leading-relaxed break-words font-sans">
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={{
                          h1: ({ ...props }) => (
                            <h1
                              className="text-sm font-bold font-heading mt-2 mb-1"
                              {...props}
                            />
                          ),
                          h2: ({ ...props }) => (
                            <h2
                              className="text-xs font-bold font-heading mt-2 mb-1"
                              {...props}
                            />
                          ),
                          h3: ({ ...props }) => (
                            <h3
                              className="text-xs font-semibold font-heading mt-1.5 mb-0.5"
                              {...props}
                            />
                          ),
                          p: ({ ...props }) => (
                            <p className="mb-1.5 leading-relaxed" {...props} />
                          ),
                          ul: ({ ...props }) => (
                            <ul
                              className="list-disc pl-4 mb-2 space-y-0.5"
                              {...props}
                            />
                          ),
                          ol: ({ ...props }) => (
                            <ol
                              className="list-decimal pl-4 mb-2 space-y-0.5"
                              {...props}
                            />
                          ),
                          li: ({ ...props }) => (
                            <li className="leading-relaxed" {...props} />
                          ),
                          code: ({ className, children, ...props }) => {
                            const isBlock = Boolean(className);
                            return isBlock ? (
                              <pre className="p-2 rounded bg-muted font-mono text-[11px] overflow-x-auto my-1">
                                <code {...props}>{children}</code>
                              </pre>
                            ) : (
                              <code
                                className="px-1 py-0.5 rounded bg-muted/80 font-mono text-[11px] text-primary"
                                {...props}
                              >
                                {children}
                              </code>
                            );
                          },
                        }}
                      >
                        {fullText}
                      </ReactMarkdown>
                    </div>
                  )}

                  {meta && (
                    <div className="pt-2 border-t border-border/50 space-y-1.5">
                      {meta.cited_flow_ids &&
                        meta.cited_flow_ids.length > 0 && (
                          <div className="flex flex-wrap items-center gap-1 text-[10px]">
                            <span className="text-muted-foreground font-medium">
                              Cited Flows:
                            </span>
                            {meta.cited_flow_ids.map((id: number) => (
                              <Badge
                                key={id}
                                variant="secondary"
                                className="font-mono text-[10px] px-1 py-0 h-4"
                              >
                                flow {id}
                              </Badge>
                            ))}
                          </div>
                        )}

                      {meta.invalid_citations &&
                        meta.invalid_citations.length > 0 && (
                          <div className="text-[10px] text-amber-600 dark:text-amber-400">
                            Unverified citations:{" "}
                            {meta.invalid_citations.join(", ")}
                          </div>
                        )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {isLoading && status === "submitted" && (
            <div className="flex items-center gap-2 p-3 text-xs text-muted-foreground bg-muted/20 rounded-md border">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
              <span>Analyzing incident flow telemetry & deviations...</span>
            </div>
          )}

          {chatError && (
            <Alert variant="destructive" className="py-2.5">
              <AlertCircle className="h-3.5 w-3.5" />
              <AlertTitle className="text-xs">Assistant Error</AlertTitle>
              <AlertDescription className="text-xs">
                {chatError.message || "Failed to stream assistant response"}
              </AlertDescription>
            </Alert>
          )}
        </div>

        {/* Input Footer */}
        <div className="p-3 sm:p-4 border-t bg-card space-y-2">
          <div className="relative">
            <Textarea
              id="assistant-query"
              value={inputQuestion}
              onChange={(e) => setInputQuestion(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about this incident, e.g. Why was this flagged as a port scan? (Press Enter to send)"
              className="resize-none min-h-[70px] text-xs pr-12"
              disabled={isLoading}
            />
            {isLoading ? (
              <Button
                size="icon"
                variant="destructive"
                onClick={() => stop()}
                className="absolute bottom-2 right-2 h-7 w-7"
                title="Stop streaming"
              >
                <Square className="h-3 w-3 fill-current" />
              </Button>
            ) : (
              <Button
                size="icon"
                disabled={!inputQuestion.trim()}
                onClick={() => handleSend()}
                className="absolute bottom-2 right-2 h-7 w-7"
                title="Send query"
              >
                <CornerDownLeft className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
