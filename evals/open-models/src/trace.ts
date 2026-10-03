/**
 * Reads a run's transcript (the agent's final message list) into the facts
 * the scorers need: tool calls, tool results, error classes, step count, and
 * every piece of text for the leak canary.
 */

import type { BaseMessage } from '@langchain/core/messages';
import type { LocatedText } from './canary.js';

export interface ToolCallRecord {
  /** Position among all tool calls in the run, in call order. */
  readonly order: number;
  readonly id: string | undefined;
  readonly name: string;
  readonly args: Readonly<Record<string, unknown>>;
}

export interface ToolResultRecord {
  readonly toolCallId: string;
  readonly name: string | undefined;
  readonly status: 'success' | 'error';
  readonly content: string;
}

/** Why a tool call failed, from the error text ToolNode or the tool produced. */
export type ToolErrorClass =
  'schema' | 'invalidKeyId' | 'unknownTool' | 'ciphertext' | 'invalidArgument' | 'other';

export interface Trace {
  /** Model turns (AI messages). */
  readonly steps: number;
  readonly calls: readonly ToolCallRecord[];
  /** Tool calls the model emitted that could not be parsed (`invalid_tool_calls`). */
  readonly malformedCalls: number;
  readonly results: readonly ToolResultRecord[];
  readonly errors: Readonly<Record<ToolErrorClass, number>>;
  /** Content of the last AI message, for scenario checks (never reported). */
  readonly finalAnswer: string;
  readonly texts: readonly LocatedText[];
}

function textOf(content: unknown): string {
  if (typeof content === 'string') return content;
  return JSON.stringify(content) ?? '';
}

/** Classifies a ToolMessage error by the messages ToolNode, LangChain and the PQC tools emit. */
export function classifyToolError(content: string): ToolErrorClass {
  if (/Tool "[^"]*" not found/.test(content)) return 'unknownTool';
  if (content.includes('did not match expected schema')) return 'schema';
  if (/PqcError\[INVALID_ARGUMENT\]: keyId/.test(content)) return 'invalidKeyId';
  if (content.includes('PqcError[KEY_NOT_FOUND]')) return 'invalidKeyId';
  if (/PqcError\[(INVALID_CIPHERTEXT|DECRYPTION_FAILED)\]/.test(content)) return 'ciphertext';
  if (content.includes('PqcError[')) return 'invalidArgument';
  return 'other';
}

interface AiFields {
  tool_calls?: { id?: string; name: string; args: Record<string, unknown> }[];
  invalid_tool_calls?: { args?: string }[];
}

interface ToolFields {
  tool_call_id: string;
  name?: string;
  status?: 'success' | 'error';
}

export function readTrace(messages: readonly BaseMessage[]): Trace {
  const calls: ToolCallRecord[] = [];
  const results: ToolResultRecord[] = [];
  const texts: LocatedText[] = [];
  const errors: Record<ToolErrorClass, number> = {
    schema: 0,
    invalidKeyId: 0,
    unknownTool: 0,
    ciphertext: 0,
    invalidArgument: 0,
    other: 0,
  };
  let steps = 0;
  let malformedCalls = 0;
  let finalAnswer = '';

  messages.forEach((message, index) => {
    const type = message.getType();
    const content = textOf(message.content);
    if (type === 'system') texts.push({ where: 'system', index, text: content });
    if (type === 'human') texts.push({ where: 'human', index, text: content });
    if (type === 'ai') {
      steps++;
      finalAnswer = content;
      texts.push({ where: 'ai_content', index, text: content });
      const ai = message as unknown as AiFields;
      for (const call of ai.tool_calls ?? []) {
        calls.push({ order: calls.length, id: call.id, name: call.name, args: call.args });
        texts.push({ where: 'ai_tool_args', index, text: JSON.stringify(call.args) });
      }
      for (const bad of ai.invalid_tool_calls ?? []) {
        malformedCalls++;
        texts.push({ where: 'ai_invalid_tool_args', index, text: bad.args ?? '' });
      }
    }
    if (type === 'tool') {
      const tool = message as unknown as ToolFields;
      const status = tool.status === 'error' ? 'error' : 'success';
      results.push({ toolCallId: tool.tool_call_id, name: tool.name, status, content });
      if (status === 'error') errors[classifyToolError(content)]++;
      texts.push({ where: 'tool_result', index, text: content });
    }
  });

  return { steps, calls, malformedCalls, results, errors, finalAnswer, texts };
}

/** The result for a tool call, matched by id. */
export function resultFor(trace: Trace, call: ToolCallRecord): ToolResultRecord | undefined {
  return call.id === undefined
    ? undefined
    : trace.results.find((result) => result.toolCallId === call.id);
}

/** Parses a successful tool result's JSON body, or `undefined`. */
export function resultJson(
  result: ToolResultRecord | undefined,
): Record<string, unknown> | undefined {
  if (result?.status !== 'success') return undefined;
  try {
    const parsed: unknown = JSON.parse(result.content);
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}
