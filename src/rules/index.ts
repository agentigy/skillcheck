import type { Rule } from '../types.js';
import { secretsRule } from './secrets.js';
import { commandInjectionRule } from './command-injection.js';
import { pathTraversalRule } from './path-traversal.js';
import { privilegeEscalationRule } from './privilege-escalation.js';
import { informationDisclosureRule } from './information-disclosure.js';

/**
 * All available security rules
 */
export const ALL_RULES: Rule[] = [
  secretsRule,
  commandInjectionRule,
  pathTraversalRule,
  privilegeEscalationRule,
  informationDisclosureRule,
];

/**
 * Get rules by severity
 */
export function getRulesBySeverity(severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): Rule[] {
  return ALL_RULES.filter(rule => rule.severity === severity);
}

/**
 * Get rule by ID
 */
export function getRuleById(id: string): Rule | undefined {
  return ALL_RULES.find(rule => rule.id === id);
}

/**
 * Get rules by IDs
 */
export function getRulesByIds(ids: string[]): Rule[] {
  return ALL_RULES.filter(rule => ids.includes(rule.id));
}
