#!/usr/bin/env node
/**
 * 🔍 Vibe-Check CLI - AI-Powered Security Scanner
 * 
 * Scans AI-generated code for OWASP vulnerabilities using
 * both pattern matching and LLM-based detection.
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import fg from 'fast-glob';
import * as fs from 'fs/promises';
import * as path from 'path';
import { scanContent, scanWithPatterns, applyFixes, generateReport, ScanResult, loadCustomPatterns, DEFAULT_PATTERNS } from './index.js';

const VERSION = '1.0.0';

const program = new Command();

program
    .name('vibe-check')
    .description('🔍 AI-powered security scanner for AI-generated code (slop)')
    .version(VERSION)
    .argument('[path]', 'Path to scan', '.')
    .option('-f, --fix', 'Auto-fix issues where possible')
    .option('--ci', 'CI mode - exit with error code on failures')
    .option('--fail-on <severities>', 'Fail on these severities (comma-separated)', 'critical,high')
    .option('--report <format>', 'Report format: text, json, html', 'text')
    .option('--include <patterns>', 'Include glob patterns (comma-separated)', '**/*.{js,ts,jsx,tsx,py,rb,php,go}')
    .option('--exclude <patterns>', 'Exclude glob patterns (comma-separated)', '**/node_modules/**,**/dist/**,**/.git/**')
    .option('--ai', 'Enable AI-powered detection (requires API key)')
    .option('--ai-only', 'Use only AI detection (no pattern matching)')
    .option('--ai-provider <provider>', 'AI provider: openai, anthropic, ollama, gemini-cli, claude-cli, manual', 'openai')
    .option('--ai-model <model>', 'AI model to use')
    .option('--patterns <file>', 'Path to custom patterns JSON file')
    .action(async (scanPath: string, options: any) => {
        console.log(chalk.bold.cyan('\n🔍 Vibe-Check Security Scanner v' + VERSION));

        // Show AI mode indicator
        if (options.aiOnly) {
            console.log(chalk.magenta('🤖 AI-Only Mode'));
        } else if (options.ai) {
            console.log(chalk.magenta('🤖 Hybrid Mode (Patterns + AI)'));
        } else {
            console.log(chalk.gray('📋 Pattern Matching Mode'));
        }

        console.log(chalk.gray('━'.repeat(50)));

        const spinner = ora('Scanning files...').start();

        try {
            // Normalize path for fast-glob
            const normalizedPath = scanPath.replace(/\\/g, '/');

            // Build include patterns
            const includePatterns = options.include.split(',').map((p: string) => {
                const pattern = p.trim();
                if (normalizedPath === '.') return pattern;
                return `${normalizedPath}/${pattern}`;
            });
            const excludePatterns = options.exclude.split(',').map((p: string) => p.trim());

            // Find files
            const files = await fg(includePatterns, {
                ignore: excludePatterns,
                absolute: true,
                onlyFiles: true,
                dot: false,
            });

            spinner.text = `Found ${files.length} files to scan`;

            // Load custom patterns if specified
            let patterns = DEFAULT_PATTERNS;
            if (options.patterns) {
                const customPatterns = loadCustomPatterns(options.patterns);
                patterns = [...patterns, ...customPatterns];
                spinner.text = `Loaded ${customPatterns.length} custom patterns`;
            }

            // Determine AI mode
            const aiMode = options.aiOnly ? 'only' : (options.ai ? 'hybrid' : 'off');

            // Set up AI config from environment
            if (aiMode !== 'off') {
                const provider = options.aiProvider;
                const envKey = provider === 'openai' ? 'OPENAI_API_KEY' :
                    provider === 'anthropic' ? 'ANTHROPIC_API_KEY' : null;

                if (envKey && !process.env[envKey] && provider !== 'ollama') {
                    spinner.warn(`${envKey} not set, AI detection may not work`);
                }
            }

            // Scan files
            const allResults: ScanResult[] = [];
            let fixedCount = 0;
            let filesScanned = 0;

            for (const file of files) {
                try {
                    const content = await fs.readFile(file, 'utf-8');
                    const relativePath = path.relative(process.cwd(), file);

                    spinner.text = `Scanning: ${relativePath}`;

                    let results: ScanResult[];

                    if (aiMode === 'off') {
                        // Fast pattern-only scan
                        results = scanWithPatterns(content, relativePath, patterns);
                    } else {
                        // AI-powered scan (async)
                        results = await scanContent(content, relativePath, {
                            aiMode,
                            aiConfig: {
                                provider: options.aiProvider,
                                model: options.aiModel
                            }
                        });
                    }

                    filesScanned++;

                    if (results.length > 0) {
                        allResults.push(...results);

                        // Apply fixes if requested
                        if (options.fix) {
                            const fixableResults = results.filter(r => r.fix);
                            if (fixableResults.length > 0) {
                                const fixed = applyFixes(content, fixableResults);
                                await fs.writeFile(file, fixed, 'utf-8');
                                fixedCount += fixableResults.length;
                            }
                        }
                    }
                } catch (err) {
                    // Skip files that can't be read
                }
            }

            spinner.succeed(`Scanned ${filesScanned} files`);

            // Count by severity
            const counts = {
                critical: allResults.filter(r => r.severity === 'critical').length,
                high: allResults.filter(r => r.severity === 'high').length,
                medium: allResults.filter(r => r.severity === 'medium').length,
                low: allResults.filter(r => r.severity === 'low').length,
            };

            const aiCount = allResults.filter(r => r.source === 'ai').length;

            // Print results
            if (allResults.length === 0) {
                console.log(chalk.green('\n✅ No security issues found!\n'));
            } else {
                // Generate and display report
                const report = generateReport(allResults, options.report);

                if (options.report === 'json') {
                    console.log(report);
                } else if (options.report === 'html') {
                    const outputPath = path.join(process.cwd(), 'vibe-check-report.html');
                    await fs.writeFile(outputPath, report);
                    console.log(chalk.cyan(`\n📄 HTML report saved to: ${outputPath}`));
                } else {
                    // Text output with colors
                    for (const result of allResults) {
                        const severityColor = {
                            critical: chalk.red.bold,
                            high: chalk.yellow.bold,
                            medium: chalk.blue,
                            low: chalk.gray,
                            info: chalk.dim,
                        }[result.severity] || chalk.white;

                        const aiTag = result.source === 'ai' ? chalk.magenta(' [AI]') : '';
                        const confTag = result.confidence && result.confidence < 1
                            ? chalk.dim(` (${Math.round(result.confidence * 100)}%)`)
                            : '';

                        console.log(`\n${severityColor(`[${result.severity.toUpperCase()}]`)} ${chalk.white(result.owaspId)}: ${result.message}${aiTag}${confTag}`);
                        console.log(chalk.gray(`  📁 ${result.file}:${result.line}`));
                        console.log(chalk.dim(`  ${result.snippet}`));

                        if (result.suggestion) {
                            console.log(chalk.green(`  💡 ${result.suggestion}`));
                        }

                        if (result.fix && !options.fix) {
                            console.log(chalk.cyan(`  ⚡ Fix available: Run with --fix`));
                        }
                    }

                    // Summary
                    console.log(chalk.bold('\n' + '━'.repeat(50)));
                    console.log(chalk.bold('SUMMARY'));
                    console.log(chalk.bold('━'.repeat(50)));
                    console.log(`${chalk.red.bold('Critical:')} ${counts.critical}  │  ${chalk.yellow.bold('High:')} ${counts.high}  │  ${chalk.blue('Medium:')} ${counts.medium}  │  ${chalk.gray('Low:')} ${counts.low}`);

                    if (aiCount > 0) {
                        console.log(chalk.magenta(`🤖 AI-detected: ${aiCount}/${allResults.length}`));
                    }

                    const fixableCount = allResults.filter(r => r.fix).length;
                    console.log(`Auto-fixable: ${fixableCount}/${allResults.length}`);

                    if (options.fix && fixedCount > 0) {
                        console.log(chalk.green(`\n✅ Fixed ${fixedCount} issues`));
                    } else if (fixableCount > 0 && !options.fix) {
                        console.log(chalk.cyan(`\nRun 'vibe-check ${scanPath} --fix' to auto-patch ${fixableCount} issues`));
                    }
                }
            }

            // CI mode exit codes
            if (options.ci) {
                const failSeverities = options.failOn.split(',').map((s: string) => s.trim().toLowerCase());
                const shouldFail = allResults.some(r => failSeverities.includes(r.severity));

                if (shouldFail) {
                    console.log(chalk.red('\n❌ CI check failed\n'));
                    process.exit(1);
                }
            }

            console.log('');

        } catch (error) {
            spinner.fail('Scan failed');
            console.error(chalk.red(`Error: ${(error as Error).message}`));
            process.exit(1);
        }
    });

// Add subcommand for pattern management
program
    .command('patterns')
    .description('List available vulnerability patterns')
    .action(() => {
        console.log(chalk.bold.cyan('\n📋 Available Vulnerability Patterns\n'));

        for (const pattern of DEFAULT_PATTERNS) {
            const severityColor = {
                critical: chalk.red,
                high: chalk.yellow,
                medium: chalk.blue,
                low: chalk.gray,
                info: chalk.dim,
            }[pattern.severity] || chalk.white;

            console.log(`${severityColor(`[${pattern.severity.toUpperCase()}]`)} ${pattern.id}`);
            console.log(chalk.gray(`  ${pattern.owaspId}: ${pattern.message}`));
            console.log(chalk.dim(`  Pattern: ${pattern.pattern.source}`));
            console.log('');
        }

        console.log(chalk.cyan('💡 Add custom patterns with --patterns <file.json>'));
        console.log(chalk.cyan('💡 Enable AI detection with --ai or --ai-only\n'));
    });

program.parse();
