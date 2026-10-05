/**
 * Report renderer regression tests.
 *
 * The final QA markdown used a nested double-quoted template literal, so the
 * failing-checklist line printed the literal text
 * `${data.checklist.filter((c) => !c.ok).length}` instead of a count — the report
 * told the reader nothing while looking like it did.
 */

import { describe, it, expect } from "vitest";
import { toFinalQaReport, buildQaReportData, QaReportData } from "../src/utils/sarif";

const base: QaReportData = {
  generatedAt: "2026-01-01T00:00:00Z",
  activeCount: 0,
  fixedCount: 0,
  suppressedCount: 0,
  todoCount: 0,
  severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  categoryCounts: {},
  securityFindings: [],
  qualityFindings: [],
  coverageFindings: [],
  docFindings: [],
  teamActivity: [],
  checklist: [
    { label: "No critical findings", ok: true, count: 0 },
    { label: "No TODOs introduced", ok: false, count: 2 },
  ],
};

describe("final QA markdown", () => {
  it("renders the failing count instead of the template source", () => {
    const md = toFinalQaReport(base);
    expect(md).toContain("1 check(s) failing");
    expect(md).not.toContain("${");
  });

  it("renders the all-clear variant when nothing fails", () => {
    const md = toFinalQaReport({ ...base, checklist: [{ label: "All good", ok: true, count: 0 }] });
    expect(md).toContain("All checks pass");
    expect(md).not.toContain("failing");
    expect(md).not.toContain("${");
  });

  it("counts every failing item", () => {
    const md = toFinalQaReport({
      ...base,
      checklist: [
        { label: "a", ok: false, count: 1 },
        { label: "b", ok: false, count: 2 },
        { label: "c", ok: false, count: 3 },
      ],
    });
    expect(md).toContain("3 check(s) failing");
  });

  it("builds report data from an empty finding list", () => {
    const data = buildQaReportData([]);
    expect(data.checklist.every((c) => typeof c.ok === "boolean")).toBe(true);
    expect(toFinalQaReport(data)).not.toContain("${");
  });
});