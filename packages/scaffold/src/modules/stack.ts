import type { GeneratedFile, Module } from "../types.ts";

const f = (path: string, contents: string): GeneratedFile => ({ path, contents });

/**
 * The parts of the stack every generated app carries, whatever it is for:
 * charts, Excel import and export, and both database drivers.
 *
 * Each arrives as a small, safe-by-default helper rather than a bare
 * dependency, because the users this product targets will reach for the
 * library directly otherwise -- and the library's defaults are not always the
 * safe ones.
 *
 * SheetJS comes from its own CDN, not npm. The npm copy stopped at 0.18.5 and
 * carries published security flaws; the vendor's build is current. Pinned by
 * the version in the URL, which the lockfile then records with a checksum.
 */
export const SHEETJS = "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz";

export const stackModule: Module = {
  id: "stack",

  appDeps: {
    "chart.js": "4.5.1",
    "react-chartjs-2": "5.3.1",
    xlsx: SHEETJS,
  },

  serverDeps: {
    postgres: "3.4.9",
    mysql2: "3.24.5",
  },

  env: [
    {
      name: "MYSQL_URL",
      description:
        "Optional. Address of an existing MySQL database, e.g. mysql://user:password@host:3306/name. Leave empty if the app does not use one. It contains a password, so keep it in .env only.",
      secret: false,
      example: "",
    },
  ],

  files: () => [
    f("app/src/components/charts.tsx", CHARTS),
    f("app/src/lib/spreadsheet.ts", SPREADSHEET),
    f("server/src/mysql.ts", MYSQL),
  ],
};

/**
 * Registers only the chart parts these components use, so a page that shows
 * no chart -- and a page that shows one bar chart -- do not ship all of
 * Chart.js to every visitor.
 */
const CHARTS = `import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from "chart.js";
import { Bar, Doughnut, Line } from "react-chartjs-2";

ChartJS.register(ArcElement, BarElement, CategoryScale, Legend, LinearScale, LineElement, PointElement, Tooltip);

/**
 * Ready-to-use charts. Pass \`data\` and \`options\` as in the Chart.js docs:
 *
 *   <BarChart data={{ labels: ["Jan", "Feb"], datasets: [{ label: "Sales", data: [3, 5] }] }} />
 */
export { Bar as BarChart, Doughnut as DoughnutChart, Line as LineChart };
`;

/**
 * Spreadsheets are a common way for someone else's content to reach your app,
 * so reading and writing them is wrapped with two protections:
 *
 *  - Reading refuses oversized files and never evaluates formulas or HTML in
 *    cells: the values come back as plain data.
 *  - Writing neutralises cells that start with = + - @, which spreadsheet
 *    programs would otherwise run as formulas on whoever opens the file
 *    ("formula injection").
 */
const SPREADSHEET = `import { read, utils, writeFile } from "xlsx";

const MAX_BYTES = 10 * 1024 * 1024;

export type Row = Record<string, unknown>;

/** The first sheet of an uploaded .xlsx, .xls or .csv file, one object per row. */
export async function readSpreadsheet(file: File): Promise<Row[]> {
  if (file.size > MAX_BYTES) throw new Error("This file is larger than 10 MB.");

  const workbook = read(await file.arrayBuffer(), { cellFormula: false, cellHTML: false });
  const first = workbook.SheetNames[0];
  if (!first) return [];
  return utils.sheet_to_json<Row>(workbook.Sheets[first]!, { defval: null });
}

const FORMULA_START = /^[=+\\-@\\t\\r]/;

/** Text that a spreadsheet program would run as a formula, made into plain text. */
function asText(value: unknown): unknown {
  return typeof value === "string" && FORMULA_START.test(value) ? \`'\${value}\` : value;
}

/** Download rows as an Excel file. */
export function downloadSpreadsheet(rows: Row[], filename: string, sheetName = "Sheet1"): void {
  const safe = rows.map((row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, asText(v)])));
  const book = utils.book_new();
  utils.book_append_sheet(book, utils.json_to_sheet(safe), sheetName);
  writeFile(book, filename.endsWith(".xlsx") ? filename : \`\${filename}.xlsx\`);
}
`;

/**
 * An optional connection to an existing MySQL database, alongside the app's
 * own PostgreSQL. It exposes one way to query -- a tagged template that sends
 * every value separately from the query text -- so the unsafe way of building
 * a query is never offered. Nothing connects until it is first used.
 */
const MYSQL = `import mysql from "mysql2/promise";
import { env } from "./env.ts";

let pool: mysql.Pool | undefined;

function connection(): mysql.Pool {
  if (!env.MYSQL_URL) {
    throw new Error("MYSQL_URL is not set. Add it to .env to use a MySQL database.");
  }
  pool ??= mysql.createPool({ uri: env.MYSQL_URL, connectionLimit: 10 });
  return pool;
}

/**
 * Run a query against the MySQL database:
 *
 *   const rows = await query\`SELECT * FROM orders WHERE id = \${orderId}\`;
 *
 * Every \${value} is sent as a separate parameter, never pasted into the query
 * text, so a visitor's input can never change what the query does. Do not add
 * a helper that takes a plain query string.
 */
export async function query<T = unknown>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T[]> {
  const [rows] = await connection().execute(strings.join("?"), values as never[]);
  return rows as T[];
}
`;
