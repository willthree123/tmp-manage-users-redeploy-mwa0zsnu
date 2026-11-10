/** HK wall-clock strings for naive `timestamp without time zone` DB columns. */

export function hkNow(): string {
  return new Date()
    .toLocaleString("sv-SE", { timeZone: "Asia/Hong_Kong" })
    .replace(" ", "T");
}

export function hkNowPlusMs(ms: number): string {
  return new Date(Date.now() + ms)
    .toLocaleString("sv-SE", { timeZone: "Asia/Hong_Kong" })
    .replace(" ", "T");
}
